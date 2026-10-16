# Repeater Firewall

The simple repeater checks every received **flood** packet against a table of firewall rules to decide whether to forward it. Packets addressed to the repeater itself, its own packets, and direct-routed packets aren't affected. The checks run after upstream's own flood checks (`flood.max`, `flood.max.unscoped`, `flood.max.advert`, regions).

Three tables work together, each with its own CLI command:

| Table | CLI | Purpose |
|---|---|---|
| Firewall rules | `fw` | 32 rules, checked in slot order: the first rule that matches forwards or drops the packet |
| Route policy | `routepol` | up to 32 repeater routes, for rules with `tl:routepol` |
| Hop policy | `hoppol` | hop limits per path hash width and packet type, for rules with `tl:hoppol` |

All three load from flash at boot, or their built-in defaults if nothing is saved. Limits (`tl:sendtrk`, `chantrk`, `pkttrk`) also use tracking tables, which are in RAM only, with no CLI.

`set fw.enabled 0` turns the firewall off (every flood that passes upstream's checks is forwarded, nothing is counted), `set fw.enabled 1` back on (the default); `get fw.enabled` shows it. It's saved with the repeater settings, not the rules.

## Firewall rules

Rules are checked from slot 0 to 31, skipping empty slots. A rule applies when every field it sets matches the packet. The first rule that applies decides, and **a packet no rule decides is dropped**, so the rules should end with catch-alls such as `rt:flood ac:fwd`.

| Key | Field | Value |
|---|---|---|
| `nm` | name | up to 8 characters |
| `pt` | packet type | `req resp txt ack adv grptxt grpdata anonreq path trace multi ctrl raw`, or 0-15 |
| `hp` | hop count (repeaters already passed) | `N` exactly, `<N` less than, `>N` more than |
| `rb` | path hash width | 1-3 bytes |
| `rt` | route type | `flood` (unscoped), `tflood` (scoped), `direct`, `tdirect` |
| `ch` | channel hash | hex, eg. `5e`: channel messages (`grptxt`, `grpdata`) on that channel only |
| `rg` | region | region name (that exact region, no parents or children), or `*` for unscoped |
| `tl` | table lookup | one table the packet must match: `routepol`, `hoppol`, `sendtrk` (sender over `lb`/`lr`), `chantrk` (channel over `lb`/`lr`) or `pkttrk` (slot `ls` over `lb`/`lr`) |
| `lb` `lr` | limit, with `tl:sendtrk` / `chantrk` / `pkttrk` | `lb` packets in a row, then 1 more every `lr` (minutes, or `30s` / `5m` / `4h` / `2d`) |
| `ls` | limit slot, with `tl:pkttrk` (required) | 0-15 |
| `ac` | action | `fwd` or `drop` (required for a new rule) |

Limits are a running allowance: a quiet sender, channel or slot can send `lb` in a row, then earns 1 back every `lr`.

- `tl:sendtrk`: adverts and anon requests, per sender (by public key; anon request keys can't be verified), in whole minutes
- `tl:chantrk`: channel messages (`grptxt`, `grpdata`), per channel (all 256 channel hashes), in seconds
- `tl:pkttrk`: any packet the rule matches, counted together in slot `ls` (16 slots), in seconds. Rules using the same slot share its allowance, eg. a total cap on distant channel messages.

A tracking table **matches a packet over its allowance**, so the rule acts on it: use `ac:drop`. A packet within its allowance is counted and goes on to the next rule (eventually a catch-all `fwd`). A packet type the table doesn't handle doesn't match. Allowances are in RAM only, and start full at boot.

### How rules share an allowance

Each sender, channel or slot has one clock, shared by every limit rule that uses it. A packet within a rule's allowance pushes the clock forward by the rule's `lr`, and time brings it back. A packet is over a rule's allowance if that push would put the clock more than the rule's window (`lb` x `lr`) ahead of now: the rule matches (and the clock isn't moved).

**Each packet should be counted by one rule per clock:** give limit rules for the same packets non-overlapping matches, eg. `hp:<7` and `hp:>6`. Otherwise a packet within one rule's allowance goes on and is counted again by the next. Rules on different clocks (eg. a channel's and a slot's) can both count it.

**Window limit:** for `tl:sendtrk`, `lb` x `lr` must be at most **32,767 minutes (about 22.75 days)**, eg. `lb:3 lr:7d` (21 days) is fine, `lb:6 lr:7d` (42 days) is too long. The error gives the longest `lr` for that `lb`, eg. `lr too long, for lb:6 the longest is lr:5461` (minutes). `chantrk` and `pkttrk` have no window limit.

A rule can never push the clock further ahead than its own window, so what's left of a bigger window stays available to the rules that have it. Use this to give one group priority, with the bigger window. Example, channel messages, local (6 repeaters or fewer) and distant:

```
nm:chanlm1 hp:<7 tl:chantrk lb:10 lr:30s ac:drop   local:   window 300 s, then 2 a minute
nm:chanlm2 hp:>6 tl:chantrk lb:6  lr:30s ac:drop   distant: window 180 s, then 2 a minute
```

A distant flood can only push the channel's clock about 180 s ahead, so local users keep the rest of their 300 s window (~4 messages) and their 2 a minute. If the windows were equal, a distant flood could use up the whole allowance and block local users too. Keep the lower-priority window clearly smaller.

A total cap (`pkttrk`) should earn back faster than one channel does (a shorter `lr`), so one busy channel can't use it all up.

### Default rules

```
 0 nm:routepol                  tl:routepol                   ac:drop   floods on listed routes
 1 nm:hoppol                    tl:hoppol                     ac:drop   floods over a hop limit
 2 nm:advlm1   pt:adv     hp:<7 tl:sendtrk      lb:3  lr:4h   ac:drop   nearby adverts over 3, then 1 per 4 hours
 3 nm:advlm2   pt:adv     hp:>6 tl:sendtrk      lb:1  lr:3d   ac:drop   other adverts over 1 per 3 days
 4 nm:anrqlm1  pt:anonreq hp:<7 tl:sendtrk      lb:6  lr:12h  ac:drop   nearby anon requests over 6, then 1 per 12 hours
 5 nm:anrqlm2  pt:anonreq hp:>6 tl:sendtrk      lb:6  lr:3d   ac:drop   other anon requests over 6, then 1 per 3 days
 6 nm:wrdrvlm  pt:grptxt  hp:>2 ch:81                         ac:drop   #wardriving: at most 3 repeaters
 7 nm:chanlm1             hp:<7 tl:chantrk      lb:7  lr:15s  ac:fwd    nearby channel messages: always forwarded, but
                                                                        counted, so they use up the channel's allowance first
 8 nm:chanlm2             hp:>6 tl:chantrk      lb:6  lr:15s  ac:drop   other channel messages over 6, then 4 a minute, per channel
 9 nm:chanfld1 pt:grptxt  hp:>6 tl:pkttrk  ls:0 lb:10 lr:6s   ac:drop   other channel messages over 10, then 10 a minute, in total
10 nm:chanfld2 pt:grpdata hp:>6 tl:pkttrk  ls:0 lb:10 lr:6s   ac:drop   (sharing slot 0 with chanfld1)
11 nm:acptfld  rt:flood                                       ac:fwd    everything else
12 nm:acpttfld rt:tflood                                      ac:fwd
```

## Route policy

Each entry is a route of 1-4 repeater hashes (1-3 bytes each) that must appear back to back, in order, in the packet's path, at a position:

- `ps:start`: the first hops, near the sender (can be faked by the sender)
- `ps:end`: the last hops, the repeaters it reached us through
- `ps:any`: anywhere

An entry hash matches a path hash it is the start of (`9e` matches `9e` and `9e12`). Each route can have an 8-character name (`nm`). Example: `routepol 0 nm:north rh:9e,4c ps:end`.

## Hop policy

A fixed list of entries, each with a hop limit or none: `direct tdirect rb1 rb2 rb3` and the packet types (`req resp txt ack grptxt grpdata anonreq path trace multi ctrl pt12 pt13 pt14 raw`). A packet matches if it has passed more repeaters than any limit that applies to it. Example: `hoppol txt:12 path:12`. Limits for all floods, unscoped floods and adverts are upstream's `flood.max`, `flood.max.unscoped` and `flood.max.advert`.

Direct messages and remote management flood `txt`, `path`, `ack`, `anonreq`, `req` and `resp` until a direct path is known, so limits on these limit how far apart people can message or manage repeaters.

## CLI

Replies (except show pages) can be pasted back as commands. Show pages start with a first line (`firewall on` / `firewall off` for `fw`, `OK` for the others), and end with a `...` line when a later page has data. Changes are live but not saved until `save`.

| Command | |
|---|---|
| `fw` | slots in use, then ` (firewall off)` if it's off |
| `fw show1` ... `show6` | 6 slots per page: `firewall on` / `off`, then one `slot name match_count` line per rule |
| `fw show` | every rule as `fw <n> - <config>` commands, after `set fw.enabled 0/1` (serial console only) |
| `fw <n>` | the rule, eg. `nm:hoppol tl:hoppol ac:drop`, or `-` if the slot is empty |
| `fw <n> <words>` | `key:value` sets, `key` shows, `show` the whole rule, `-` clears the slot first |
| `fw insert <n>` / `fw collapse <n>` | open slot n / remove empty slot n, moving the rules after it |
| `fw clear` / `setdefault` / `save` / `reload` | |
| `fw unsave` | removes the saved rules: the current ones stay, the defaults load at boot (or `fw setdefault`) |
| `fw senders` | the sender tracking table (`tl:sendtrk`): `tracking` senders whose limits are still in effect (allowance not fully back) out of 2048, then of those, the ones with `adverts` / `anonreqs` (a sender can be in both). `(overwriting)`: all 2048 are tracked, so a new sender replaces the one closest to fully recovered, losing its limits early |
| `routepol ...` | the same as `fw`, without insert / collapse (fields `nm`, `rh`, `ps`); `show1` ... `show6`: 6 slots per page, `slot name match_count` |
| `hoppol` | limits that are set, eg. `txt:12 path:12` |
| `hoppol <words>` | `name:max` sets (`-` none), `name` shows, `show1` ... `show3`: 8 entries per page, `entry name match_count` |
| `hoppol show` | every entry's limit as `hoppol` commands (serial console only) |
| `hoppol clear` / `setdefault` / `save` / `reload` / `unsave` | |

Saved files: `/fw_rules_v1`, `/route_pol_v1`, `/hop_pol_v1` (text, one entry per line). If a saved file can't be loaded (at boot or by `reload`), that table gets its defaults; `reload` with nothing saved changes nothing. A saved rule whose region is no longer in the region list is skipped (its slot left empty), and the rest load.

## Files

| File | |
|---|---|
| `examples/simple_repeater/FirewallTable.h` | rules, checks, `fw` CLI, defaults |
| `examples/simple_repeater/RoutePolicy.h` | route policy, `routepol` CLI |
| `examples/simple_repeater/HopPolicy.h` | hop policy, `hoppol` CLI |
| `examples/simple_repeater/SenderTracking.h` | per-sender advert / anon request allowances |
| `examples/simple_repeater/ChannelTracking.h` | per-channel message allowances |
| `examples/simple_repeater/PacketTracking.h` | allowance clocks (`ls` slots, and the channels') |
| `examples/simple_repeater/TableCli.h` | CLI helpers shared by the tables |
| `examples/simple_repeater/TableFile.h` | file helpers |
| `examples/simple_repeater/MyMesh.cpp` | `allowPacketForward()` calls the firewall; `begin()` loads the tables; `show` commands |
| `src/helpers/CommonCLI.cpp` | `set` / `get fw.enabled` |
