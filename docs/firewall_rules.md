# Repeater Firewall

This is a basic firewall designed to prioritize messaging over unnecessary background packets.  

The firewall uses pre-defined lookup tables for tracking purposes.  Tracking is based on the [generic cell rate algorithm](https://en.wikipedia.org/wiki/Generic_cell_rate_algorithm) in order to minimize memory usage.  

For example, instead of blocking adverts at a certain number of hops, this firewall tracks up to 2048 senders, allowing distant senders only 1 advert every 3 days.

Three tables work together, each with its own CLI command:

| Table | CLI | Purpose |
|---|---|---|
| Firewall rules | `fw` | 32 rules, checked in slot order: the first rule that matches forwards or drops the packet |
| Route policy | `routepol` | up to 32 repeater routes, for rules with `tl:routepol` |
| Hop policy | `hoppol` | hop limits per payload type, route type and path hash width, for rules with `tl:hoppol` |

All three tables load from flash at boot, or their built-in defaults if nothing is saved. Tracking tables (`tl:sendtrk`, `chantrk`, `pkttrk`) are in RAM only.

`set fw.enabled 0` turns the firewall off and disables its counters, `set fw.enabled 1` turns it back on (the default), and  `get fw.enabled` shows the current state. 

## Firewall rules

Rules are checked from slot 0 to 31, skipping empty slots. A rule applies when every configured check matches the packet. The first rule that matches takes action on the packet, and no further rules are checked.  If no rules match, the packet is dropped, so be sure to use a catch-all 'fwd' as the last rule.

| Key | Field | Value |
|---|---|---|
| `nm` | name | up to 8 characters |
| `pt` | payload type | `req resp txt ack adv grptxt grpdata anonreq path trace multi ctrl raw`, or 0-15 |
| `hp` | hop count (repeaters already passed, not counting dummy `000000` hashes at the start of a 3-byte-hash path) | `N` exactly, or a range `A-B`, eg. `hp:0-4`, `hp:9-63` (a path holds at most 63 hops: `64` is taken as 63). `<N` / `>N` are also accepted, and shown as a range |
| `rb` | route path hash width | 1-3 bytes |
| `rt` | route type | `flood` (unscoped), `tflood` (scoped), `direct`, `tdirect` |
| `ch` | channel hash | hex, eg. `5e`: channel messages (`grptxt`, `grpdata`) on that channel only |
| `rg` | region | region name (that exact region, no parents or children), or `*` for unscoped |
| `tl` | table lookup | check the table to see if the packet matches: `routepol`, `hoppol`, `sendtrk`, `chantrk` or `pkttrk` |
| `lb` `lr` | limit burst and limit recover | used with the sendtrk, chantrk, and pkttrk tables. `lb` packets allowed in a burst, then 1 more every `lr` time-span, until the burst is fully recovered (minutes, or `30s` / `5m` / `4h` / `2d`). |
| `ls` | limit slot | used with the `tl:pkttrk` table (required). 0-15 |
| `ac` | action | `fwd` or `drop` (required for a new rule) |

Limits are a running allowance: a quiet sender, channel or slot can send in a burst `lb` packets in a row, then recovers 1 packet every `lr` span of time.

- `tl:sendtrk`: adverts, anon requests, requests, responses, DMs and path returns, per sender, in whole minutes. Each rule has its own clock per sender
- `tl:chantrk`: channel messages (`grptxt`, `grpdata`), per channel (all 256 channel hashes), in seconds
- `tl:pkttrk`: any packet the rule matches, counted together in slot `ls` (16 slots), in seconds. Rules using the same slot share its allowance, eg. a total cap on distant channel messages.

A tracking table **matches a packet over its allowance**, so the rule acts on it: use `ac:drop`. A packet within its allowance is counted and goes on to the next rule (eventually a catch-all `fwd`). A packet type the table doesn't handle doesn't match. Allowances are in RAM only, and start full at boot.

### How rules share an allowance

Refer to the [generic cell rate algorithm](https://en.wikipedia.org/wiki/Generic_cell_rate_algorithm) for background.

Each sender, channel or slot updates a clock each time it sends a packet. A packet within a rule's allowance pushes the clock forward by the rule's `lr`. A packet is over a rule's allowance if that push would put the clock more than the rule's window (`lb` x `lr`) ahead of now.  As time passes, all saved clocks slowly move back into the rule's window and one or more packets are allowed to be sent again.

**Each packet should be counted by one rule per clock:** for `chantrk` and `pkttrk`, give limit rules for the same packets non-overlapping matches, eg. `hp:0-8` and `hp:9-63`. Otherwise a packet within one rule's allowance is counted again by the next rule's allowance. `sendtrk` rules each have their own clocks, so they never count against each other.

**Window limit:** for `tl:sendtrk`, `lb` x `lr` must be at most **32,767 minutes (about 22.75 days)**, eg. `lb:3 lr:7d` (21 days) is fine, `lb:6 lr:7d` (42 days) is too long. The error gives the longest `lr` for that `lb`, eg. `lr too long, for lb:6 the longest is lr:5461` (minutes). `chantrk` and `pkttrk` have no window limit.

With `chantrk` and `pkttrk`, rules share the clock, and a rule can never push it further ahead than its own window.  This can be used to give certain rules priority over other rules.  For example, local channel messages vs distant channel messages:

```
nm:chanlm1 hp:0-8  tl:chantrk lb:10 lr:30s ac:drop   # local:   window 300 s, then 2 a minute
nm:chanlm2 hp:9-63 tl:chantrk lb:6  lr:30s ac:drop   # distant: window 180 s, then 2 a minute
```

Distant packets can only push the channel's clock about 180 s ahead, so local users keep the rest of their 300 s window (~4 messages) and their 2 a minute. If the windows were equal, distant packets could use up the whole allowance and block local users too. Keep the lower-priority window clearly smaller.


### Default rules

```
 0 nm:routepol                   tl:routepol                  ac:drop   packets on listed routes
 1 nm:hoppol                     tl:hoppol                    ac:drop   packets over a hop limit
 2 nm:advlm1   pt:adv     hp:0-4  tl:sendtrk      lb:10 lr:30m ac:drop   nearby adverts over 10, then 1 per 30 minutes
 3 nm:advlm2   pt:adv     hp:5-8  tl:sendtrk      lb:10 lr:1h  ac:drop   mid-range adverts over 10, then 1 an hour
 4 nm:advlm3   pt:adv     hp:9-63 tl:sendtrk      lb:1  lr:3d  ac:drop   distant adverts over 1 per 3 days
 5 nm:anrqlm1  pt:anonreq hp:0-4  tl:sendtrk      lb:10 lr:30m ac:drop   nearby anon requests over 10, then 1 per 30 minutes
 6 nm:anrqlm2  pt:anonreq hp:5-8  tl:sendtrk      lb:10 lr:1h  ac:drop   mid-range anon requests over 10, then 1 an hour
 7 nm:reqlm1   pt:req     hp:0-4  tl:sendtrk      lb:5  lr:30m ac:drop   nearby requests over 5, then 1 per 30 minutes, per source / destination pair
 8 nm:reqlm2   pt:req     hp:5-8  tl:sendtrk      lb:5  lr:1h  ac:drop   mid-range requests over 5, then 1 an hour, per pair
 9 nm:wrdrvlm  pt:grptxt  hp:3-63 ch:81                        ac:drop   #wardriving: at most 3 repeaters
10 nm:chanlm1             hp:0-8  tl:chantrk      lb:8  lr:15s ac:fwd    nearby channel messages: always forwarded, but
                                                                         counted, so they use up the channel's allowance first
11 nm:chanlm2             hp:9-63 tl:chantrk      lb:6  lr:15s ac:drop   distant channel messages over 6, then 4 a minute, per channel
12 nm:chandos1 pt:grptxt  hp:9-63 tl:pkttrk  ls:0 lb:10 lr:6s  ac:drop   distant channel messages over 10, then 10 a minute, in total
13 nm:senddos1 pt:adv     hp:9-63 tl:pkttrk  ls:1 lb:8  lr:5s  ac:drop   distant adverts over 8, then 12 a minute, in total
14 nm:acptfld  rt:flood                                        ac:fwd    everything else
15 nm:acpttfld rt:tflood                                       ac:fwd
```

Anon requests and requests have no distant rules: the hop policy (`anonreq:8`, `req:8`) drops them past 8 hops. Distant channel data (`grpdata`) needs no total cap either: `grpdata:8` drops it.

The total caps (`chandos1`, `senddos1`) catch distant senders using new channel hashes or new keys, which get a new per-channel or per-sender allowance each time. Their limits are far above normal traffic, so they only act during a flood of packets. Nearby and mid-range packets (0-8 hops) have no total cap: only their per-sender limits apply. A sender can claim any hop count, so a total cap for them can be added with `tl:pkttrk` on a free slot if needed.

## Route policy table

`tl:routepol`

This table can be used to block certain senders or paths.  For example, someone flooding the network with requests could be blocked by adding the first few hops of their path.

Each entry is a route of 1-4 hashes (1-3 bytes each) that must appear back to back, in order, in the packet's path:

| Key | Field | Value |
|---|---|---|
| `nm` | name | for reference, up to 8 characters, eg. `nm:reqfld1` |
| `rh` | route hashes | the hashes that make up the route: 1-4, comma separated, each 2, 4 or 6 hex digits (all the same length), eg. `rh:9e,4c` |
| `ps` | position | where the route must be in the path: `ps:start`, `ps:end`, or `ps:any` (the default) |

An entry hash matches a path hash it is the start of (`9e` matches `9e` and `9e12`).

Example: `routepol 0 nm:reqfld1 rh:9e,4c ps:end`.

## Hop policy table

`tl:hoppol`

This table limits how far certain kinds of packets travel, by route type, path hash width or payload type. For example, `txt:12` matches direct text messages that have already passed more than 12 repeaters.

The table is a fixed list of 22 entries, each with a hop limit (0-64) or none (`-`). Each matches packets with one property:

| Entry | Matches |
|---|---|
| `req` | requests: remote management and stats, logged in |
| `resp` | responses to requests |
| `txt` | direct text messages (DMs) |
| `ack` | acknowledgements of DMs |
| `grptxt` | channel text messages |
| `grpdata` | channel data |
| `anonreq` | anonymous requests: logins and requests from unknown nodes |
| `path` | path returns, which set up a direct route |
| `trace` | trace packets (currently sent direct only, so rarely flood-routed) |
| `multi` | multipart packets (currently sent direct only, so rarely flood-routed) |
| `ctrl` | control packets, eg. neighbour discovery |
| `pt12` | payload type 12, not used by MeshCore yet |
| `pt13` | payload type 13, not used by MeshCore yet |
| `pt14` | payload type 14, not used by MeshCore yet |
| `raw` | raw custom packets (payload type 15) |
| `direct` | direct-routed packets, unscoped. The firewall only checks flood-routed packets, so this doesn't match yet |
| `tdirect` | direct-routed packets, scoped. Doesn't match yet, as `direct` |
| `flood` | flood-routed packets, unscoped |
| `tflood` | flood-routed packets, scoped |
| `rb1` | packets whose path uses 1-byte repeater hashes |
| `rb2` | packets whose path uses 2-byte repeater hashes |
| `rb3` | packets whose path uses 3-byte repeater hashes |

A packet is checked against every entry that applies to it (its payload type, route type and path hash width), and matches if it has passed more repeaters than any of those limits. Eg. with `txt:12` and `rb1:8`, a DM with 1-byte hashes is stopped after 8 repeaters. Each entry counts the packets it applies to as they pass through the table (seen), and the ones it caused a rule to act on (matched), shown as `seen/matched` on the `hoppol show<p>` pages.

`flood` and `tflood` overlap with upstream's `flood.max.unscoped` and `flood.max`, which are checked first: with both set, the lower limit wins. Adverts aren't in the list: their hop limit is upstream's `flood.max.advert` (and the sender tracking table limits them).

Defaults: `req:8 resp:8 txt:12 ack:12 grpdata:8 anonreq:8 path:12 trace:8 multi:8 ctrl:1 raw:8`, the rest none. Direct messages use `txt`, `path` (the reply's path back, carrying the ACK) and `ack`, so they reach 12 hops.

Example: `hoppol txt:12 path:12`.

## Sender tracking table

`tl:sendtrk`

This table limits how often each sender's packets are forwarded. For example, a node re-advertising every few minutes only gets through a few times, then once every few hours.

Each `sendtrk` rule has its own clock for each sender, in whole minutes, so rules for different hop ranges never use up each other's allowance. The sender depends on the packet type:

| Packet type | Sender | Clocks |
|---|---|---|
| `adv` | the public key (signed) | one per sender |
| `anonreq` | the public key (can't be checked by a repeater) | one per sender |
| `req`, `resp`, `txt`, `path` | the 1-byte source hash (can't be checked by a repeater) | one per source and destination hash pair |

Other packet types don't match. A sender's adverts and anon requests always have separate clocks, even on a rule without `pt`. Senders that share a 1-byte source hash share a clock for the same destination.

The rule sets the limit: `lb` in a row, then 1 more every `lr`, with `lb` x `lr` at most 32,767 minutes. Up to 2048 clocks are kept: when they're all in use, a new one replaces the one closest to fully recovered. Per-sender limits stop single misbehaving nodes: a sender using new keys gets a new allowance each time, so use `tl:pkttrk` for a total cap (as `senddos1`).

Clocks belong to a rule's slot:

| Firewall change | Clocks |
|---|---|
| a field edit, eg. `fw 2 lb:30` | kept: senders keep their used allowance, checked against the new limit |
| replacing a rule (`fw 2 - ...`) or emptying a slot | that rule's clocks are forgotten (full allowance) |
| `fw insert` / `fw collapse` | moved with their rules |
| `fw clear` / `setdefault` / `reload`, or a reboot | all forgotten |
| `set fw.enabled 0` | kept, but not checked or counted while the firewall is off |

To start a rule's senders over after changing its `pt` or `tl`, replace the rule instead of editing it.

Examples: `fw 2 nm:advlm1 pt:adv hp:0-4 tl:sendtrk lb:3 lr:4h ac:drop`, `fw 20 nm:reqlm pt:req hp:3-63 tl:sendtrk lb:4 lr:10m ac:drop` (requests per source / destination pair).

## Channel tracking table

`tl:chantrk`

This table limits channel messages per channel. For example, one busy or spammed channel can't fill the mesh, while the other channels carry on normally.

There's a clock for each of the 256 channel hashes, in seconds. Only channel messages (`grptxt`, `grpdata`) are tracked, and channels sharing a hash share an allowance.

Example: `fw 10 nm:chanlm2 hp:9-63 tl:chantrk lb:6 lr:15s ac:drop`.

## Packet tracking table

`tl:pkttrk`

This table puts one shared limit on whatever the rule matches. For example, it can cap all distant channel messages together, which also catches spam spread over many channel hashes, or all distant adverts and anon requests together, which also catches senders using new keys.

There are 16 numbered slots (`ls:0` to `ls:15`), each a clock in seconds. Rules using the same slot share its allowance.

Example: `fw 11 nm:chandos1 pt:grptxt hp:9-63 tl:pkttrk ls:0 lb:10 lr:6s ac:drop`.

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
| `fw senders` / `senders2` ... | the sender tracking table (`tl:sendtrk`): `senders: <tracked>/2048`, clocks whose limits are still in effect (allowance not fully back), then 4 `sendtrk` rules per page: `<slot> <name>: <tracked> (<over> over)`, over: senders whose next packet is over the rule's limit. `(overwriting)`: all 2048 are tracked, so a new one replaces the one closest to fully recovered, losing its limits early |
| `routepol ...` | the same as `fw`, without insert / collapse (fields `nm`, `rh`, `ps`); `show1` ... `show6`: 6 slots per page, `slot name match_count` |
| `hoppol` | limits that are set, eg. `txt:12 path:12` |
| `hoppol <words>` | `name:max` sets (`-` none), `name` shows, `show1` ... `show5`: 5 entries per page, `entry name seen/matched` |
| `hoppol show` | every entry's limit as `hoppol` commands (serial console only) |
| `hoppol clear` / `setdefault` / `save` / `reload` / `unsave` | |

Saved files: `/fw_rules_v1`, `/route_pol_v1`, `/hop_pol_v1` (text, one entry per line). If a saved file can't be loaded (at boot or by `reload`), that table gets its defaults; `reload` with nothing saved changes nothing. A saved rule whose region is no longer in the region list is skipped (its slot left empty), and the rest load.

## Files

| File | |
|---|---|
| `examples/simple_repeater/FirewallTable.h` | rules, checks, `fw` CLI, defaults |
| `examples/simple_repeater/RoutePolicy.h` | route policy, `routepol` CLI |
| `examples/simple_repeater/HopPolicy.h` | hop policy, `hoppol` CLI |
| `examples/simple_repeater/SenderTracking.h` | per-sender allowances, one clock per rule |
| `examples/simple_repeater/ChannelTracking.h` | per-channel message allowances |
| `examples/simple_repeater/PacketTracking.h` | allowance clocks (`ls` slots, and the channels') |
| `examples/simple_repeater/TableCli.h` | CLI helpers shared by the tables |
| `examples/simple_repeater/TableFile.h` | file helpers |
| `examples/simple_repeater/MyMesh.cpp` | `allowPacketForward()` calls the firewall; `begin()` loads the tables; `show` commands |
| `src/helpers/CommonCLI.cpp` | `set` / `get fw.enabled` |
