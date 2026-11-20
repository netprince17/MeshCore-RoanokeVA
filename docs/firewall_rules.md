# Repeater Firewall

This is a basic meshcore repeater firewall designed to prioritize messaging over unnecessary overhead packets, and keep distant traffic from overwhelming local traffic.  

Overhead packets are used for management functions but carry no messages: adverts, logins, anonymous requests, remote management, and stats requests. Most of them are only useful close to their sender, so forwarding them over long distances wastes airtime, and limiting them keeps the mesh running smoothly.

The firewall sorts packets into three distance tiers by hop count: **nearby** (0-4 hops), **mid-range** (5-8) and **distant** (9+). The closer the sender, the higher the priority of its overhead packets, so the local mesh is served first. Nearby senders get the most generous limits, mid-range senders tighter limits, and distant packets the tightest limits plus total caps, so far-away nodes can't flood the local mesh. See [Firewall rules table](#firewall-rules-table) for the details.

The distant mesh is much larger than the local mesh. Each extra hop reaches more repeaters and nodes, so the nodes 9 or more hops away can far outnumber the local ones. Distant traffic can easily fill the available airtime and crowd out local messages.  This firewall is designed to help keep distant traffic from overwhelming local traffic.

## How the firewall works

The firewall is made up of tables. The primary table is the firewall rules table, which holds the rules used to check each packet. The other tables track or check certain aspects of a packet, such as its route, hop count or how often its sender has been heard. A rule can reference another table as part of its check, then the rule decides whether the packet is forwarded or dropped.  

- **Firewall rules** (`fw`): the main table, containing the firewall rules. Each rule can check one of the tables below.
- **Route policy** (`routepol`): blocks packets with the specified route, eg. to stop one source flooding the mesh.
- **Hop policy** (`hoppol`): limits how many hops each kind of packet can travel.
- **Sender tracking** (`sendtrk`): limits how often each sender's packets are forwarded.
- **Channel tracking** (`chantrk`): limits channel messages per channel.
- **Packet tracking** (`pkttrk`): one shared limit on all the packets a rule matches, eg. a total cap on distant adverts.

The default rules are designed to work well on the RoanokeMesh network, but every table can be reconfigured if needed. `fw setdefault` restores the default rules, and `set fw.enabled 0` turns the firewall off for testing (`set fw.enabled 1` turns it back on).

### The default firewall

The default rules keep messages flowing while limiting overhead packets, with the tightest limits on distant traffic. Nearby nodes can advertise, log in and manage repeaters freely, distant nodes are held to a trickle, and total caps stop a distant flood of packets from filling the airtime.

- **0** `routepol`: drops packets on routes listed in the route policy table (none by default).
- **1** `hoppol`: drops packets that have traveled further than their hop policy limit, eg. requests past 8 hops.
- **2** `advlm1`: limit nearby adverts, 15 adverts in a burst, then recover 1 per 30 minutes.
- **3** `advlm2`: limit mid-range adverts, 15 adverts in a burst, then recover 1 per hour.
- **4** `advlm3`: limit distant adverts, 1 advert in a burst, then recover 1 per 3 days.
- **5** `anrqlm1`: limit nearby anonymous requests, 15 requests in a burst, then recover 1 per 30 minutes.
- **6** `anrqlm2`: limit mid-range anonymous requests, 15 requests in a burst, then recover 1 per hour.
- **7** `reqlm1`: limit nearby requests, 15 requests in a burst, then recover 1 per 30 minutes.
- **8** `reqlm2`: limit mid-range requests, 15 requests in a burst, then recover 1 per hour.
- **9** `wrdrvlm`: allow #wardriving channel messages within 3 hops.
- **10** `chanlm1`: count nearby and mid-range channel messages, 8 messages in a burst, then recover 1 per 15 seconds.
- **11** `chanlm2`: limit distant channel messages, 6 messages in a burst, then recover 1 per 15 seconds.
- **12** `chandos1`: limit all distant channel messages together, 10 messages in a burst, then recover 1 per 6 seconds.
- **13** `senddos1`: limit all distant adverts together, 8 adverts in a burst, then recover 1 per 5 seconds.
- **14** `acptfld`: forwards everything else (unscoped flood-routed packets).
- **15** `acpttfld`: forwards everything else (scoped flood-routed packets).

## Firewall rules table

Rules are checked from slot 0 to 31, skipping empty slots. A rule applies when every configured check matches the packet. The first rule that matches takes action on the packet, and no further rules are checked.  If no rules match, the packet is dropped, so be sure to use a catch-all `fwd` as the last rule.

```
fw <slot> [-] <key>:<value> [<key>:<value> ...]
```

`<slot>` is 0-31 and each `<key>:<value>` sets one field (see the table below). On a slot that already holds a rule, only the given fields change; `-` clears the slot first, replacing the rule.

The rules can be added or updated from the command line, the default rules are added with commands like these:

```
fw 0  nm:routepol                    tl:routepol                   ac:drop
fw 1  nm:hoppol                      tl:hoppol                     ac:drop
fw 2  nm:advlm1   pt:adv     hp:0-4  tl:sendtrk       lb:15 lr:30m ac:drop
fw 3  nm:advlm2   pt:adv     hp:5-8  tl:sendtrk       lb:15 lr:1h  ac:drop
fw 4  nm:advlm3   pt:adv     hp:9-63 tl:sendtrk       lb:1  lr:3d  ac:drop
fw 5  nm:anrqlm1  pt:anonreq hp:0-4  tl:sendtrk       lb:15 lr:30m ac:drop
fw 6  nm:anrqlm2  pt:anonreq hp:5-8  tl:sendtrk       lb:15 lr:1h  ac:drop
fw 7  nm:reqlm1   pt:req     hp:0-4  tl:sendtrk       lb:15 lr:30m ac:drop
fw 8  nm:reqlm2   pt:req     hp:5-8  tl:sendtrk       lb:15 lr:1h  ac:drop
fw 9  nm:wrdrvlm  pt:grptxt  hp:3-63 ch:81                         ac:drop
fw 10 nm:chanlm1             hp:0-8  tl:chantrk       lb:8  lr:15s ac:fwd
fw 11 nm:chanlm2             hp:9-63 tl:chantrk       lb:6  lr:15s ac:drop
fw 12 nm:chandos1 pt:grptxt  hp:9-63 tl:pkttrk   ls:0 lb:10 lr:6s  ac:drop
fw 13 nm:senddos1 pt:adv     hp:9-63 tl:pkttrk   ls:1 lb:8  lr:5s  ac:drop
fw 14 nm:acptfld                     rt:flood                      ac:fwd
fw 15 nm:acpttfld                    rt:tflood                     ac:fwd
```

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

## Route policy table

The route policy table holds up to 32 routes, used by firewall rules with `tl:routepol`. It can be used to block certain senders or paths. For example, someone flooding the network with requests could be blocked by adding the first few hops of their path. A packet matches when one of the routes appears in its path: 1-4 repeater hashes, back to back and in order.

```
routepol <slot> [-] <key>:<value> [<key>:<value> ...]
```

`<slot>` is 0-31 and each `<key>:<value>` sets one field (see the table below). As with `fw`, only the given fields change on a slot that already holds a route; `-` clears the slot first, replacing the route.

There are no default routes. Routes are added with commands like these:

```
routepol 0  nm:reqfld1  rh:9e,4c  ps:end
routepol 1  nm:town     rh:b7     ps:start
```

| Key | Field | Value |
|---|---|---|
| `nm` | name | for reference, up to 8 characters |
| `rh` | route hashes | the hashes that make up the route: 1-4, comma separated, each 2, 4 or 6 hex digits (all the same length), eg. `rh:9e,4c`. A hash matches a path hash it is the start of (`9e` matches `9e` and `9e12`) |
| `ps` | position | where the route must be in the path: `start`, `end`, or `any` (the default) |

## Hop policy table

The hop policy table limits how far certain kinds of packets travel, used by firewall rules with `tl:hoppol`. It is a fixed list of 22 entries, each with a hop limit or none. For example, `txt:12` matches DMs that have already passed more than 12 repeaters.

```
hoppol <entry>:<limit> [<entry>:<limit> ...]
```

`<entry>` is one of the entries in the table below, and `<limit>` is 0-64 hops, or `-` for no limit. Several entries can be set in one command; if any of them is invalid, none are changed.

The default limits are set with this command:

```
hoppol req:8 anonreq:8 resp:8 path:12 ack:12 txt:12 trace:8 grpdata:8 multi:8 ctrl:1 raw:8
```

| Entry | Matches | Default |
|---|---|---|
| `req` | requests: remote management and stats, logged in | 8 |
| `resp` | responses to requests | 8 |
| `txt` | direct text messages (DMs) | 12 |
| `ack` | acknowledgements of DMs | 12 |
| `grptxt` | channel text messages | - |
| `grpdata` | channel data | 8 |
| `anonreq` | anonymous requests: logins and requests from unknown nodes | 8 |
| `path` | path returns, which set up a direct route | 12 |
| `trace` | trace packets (currently sent direct only, so rarely flood-routed) | 8 |
| `multi` | multipart packets (currently sent direct only, so rarely flood-routed) | 8 |
| `ctrl` | control packets, eg. neighbor discovery | 1 |
| `pt12` `pt13` `pt14` | payload types 12-14, not used by MeshCore yet | - |
| `raw` | raw custom packets (payload type 15) | 8 |
| `direct` `tdirect` | direct-routed packets, unscoped / scoped. The firewall only checks flood-routed packets, so these don't match yet | - |
| `flood` | flood-routed packets, unscoped | - |
| `tflood` | flood-routed packets, scoped | - |
| `rb1` `rb2` `rb3` | packets whose path uses 1-, 2- or 3-byte repeater hashes | - |

A packet is checked against every entry that applies to it (its payload type, route type and path hash width), and matches if it has passed more repeaters than any of those limits. Eg. with `txt:12` and `rb1:8`, a DM with 1-byte hashes is stopped after 8 repeaters. DMs use `txt`, `path` (the reply's path back, carrying the ACK) and `ack`, so by default they reach 12 hops.

`flood` and `tflood` overlap with upstream's `flood.max.unscoped` and `flood.max`, which are checked first: with both set, the lower limit wins. Adverts aren't in the list: their hop limit is upstream's `flood.max.advert`, and the sender tracking table limits them.

## Sender tracking table

The sender tracking table limits how often each sender's packets are forwarded, used by firewall rules with `tl:sendtrk`. For example, a node re-advertising every few minutes only gets through a few times, then once every few hours. Tracking is based on the [generic cell rate algorithm](https://en.wikipedia.org/wiki/Generic_cell_rate_algorithm), which needs only one small clock per sender.

```
fw <slot> [-] [<key>:<value> ...] tl:sendtrk lb:<burst> lr:<time> ac:drop
```

The tracking tables have no command of their own: a firewall rule sets the limit. Each sender can send `lb` packets in a row, then 1 more every `lr`. A packet over its sender's allowance matches, so the rule drops it; a packet within it is counted and goes on to the next rule.

The default rules use it with commands like these:

```
fw 2  nm:advlm1   pt:adv     hp:0-4  tl:sendtrk       lb:15 lr:30m ac:drop
fw 3  nm:advlm2   pt:adv     hp:5-8  tl:sendtrk       lb:15 lr:1h  ac:drop
fw 4  nm:advlm3   pt:adv     hp:9-63 tl:sendtrk       lb:1  lr:3d  ac:drop
fw 5  nm:anrqlm1  pt:anonreq hp:0-4  tl:sendtrk       lb:15 lr:30m ac:drop
fw 6  nm:anrqlm2  pt:anonreq hp:5-8  tl:sendtrk       lb:15 lr:1h  ac:drop
fw 7  nm:reqlm1   pt:req     hp:0-4  tl:sendtrk       lb:15 lr:30m ac:drop
fw 8  nm:reqlm2   pt:req     hp:5-8  tl:sendtrk       lb:15 lr:1h  ac:drop
```

| Key | Field | Value |
|---|---|---|
| `lb` | limit burst | packets allowed in a row |
| `lr` | limit recover | time to recover 1 packet: minutes, or `30s` / `5m` / `4h` / `2d`. Rounded up to whole minutes |
| | window | `lb` x `lr` must be at most **32,767 minutes (about 22.75 days)**, eg. `lb:3 lr:7d` is fine, `lb:6 lr:7d` is too long. The error gives the longest `lr` for that `lb` |

The sender depends on the packet type:

| Packet type | Sender |
|---|---|
| `adv` | the public key (signed) |
| `anonreq` | the public key (can't be checked by a repeater) |
| `req`, `resp`, `txt`, `path` | the 1-byte source hash and the first repeater's hash in the path (1-3 bytes; 0 for a packet heard straight from the sender). Can't be checked by a repeater |

Other packet types don't match. Dummy `000000` hashes at the start of a path are skipped, so the first real repeater is used. Senders with the same source hash and first repeater share a clock, and a sender heard through different first repeaters gets a clock for each. A rule without `pt` shares each sender's clock between the packet types it sees.

Each rule has its own clock per sender, so rules for different hop ranges never use up each other's allowance. Up to 2340 clocks are kept (585 on STM32): when they're all in use, a new one replaces the one closest to fully recovered. A sender using new keys gets a new allowance each time, so use `tl:pkttrk` for a total cap (as `senddos1`).

When changing a firewall rule, the senders table may need to be updated as follows:

| Firewall change | Clocks |
|---|---|
| a field edit, eg. `fw 2 lb:30` | kept: senders keep their used allowance, checked against the new limit |
| replacing a rule (`fw 2 - ...`) or emptying a slot | that rule's clocks are forgotten (full allowance) |
| `fw insert` / `fw collapse` | moved with their rules |
| `fw clear` / `setdefault` / `reload`, or a reboot | all forgotten |
| `set fw.enabled 0` | kept, but not checked or counted while the firewall is off |

To start a rule's senders over after changing its `pt` or `tl`, replace the rule instead of editing it.

### Viewing the sender tracking table

`fw senders` shows how many senders each `sendtrk` rule is tracking, and how many it has limited. It is serial console only; remotely, use the pages `fw senders1`, `fw senders2` ... (4 rules per page).

```
fw senders
senders: 41 tracked, 46/2340 records, 0 replaced since boot
# rule       tracked     maxed   dropped  window
 2 advlm1         12         0         0  7h30m
 3 advlm2          9         1         4  15h
 4 advlm3         17        17       236  3d
 5 anrqlm1         2         0         0  7h30m
 6 anrqlm2         1         0         0  15h
 7 reqlm1          0         0         0  7h30m
 8 reqlm2          0         0         0  15h
left over from old rules: 5
```

| Column | |
|---|---|
| tracked | senders whose limit is still in effect (their allowance isn't fully back) |
| maxed | senders whose next packet would be dropped. With `lb:1` that's every tracked sender, as `advlm3` |
| dropped | packets the rule dropped (its match count). On an `ac:fwd` rule they're forwarded instead, marked `fwd` |
| window | `lb` x `lr`, how far ahead a sender's clock can get |

The first line counts the records in use out of 2340 (585 on STM32). Replaced records are senders whose limits were lost early because the table was full; a growing count means more senders are being tracked than the table can hold. `left over from old rules` counts records from slots that no longer hold a `sendtrk` rule; once the table is full, they are among the first replaced.

The pages show the same counts in a shorter form, `<slot> <name> <tracked>/<maxed> (<dropped>)`, with `(overwriting)` after the first line when the table is full:

```
fw senders1
senders: 41/2340
# rule tracked/maxed (dropped)
2 advlm1 12/0 (0)
3 advlm2 9/1 (4)
4 advlm3 17/17 (236)
5 anrqlm1 2/0 (0)
...
```

## Channel tracking table

The channel tracking table limits channel messages (`grptxt`, `grpdata`) per channel, used by firewall rules with `tl:chantrk`. For example, one busy or spammed channel can't fill the mesh, while the other channels carry on normally. There is a clock for each of the 256 channel hashes, in seconds; channels sharing a hash share an allowance.

```
fw <slot> [-] [<key>:<value> ...] tl:chantrk lb:<burst> lr:<time> ac:drop|fwd
```

Each channel can send `lb` messages in a row, then 1 more every `lr`. A message over the channel's allowance matches, so the rule acts on it; a message within it is counted and goes on to the next rule.

The default rules use it with commands like these:

```
fw 10 nm:chanlm1             hp:0-8  tl:chantrk       lb:8  lr:15s ac:fwd
fw 11 nm:chanlm2             hp:9-63 tl:chantrk       lb:6  lr:15s ac:drop
```

`chanlm1` uses `ac:fwd`, so nearby messages are always forwarded, but they are counted and use up the channel's allowance first.

| Key | Field | Value |
|---|---|---|
| `lb` | limit burst | messages allowed in a row |
| `lr` | limit recover | time to recover 1 message: minutes, or `30s` / `5m` / `4h` / `2d` |

Rules share each channel's clock, and a rule can never push it further ahead than its own window (`lb` x `lr`). This gives rules with a larger window priority. For example:

```
fw 20 nm:chanex1 hp:0-8  tl:chantrk lb:10 lr:30s ac:drop   # local:   window 300 s, then 2 a minute
fw 21 nm:chanex2 hp:9-63 tl:chantrk lb:6  lr:30s ac:drop   # distant: window 180 s, then 2 a minute
```

Distant messages can only push the clock about 180 s ahead, so local users keep the rest of their 300 s window (about 4 messages). If the windows were equal, distant messages could use up the whole allowance. Keep the lower-priority window clearly smaller, and give rules on the same clock non-overlapping matches (eg. `hp:0-8` and `hp:9-63`), so each message is counted once.

## Packet tracking table

The packet tracking table puts one shared limit on all the packets a rule matches, used by firewall rules with `tl:pkttrk`. For example, it can cap all distant channel messages together, which also catches spam spread over many channel hashes, or all distant adverts together, which also catches senders using new keys. There are 16 numbered slots, each a clock in seconds.

```
fw <slot> [-] [<key>:<value> ...] tl:pkttrk ls:<0-15> lb:<burst> lr:<time> ac:drop
```

The slot can send `lb` packets in a row, then 1 more every `lr`. A packet over the slot's allowance matches, so the rule drops it; a packet within it is counted and goes on to the next rule.

The default rules use it with commands like these:

```
fw 12 nm:chandos1 pt:grptxt  hp:9-63 tl:pkttrk   ls:0 lb:10 lr:6s  ac:drop
fw 13 nm:senddos1 pt:adv     hp:9-63 tl:pkttrk   ls:1 lb:8  lr:5s  ac:drop
```

Their limits are far above normal traffic, so they only act during a flood of packets.

| Key | Field | Value |
|---|---|---|
| `ls` | limit slot | 0-15 (required) |
| `lb` | limit burst | packets allowed in a row |
| `lr` | limit recover | time to recover 1 packet: minutes, or `30s` / `5m` / `4h` / `2d` |

Rules using the same slot share its allowance, in the same way as rules sharing a channel's clock (see [Channel tracking table](#channel-tracking-table)).

## Firewall log

The firewall log keeps the 128 most recently dropped packets, newest first: which rule dropped each one, its payload type, hop count, and the key its rule's table used. It is in RAM only, starts empty at boot, and isn't included on STM32.

```
fw log [<rule>|-]
fw log<p> [<rule>|-]
fw log csv [<rule>|-]
fw log clear
```

`fw log` shows the whole log (serial console only), `fw log<p>` a page of 5 entries (works remotely). Add a rule number to show only that rule's drops, or `-` for packets no rule matched. `fw log csv` prints the log as CSV (serial console only). `fw log clear` empties the log; the counts since boot stay.

```
fw log
drops: 1873 since boot, 128 logged
# age rule         type     route   hops  key
  12s  4 advlm3    adv      flood     11  pre a1b2c3d4
  40s 11 chanlm2   grptxt   tflood     9  ch 5e
   1m 12 chandos1  grptxt   flood     10  ls 0
   3m  1 hoppol    req      flood      9  hop req
   5m  8 reqlm2    req      tflood     6  src 3a via 9e
   7m  0 routepol  txt      flood      4  route 2 (reqfld1)
   9m  - (none)    raw      flood      2
  ...
```

| Key | Table | Meaning |
|---|---|---|
| `pre a1b2c3d4` | `sendtrk` | adverts and anon requests: the first 4 bytes of the sender's public key |
| `src 3a via 9e` | `sendtrk` | requests, responses, DMs and path returns: the source hash and the first repeater (no `via` when heard straight from the sender) |
| `ch 5e` | `chantrk` | the channel hash |
| `ls 0` | `pkttrk` | the packet tracking slot |
| `route 2 (reqfld1)` | `routepol` | the route policy slot that matched |
| `hop req` | `hoppol` | the hop policy entry that matched |

A rule without a table has no key. `- (none)`: no rule matched, so the packet was dropped at the end of the list. `- (old)`: the rule was replaced or its slot emptied since. Entries move with their rules on `fw insert` / `fw collapse`, and `fw clear` / `setdefault` / `reload` empty the log.

Pages leave out the labels, the rule names and the route type to fit 5 entries in one reply. Filtered pages leave out the slot too, and their first line is the rule's drops since boot (its match count):

```
fw log1
drops: 1873
12s 4 adv 11 a1b2c3d4
40s 11 grptxt 9 5e
1m 12 grptxt 10 0
3m 1 req 9 req
5m 8 req 6 3a/9e
...
```

```
fw log1 4
rule 4 advlm3: 236 drops
12s adv 11 a1b2c3d4
2m adv 9 77c1e0a9
5m adv 14 0be4f512
9m adv 10 a1b2c3d4
14m adv 12 a1b2c3d4
...
```

On pages, `-` is a drop with no rule matched and `old` a rule since replaced. The log is shared by all rules, so a busy rule can push a quiet rule's drops out of it: the count since boot shows how many there were.

`fw log csv` prints the same drops as CSV for a spreadsheet (serial console only), newest first. `age_s` is how many seconds ago the packet was dropped, and `uptime_s` the repeater's uptime then (it stays the same between dumps, so two dumps can be merged). Keys are shown without their labels, as on the pages, and `table` says which table each key is from:

```
fw log csv
age_s,uptime_s,rule,name,type,route,hops,table,key
12,86388,4,advlm3,adv,flood,11,sendtrk,a1b2c3d4
40,86360,11,chanlm2,grptxt,tflood,9,chantrk,5e
545,85855,-,(none),raw,flood,2,,
```

## CLI Reference

Replies (except show pages) can be pasted back as commands. Show pages start with a first line (`firewall on` / `firewall off` for `fw`, `OK` for the others), and end with a `...` line when a later page has data. Changes are live but not saved until `save`.

| Command | |
|---|---|
| `fw` | slots in use, then ` (firewall off)` if it's off |
| `fw show1` ... `show6` | 6 slots per page: `firewall on` / `off`, then one `slot name match_count` line per rule |
| `fw show` | every rule as `fw <n> - <config>` commands, after `set fw.enabled 0/1` (serial console only) |
| `fw counts` | every rule's match count, `slot name action matches` (serial console only) |
| `fw <n>` | the rule, eg. `nm:hoppol tl:hoppol ac:drop`, or `-` if the slot is empty |
| `fw <n> <words>` | `key:value` sets, `key` shows, `show` the whole rule, `-` clears the slot first |
| `fw insert <n>` / `fw collapse <n>` | open slot n / remove empty slot n, moving the rules after it |
| `fw clear` / `setdefault` / `save` / `reload` | |
| `fw unsave` | removes the saved rules: the current ones stay, the defaults load at boot (or `fw setdefault`) |
| `fw senders1` / `senders2` ... | the sender tracking table (`tl:sendtrk`), 4 `sendtrk` rules per page: `senders: <tracked>/<size>` (size: 2340, or 585 on STM32), then the title `# rule tracked/maxed (dropped)`, then `<slot> <name> <tracked>/<maxed> (<dropped>)` per rule, eg. `4 advlm3 7/7 (1234)`. tracked: senders whose limit is still in effect (allowance not fully back); maxed: senders whose next packet would be dropped (with `lb:1` that's every tracked sender); dropped: packets the rule dropped (its match count, as `fw show<p>`; `fwd` after it on an `ac:fwd` rule, which forwards them instead). `(overwriting)`: all <size> are tracked, so a new one replaces the one closest to fully recovered, losing its limits early |
| `fw senders` | the whole sender tracking table (serial console only): `senders: <tracked> tracked, <in use>/<size> records, <n> replaced since boot` (replaced: records whose limits were lost early because the table was full), then the title `# rule tracked maxed dropped window` and a line for every `sendtrk` rule (as the pages; window: `lb` x `lr`), then `left over from old rules`: clocks of slots that no longer hold a `sendtrk` rule |
| `fw log1` / `log2` ... `[<n>\|-]` | the firewall log, 5 drops per page, newest first, of all rules, rule n, or no rule matched (see [Firewall log](#firewall-log)) |
| `fw log [<n>\|-]` | the whole firewall log (serial console only) |
| `fw log csv [<n>\|-]` | the firewall log as CSV (serial console only) |
| `fw log clear` | empties the firewall log |
| `routepol ...` | the same as `fw`, without insert / collapse (fields `nm`, `rh`, `ps`); `show1` ... `show6`: 6 slots per page, `slot name match_count` |
| `routepol counts` | every route's match count, `slot name matches` (serial console only) |
| `hoppol` | limits that are set, eg. `txt:12 path:12` |
| `hoppol <words>` | `name:max` sets (`-` none), `name` shows, `show1` ... `show5`: 5 entries per page, `entry name seen/matched` |
| `hoppol show` | every entry's limit as `hoppol` commands (serial console only) |
| `hoppol counts` | all 22 entries, `entry limit seen matched` (serial console only) |
| `hoppol clear` / `setdefault` / `save` / `reload` / `unsave` | |
| `config show` | the whole firewall, route policy, hop policy, backup mode and reports setup as one script of commands, each table cleared first and saved after, to paste into this or another repeater (serial console only). Regions and stock settings aren't included. While it's pasted, between `fw clear` and the rules, no flood-routed packets are forwarded |
| `cmds` / `cmds <group>` | the commands this build adds: the groups, or one group's commands (`fw`, `routepol`, `hoppol`, `primary`, `stats`, `reports`, `config`), one reply each so they work remotely. `x[p]`: `x<p>` a page, plain `x` serial console only; `*`: serial console only |

Serial console only commands reply remotely with an error naming the paged command to use instead, eg. `Err - fw counts: serial console only, use fw show<p>`.

Saved files: `/fw_rules_v1`, `/route_pol_v1`, `/hop_pol_v1` (text, one entry per line). If a saved file can't be loaded (at boot or by `reload`), that table gets its defaults; `reload` with nothing saved changes nothing. A saved rule whose region is no longer in the region list is skipped (its slot left empty), and the rest load.

## Files

| File | |
|---|---|
| `examples/simple_repeater/FirewallTable.h` | rules, checks, `fw` CLI, defaults |
| `examples/simple_repeater/RoutePolicy.h` | route policy, `routepol` CLI |
| `examples/simple_repeater/HopPolicy.h` | hop policy, `hoppol` CLI |
| `examples/simple_repeater/SenderTracking.h` | per-sender allowances, one clock per rule |
| `examples/simple_repeater/FirewallLog.h` | the log of recently dropped packets (`fw log`) |
| `examples/simple_repeater/ChannelTracking.h` | per-channel message allowances |
| `examples/simple_repeater/PacketTracking.h` | allowance clocks (`ls` slots, and the channels') |
| `examples/simple_repeater/TableCli.h` | CLI helpers shared by the tables |
| `examples/simple_repeater/TableFile.h` | file helpers |
| `examples/simple_repeater/MyMesh.cpp` | `allowPacketForward()` calls the firewall; `begin()` loads the tables; the serial console only commands (`show`, `counts`, `fw senders`, `config show`) and `cmds` |
| `src/helpers/CommonCLI.cpp` | `set` / `get fw.enabled` |
