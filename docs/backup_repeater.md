# Backup Repeater Mode (aka Enhanced Receive Mode)

Backup mode is a repeater mode used to enhance the reception of another repeater, or take over if that repeater stops working.  This works best when the repeaters are very close to each other.  An example could be a rooftop repeater on your house, and a hilltop repeater in your backyard.

Backup mode works by listening for meshcore packets, and making sure they are forwarded by the primary repeater.  If the primary repeater forwards the packets, the backup repeater does nothing.  If the primary repeater does not forward the packet, the backup repeater forwards the packet.

No special configuration is required on the primary repeater, so this could be used to enhance or backup someone else's repeater.

## Testing: Why this works

In my testing, I have a high hilltop repeater, and a less-high rooftop repeater.  The high hilltop repeater is exposed to a lot of interference, and does not receive 10%-20% of meshcore traffic.  The rooftop repeater is not exposed to as much interference, and therefore is able to recover many packets that the hilltop repeater does not receive.

The backup repeater tracks how many packets it had to send because the primary did not send them.  For example, use the 'stats 5' command to see the last 5 minutes.

## Configuring the backup repeater

The backup repeater holds each received packet long enough to allow the primary repeater to send it first.  If the primary repeater sends the packet, the backup repeater skips sending that packet.  If the primary repeater does not send the packet before the holdoff time expires, the backup repeater sends it.

The backup repeater does not forward adverts from the primary repeater.  This is to help preserve airtime for incoming packets.

The backup repeater's algorithm only affects flood packets, directed (routed) packets work just like a standard repeater.

Backup mode is enabled when `primary holdoff` is greater than 0 and at least one primary repeater is configured. The default holdoff is 0: disabled.

**Recommended holdoff setting: 10** With the default `rxdelay` (3.0) and `txdelay` (1.5), using `holdoff 10` should give the primary repeater enough time to send the packet before the backup sends it. Lower values relay sooner when a primary misses a packet, but the backup may relay before the primary for certain packets.

Held relays wait in the packet pool shared with received packets (32), so while very unlikely, it is possible a long hold-off on a busy channel could leave no room for incoming packets (monitor `sq` value in `stats` command).

1-byte, 2-byte and 3-byte packets all match a configured repeater, whether the config is 1, 2, or 3 bytes.

## Commands

| Command | Reply | |
|---|---|---|
| `primary <n> <hash>` | `OK` | sets slot `<n>` (0-15) to a primary's hash: 2, 4 or 6 hex digits (1-3 bytes) |
| `primary <n> -` | `OK` | clears slot `<n>` |
| `primary <n>` | `cc12 1234` | shows slot `<n>`: hash, relays skipped since boot (`-` if empty) |
| `primary holdoff <n>` | `OK` | sets the hold-off: 0 (off) or 1-20 times the packet's airtime.  10 is recommended. |
| `primary holdoff` | `10` | shows the hold-off |
| `primary` | `on 0:cc12 1:ab` | `on` or `off` (hold-off above 0 and a primary set), and the slots in use |
| `primary save` | `OK - saved` | saves the hold-off and the slots to `/primary_v1`, loaded at boot |
| `primary unsave` | `OK - saved settings removed, off at boot` | removes the saved settings; the current ones stay until a reboot |
| `primary reload` | `OK - saved settings loaded` | goes back to the saved settings |
| `primary clearall` | `OK - all slots cleared, not saved` | empties every slot (the hold-off stays; with no slots it's off) |
| `primary show<p>` | see below | page `<p>` (1-3) of 6 slots: relays skipped since boot per primary, for the slots in use |
| `primary show` | see below | every slot in use, serial console only |

`primary show1` (slots 0-5; `show2` 6-11, `show3` 12-15), and `primary show` on the serial console for all of them: the first line says whether the mode is on and the hold-off, then one line per slot in use: slot, hash, relays skipped since boot. A page with no slots in use replies its range instead, eg. `no primaries 6-11`, and a page ends with a `...` line when a later page has slots in use (as `fw show<p>`):


## Examples

Add a primary repeater (cc12) in slot 0, and set the holdoff, enabling backup mode:

```
> primary 0 cc12
> primary holdoff 10
> primary save
```

Shows the current configuration

```
> primary show1
primary on holdoff=10
0 cc12 1234
1 ab 56
```

Show how many packets were skipped and sent in the last 5 minutes:
```
> stats 5
...
skp/snt: 16/2
```

## Stats

The [stats history](stats_history.md) counts, per 5-minute slot, the relays skipped and the relays sent because no primary was heard relaying them (`skp/snt` in `stats <n>` / `stats +<n>`). On STM32 boards there's no stats history, so only the per-primary counts are kept.

The [alerts](reports.md) include `alerts.primary.missed` (default 24): while this mode is on, an alert when at least that many relays a slot are sent because no primary relayed them, 2 slots in a row, eg. `ALERT primary missed 41 relays (5m), skipped 3`.

## Files

| File | |
|---|---|
| `examples/simple_repeater/PrimaryRepeater.h` | settings, the `primary` commands, the hold-off, the primary relays heard, the per-primary counts |
| `examples/simple_repeater/MyMesh.cpp` | hooks it up: `getRetransmitDelay()`, cancelling in `logRx()`, `allowPacketForward()`, the commands |
| `examples/simple_repeater/StatsHistory.h` | the `skp` and `snt` counts |
| `examples/simple_repeater/Reports.h` | the primary missed alert |
