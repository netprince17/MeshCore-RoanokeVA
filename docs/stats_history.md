# Repeater Stats History

The simple repeater keeps a history of its radio stats: one reading per 5-minute slot, for the last 24 hours (288 slots). It's in RAM only, so it starts empty at every boot, and the first slot is filled 5 minutes after boot. `clear stats` doesn't touch it. It isn't built for STM32 boards (STM32WL, 64 KB RAM).

## What's recorded

Per slot:

| Stat | |
|---|---|
| packets / bytes received | decoded packets only (as RX airtime), bytes as on air |
| packets / bytes sent | every packet sent (forwarded or our own), bytes as on air |
| RX / TX airtime | whole percent of the slot, rounded to nearest. TX is measured; RX is estimated from decoded packets, so it's a lower bound on how busy the channel is |
| noise floor | median of the slot's RSSI readings (one every 5 s while the radio is listening), dBm. Packets are short, so it follows the background noise. It shifts if the RX gain or frequency changes |
| firewall drops | floods the firewall dropped (none while `fw.enabled` is 0) |
| RX errors | packets the radio heard but couldn't read, eg. CRC failures from collisions or interference |
| flood dups | floods heard again after they were already seen: how many other repeaters around here pass the same traffic |
| send queue peak | the most packets waiting to be sent at once (the pool holds 32) |
| deferred | sends put off because the channel was busy (a packet coming in, or `int.thresh` exceeded), one per retry (every 120-360 ms) |
| forced | sends forced out after the channel stayed busy for 4 s |
| holds | times sending was held back because the airtime budget (`set dutycycle`) was used up, one per hold until the next send |
| looped | floods dropped by loop detection (`loop.detect`) |

Counts stop at 65535 per slot (255 for looped and the send queue) instead of wrapping, so the maximum means "at least"; totals over several slots are then minimums too. RX errors and flood dups come from running totals that `clear stats` resets: a slot it happens in only counts from the reset.

## CLI

Works on the serial console and remotely; every reply fits one message. Only completed slots are shown: the newest is the last full 5 minutes, so it can be up to 10 minutes old.

**`stats`**: a summary. Airtime and noise floor for the last 5 min / 15 min / 60 min / 24 h (each the average of those slots, or of the slots there are so far; `-` if no slot had a noise reading), and the 24 h totals of packets / bytes in and out and firewall drops:

```
air_rx: 3%/2%/2%/1%
air_tx: 1%/1%/1%/1%
nf: -112/-111/-112/-113
in_24hr: 4521p/312040b
out_24hr: 2210p/158900b
fw_24hr: 37
hist: 125m
```

`hist` is how far back the history goes, so which `stats <minutes>` work (up to `1440m`). It's the last line, so in the extreme case of a reply over 160 characters it's what gets cut off.

**`stats <minutes>`** (5, 10, 15 ... 1440): every stat of the one slot that ended that long ago, as recorded. `stats 5` is the newest slot, `stats 10` the one before it, `stats 15` the one from 10-15 minutes ago. Other numbers are rejected.

**`stats +<minutes>`** (5, 10, 15 ... 1440): every stat over the last that many minutes (or the history there is), eg. `stats +15` the newest 3 slots summed: counts are totals, airtime and noise floor averages, the send queue the highest.

**`stats all`**: the same, over every slot there is (as much as the summary's `hist` line says; the same as `stats +1440`).

```
rx: 210p/14560b
tx: 98p/6720b
arr/art: 2%/1%
nf: -112
fw/err/dup: 37/5/88
sq: 6
dfr/frc/hld: 12/0/0
lp: 1
```

Replies are cut off at 160 characters; only extreme 24 h totals could reach that.

| Line | Stat |
|---|---|
| `rx` / `tx` | packets / bytes received / sent |
| `arr` / `art` | RX / TX airtime % |
| `nf` | noise floor, dBm (`-` if no reading) |
| `fw` / `err` / `dup` | firewall drops / RX errors / flood dups |
| `sq` | send queue peak |
| `dfr` | sends deferred |
| `frc` | sends forced |
| `hld` | duty cycle holds |
| `lp` | looped floods dropped |

## Files

| File | |
|---|---|
| `examples/simple_repeater/StatsHistory.h` | the history, and the `stats` replies |
| `examples/simple_repeater/MyMesh.cpp` | feeds it (`loop()`, `logRx()`, `logTx()`, loop detection, firewall) and the `stats` command |
| `src/Dispatcher.h` / `.cpp` | `logTxDeferred()`, `logTxForced()` and `logTxBudgetHold()` hooks |
