# Repeater Reports and Alerts

The repeater can answer `report` requests and post alerts on a channel, by default the `#repeaters` hashtag channel. Everything it sends and answers is scoped to one region. Replies are off by default (`set reports.enabled 1` turns them on); alerts are on by default (`set alerts.enabled 0` turns them off). The channel, region and hop settings apply to both. It needs the [stats history](stats_history.md), so it isn't built for STM32 boards.

## Reports

Send one of these on the channel, scoped to the region:

| Message | Who replies | Delay | Cooldown |
|---|---|---|---|
| `report` | every repeater with reports on | random 1-30 s | `reports.cooldown` |
| `report <name>` | only the repeater with that name (not case-sensitive) | 1-3 s | none |

Only requests sent in `reports.channel.region`, and relayed at most `reports.hops.max` times, are answered. The reply comes from the repeater (its name is the sender), eg.:

```
v1.18.0
3d4h, 4.05V, air 3%/1% (60m)
nf -112, fw 410 (24h), nb 5
tx 10230, rx 21503, err 37 (24h)
```

| Part | |
|---|---|
| `v1.18.0` | firmware version |
| `3d4h` | uptime, days and hours |
| `4.05V` | battery voltage (left out if the board can't measure it) |
| `air` | RX / TX airtime, average over the last 60 minutes |
| `nf` | noise floor (dBm), average over the last 60 minutes |
| `fw` | packets the firewall dropped, last 24 hours |
| `nb` | neighbour repeaters heard directly in the last 7 days |
| `tx` / `rx` / `err` | packets sent, decoded packets received, and packets heard but not readable, last 24 hours |

Just after boot, items without data yet (airtime and noise floor, until the first 5-minute slot) are left out.

## Alerts

While alerts are on (`alerts.enabled`), the repeater posts an alert when a reading is out of range at 2 completed stats slots (5 minutes each) in a row. Each alert repeats at most once per `alerts.cooldown`, and none are sent in the first 15 minutes after boot. Set an alert's value to 0 to turn it off.

| Alert | Out of range when | Message |
|---|---|---|
| battery | below `alerts.battery` / 10 V | `ALERT battery low 3.38V` |
| airtime | RX airtime at or above `alerts.airtime` % | `ALERT rx airtime high 31% (5m)` |
| noise floor | at least `alerts.noisefloor` dB above the average of the earlier history (from 1 hour of history) | `ALERT noise floor up 12dB: -100dBm (24h avg -112dBm)` |

## How replies and alerts are sent

They go out like a channel message from a companion: through the repeater's normal send queue, so the usual send checks apply (listen before transmit, the duty cycle), scoped to `reports.channel.region`.

To cap how far they're relayed, the path is pre-filled with dummy `000000` 3-byte hashes, leaving `reports.hops.max` slots: every repeater stops relaying a packet once its path is full. Repeaters running this firmware don't count the dummy hashes as hops (`hp:` rules and the hop policy see the real count). Stock repeaters count them, so one with a low `flood.max` (below about 21) won't relay reports.

## Settings

`set <setting> <value>` and `get <setting>`, saved straight away. `get reports` and `get alerts` list them all.

| Setting | Default | Values |
|---|---|---|
| `reports.enabled` | `0` | `0` / `1`: replies to `report` / `report <name>` |
| `reports.channel.key` | `89db441e2814dccf0dbd2e8cc5f501a3` (`#repeaters`) | the channel's secret, 32 hex digits |
| `reports.channel.region` | `us-va` | region name, required: the scope of everything sent and answered |
| `reports.hops.max` | `3` | 0-8: requests relayed at most this many times are answered, replies and alerts are relayed at most this many times |
| `reports.cooldown` | `60` | 15-1440 minutes between replies to `report` |
| `alerts.enabled` | `1` | `0` / `1`: the alerts |
| `alerts.battery` | `34` | tenths of a volt (34 = 3.4 V), 10-50, `0` = off |
| `alerts.noisefloor` | `10` | dB, 3-40, `0` = off |
| `alerts.airtime` | `25` | RX airtime %, 1-100, `0` = off |
| `alerts.cooldown` | `60` | 15-1440 minutes between repeats of the same alert |

For a hashtag channel, the key is the first 16 bytes of `sha256("#name")`:
```
python3 -c 'import hashlib; print(hashlib.sha256(b"#repeaters").digest()[:16].hex())'
```

## Files

| File | |
|---|---|
| `examples/simple_repeater/Reports.h` | settings, request checks, the reply text, alerts, message and packet building |
| `examples/simple_repeater/MyMesh.cpp` | hooks it up: the channel, creating and queueing packets, the `set` / `get` commands |
| `examples/simple_repeater/FirewallTable.h` | `realHopCount()`: hop counts without the dummy hashes |
