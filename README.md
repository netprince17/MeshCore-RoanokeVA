# MeshCore for RoanokeMesh Repeaters

This is a build of [MeshCore](https://github.com/meshcore-dev/MeshCore) for the [RoanokeMesh](https://roanokemesh.org) area. This firmware comes pre-configured with LORA settings and regions for our area, as well as some basic filtering and stats designed to keep the mesh optimized for messaging.

## What's different from stock MeshCore

- **Pre-configured for our area:** the US/Canada LoRa preset (910.525 MHz, BW 62.5, SF 7, CR 8), and our regions: `us`, `us-south`, `us-east`, `us-southeast`, `us-va` and `us-va-sw`. The regions are added at boot-up whenever none are already installed.  The local region is not installed by default, it can still be added if necessary.
- **Packet firewall:** a very basic firewall similar to iptables, with defaults configured to optimize communications for messaging, and reduce background noise such as distant repeater logins and group data packets. Manage it with `fw`, `routepol` and `hoppol`. See [docs/firewall_rules.md](docs/firewall_rules.md).
- **Stats history:** airtime, noise floor, packets/bytes counters, firewall drops, send queue, busy-channel waits and more, every 5 minutes for the last 24 hours. Use `stats`. See [docs/stats_history.md](docs/stats_history.md).
- **Reports and alerts:** the repeater answers `report` and `report <name>` requests on the `#repeaters` channel (off by default), and posts alerts there for low battery, high airtime and a rising noise floor (on by default), scoped to a region. Configure it with `set` / `get` `reports.*` and `alerts.*`. See [docs/reports.md](docs/reports.md).
- **Serial console:** backspace works properly with terminal apps such as putty.

## Getting started

1. Download the repeater firmware for your board from this repository's [Releases](../../releases).  Make sure you pick the one for your exact hardware.  *The version with 'merged' in the name will erase your current settings, and the version without 'merged' in the name will keep your current settings.*
2. Open the standard [MeshCore flasher](https://flasher.meshcore.io). Instead of selecting your hardware from the list, choose **Custom Firmware** and select the file you downloaded.
3. Flash the firmware.
4. On the same page, use the 'Repeater Setup' link to set the name of the repeater.  

NOTE: The default settings only apply on new installs or doing a factory rest.  The default regions will apply on boot anytime there are no regions configured.

## Upstream

Everything else is stock MeshCore: see [README-meshcore.md](README-meshcore.md) and the [MeshCore repository](https://github.com/meshcore-dev/MeshCore). MIT licence, as upstream: [license.txt](license.txt).

More about the network: [roanokemesh.org](https://roanokemesh.org).
