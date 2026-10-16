# MeshCore for RoanokeMesh

A build of [MeshCore](https://github.com/meshcore-dev/MeshCore) for the [RoanokeMesh](https://roanokemesh.org) network. The repeater firmware comes pre-configured for our area, with regions and flood filtering already set up, so a new repeater works well out of the box. Based on MeshCore v1.18.0.

## What's different from stock MeshCore

- **Pre-configured for the area:** the US/Canada LoRa preset (910.525 MHz, BW 62.5, SF 7, CR 8), and our regions: `us`, `us-south`, `us-east`, `us-southeast`, `us-va` and `us-va-sw`. The regions are added at boot whenever none are set up besides `*`, on new installs and upgrades alike.
- **Flood firewall:** rules decide which floods the repeater forwards. The defaults limit adverts and anon requests per sender, limit channel messages per channel and in total, keep `#wardriving` local, and apply route and hop limits. Manage it with `fw`, `routepol` and `hoppol`, or turn it off with `set fw.enabled 0`. See [docs/firewall_rules.md](docs/firewall_rules.md).
- **Stats history:** airtime, noise floor, packets and bytes, firewall drops, send queue, busy-channel waits and more, every 5 minutes for the last 24 hours. Use `stats`. See [docs/stats_history.md](docs/stats_history.md).
- **Repeater defaults for a busy mesh:** strict loop detection, 3-byte path hashes, longer advert intervals, and more forwarding delay.
- **Serial console:** backspace works.

## Getting started

1. Download the repeater firmware for your board from this repository's [Releases](../../releases). Each release has a file per board: make sure you pick the one for your exact hardware.
2. Open the standard [MeshCore flasher](https://flasher.meshcore.co.uk). Instead of selecting your hardware from the list, choose **Custom Firmware** and select the file you downloaded.
3. Flash, then set the repeater's name and admin password as usual.

The area settings and filtering are defaults: a new install gets them all. A repeater that already has saved settings keeps them, apart from the regions, which are added if it only has `*`.

## Upstream

Everything else is stock MeshCore: see [README-meshcore.md](README-meshcore.md) and the [MeshCore repository](https://github.com/meshcore-dev/MeshCore). MIT licence, as upstream: [license.txt](license.txt).

More about the network: [roanokemesh.org](https://roanokemesh.org).
