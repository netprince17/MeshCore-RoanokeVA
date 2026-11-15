# RoanokeMesh MeshCore fork

A fork of MeshCore (currently based on upstream 1.18.0) for the RoanokeMesh network. Nearly all of
our work is in the repeater firmware, `examples/simple_repeater/`.

## Repos and branches
- `upstream`: meshcore-dev/MeshCore. `origin`: git.oneitguy.com/bpfountz/meshcore-bgp (work branches).
  `github`: netprince17/MeshCore-RoanokeVA (public releases).
- `roanokeva-build1` is the release branch on `github`, squashed into "RoanokeMesh build" commits.
  Feature work happens on branches on `origin` (adv-filtering-1, backup_repeater1, ...).

## Build
- Verify changes with `pio run -e Heltec_v3_repeater` (ESP32-S3). The nRF52 and STM32 builds are
  blocked on this PC. Ignore the `liblto_plugin-0.dll` warnings.
- Code must still compile for STM32: StatsHistory and Reports are left out there with
  `#if !defined(STM32_PLATFORM)` (STM32WL has 64 KB RAM).

## Repeater additions
- FirewallTable.h: rules for flood-routed packets. It runs last in MyMesh::allowPacketForward(), and
  then the backup-mode check runs. Lookup tables: RoutePolicy.h (`routepol`), HopPolicy.h (`hoppol`),
  SenderTracking / PacketTracking / ChannelTracking (`tl:sendtrk` / `pkttrk` / `chantrk`).
  TableCli.h and TableFile.h are the shared CLI and file helpers.
- StatsHistory.h: 5-minute slots for 24 hours, RAM only (`stats`).
- Reports.h: `report` replies and alerts on the #repeaters channel (`reports.*`, `alerts.*`).
- PrimaryRepeater.h: backup mode (`primary`).
- Each module saves its own file and falls back to built-in defaults (eg. FIREWALL_DEFAULT_RULES).
  `<table> show` works on the serial console only.
- Docs: docs/firewall_rules.md, stats_history.md, reports.md, backup_repeater.md.

## Changes to stock MeshCore (keep these minimal)
- Dispatcher: the logTxDeferred / logTxForced / logTxBudgetHold hooks.
- CommonCLI: the `firewall_enabled` pref (`fw_en`) and `set/get fw.enabled`.
- MyMesh: wiring, the new commands, DEFAULT_REGION_DEF regions at boot, changed default settings.
- main.cpp: serial backspace. platformio.ini: US preset. build.sh: `|| return 0`.
- New code goes in our own headers. Touch upstream files only to hook it up.

## Conventions
- Comments are plain sentences describing behaviour, in the style of the existing headers.
- Say the firewall acts on "packets" or "flood-routed packets", not "floods".
