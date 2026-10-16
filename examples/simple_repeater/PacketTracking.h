#pragma once

#include <stdint.h>

// Allowance clocks for firewall limits: 'SLOTS' clocks, each shared by every packet counted against it.
// tl:pkttrk uses PacketTracking<PACKET_TRACKING_SLOTS> (slot ls, any packet the rule matches); ChannelTracking
// uses one per channel hash. A packet within the allowance pushes its clock forward limit_recovery; it may not get
// more than limit_burst x limit_recovery ahead of now. 32-bit uptime seconds, so no wrap handling and no window
// limit. RAM only, every clock starts with a full allowance.

#define PACKET_TRACKING_SLOTS        16     // ls: 0..PACKET_TRACKING_SLOTS-1

template <int SLOTS>
class PacketTracking {
  uint32_t _next[SLOTS];   // per slot: allowance clock, uptime seconds

public:
  PacketTracking(): _next() { }

  // Firewall check: true if a packet is over slot 'slot's allowance of 'limit_burst', then 1 per 'limit_recovery'
  // seconds (limit_burst 0: always over). Within it: the packet is counted, false. A bad slot: false.
  bool isOverLimit(int slot, uint64_t uptime_millis, uint32_t limit_recovery, uint8_t limit_burst) {
    if (slot < 0 || slot >= SLOTS) return false;
    if (limit_burst == 0 || limit_recovery == 0) return true;
    uint32_t window = (uint32_t)limit_burst * limit_recovery;   // at most 255 x lr's longest: fits

    uint32_t now = (uint32_t)(uptime_millis / 1000);
    uint32_t next = _next[slot];
    if (next < now) next = now;                    // behind now: fully recovered
    uint32_t after = next + limit_recovery;        // push forward one timespan
    if (after - now > window) return true;         // too far ahead: over the limit
    _next[slot] = after;
    return false;
  }
};
