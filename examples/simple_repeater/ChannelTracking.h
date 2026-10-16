#pragma once

#include "PacketTracking.h"

// Per-channel allowances for channel messages (GRP_TXT / GRP_DATA, firewall tl:chantrk with lb / lr): one
// PacketTracking clock for each of the 256 channel hashes. Channels sharing a hash share an allowance. RAM only.

class ChannelTracking {
  PacketTracking<256> _clocks;   // per channel hash

public:
  // Firewall check (tl:chantrk): true if a channel message is over its channel's allowance (the hash in payload[0])
  // of 'limit_burst', then 1 per 'limit_recovery' seconds. Within it: the message is counted, false. Other packet
  // types: false (not handled). Expects Packet.h to be included first, as MyMesh.h does.
  bool isOverLimit(const mesh::Packet* packet, uint64_t uptime_millis, uint32_t limit_recovery, uint8_t limit_burst) {
    uint8_t type = packet->getPayloadType();
    if (type != PAYLOAD_TYPE_GRP_TXT && type != PAYLOAD_TYPE_GRP_DATA) return false;   // not handled here
    if (packet->payload_len < 1) return false;
    return _clocks.isOverLimit(packet->payload[0], uptime_millis, limit_recovery, limit_burst);
  }
};
