#pragma once

#include <stdint.h>

// Per-sender allowances (firewall tl:sendtrk with lb / lr). Every sendtrk rule has its own clock for each sender, so
// rules (eg. hop bands) never share or double count an allowance. The sender is:
//   adverts, anon requests:    4 middle bytes of the public key
//   req, resp, txt, path:      the 1-byte source hash and the first real repeater's hash (1-3 bytes, 0 if heard
//                              straight from the sender), so one clock per sender whatever the destination
// A rule without pt shares a sender's clock between the packet types it sees. An allowed packet pushes its clock
// forward limit_recovery, and it may not get more than limit_burst x limit_recovery ahead of now. When full, a new
// record replaces the one with the least time left. RAM only.

#ifndef SENDER_TRACKING_SIZE
  #if defined(STM32_PLATFORM)
    #define SENDER_TRACKING_SIZE    585        // 4 KB (7 bytes per record), STM32WL only has 64 KB RAM
  #else
    #define SENDER_TRACKING_SIZE    2340       // 16 KB (7 bytes per record)
  #endif
#endif

// Longest allowance, limit_burst x limit_recovery, in minutes (~22 days: half the 16-bit clock range).
#define SENDER_TRACKING_MAX_WINDOW      32767

// How often add() moves clocks that are behind now up to now, in minutes (see recoverAll())
#define SENDER_TRACKING_RECOVER_MINUTES 60

class SenderTracking {
  // One record per (sender, rule), kept in three arrays so every field is aligned (7 bytes per record)
  uint32_t _ids[SENDER_TRACKING_SIZE];              // sender: 4 middle public key bytes (adverts, anon
                                                    // requests), or the source hash and the first repeater's
                                                    // hash (1-3 bytes, unused bytes 0)
  uint8_t  _rules[SENDER_TRACKING_SIZE];            // firewall rule slot owning this clock
  uint16_t _recovery_clocks[SENDER_TRACKING_SIZE];  // repeater uptime in minutes when the allowance is full
                                                    // again: now, or ahead of now while recovering
  int _count;              // records in use (0..SENDER_TRACKING_SIZE)
  uint32_t _last_recover;  // uptime minutes of the last recoverAll()
  uint32_t _replaced;      // records replaced while their limits were still in effect (table full), since boot

public:
  SenderTracking(): _count(0), _last_recover(0), _replaced(0) { }

  // sender id: 4 middle bytes of the public key (resists vanity-key grinding of the first bytes)
  static uint32_t keyIdOf(const uint8_t* pub_key) {
    return ((uint32_t)pub_key[8]  << 24) | ((uint32_t)pub_key[14] << 16) |
           ((uint32_t)pub_key[20] <<  8) |  (uint32_t)pub_key[26];
  }

  // sender id: the source hash, then the first repeater's hash (1-3 bytes, unused bytes 0; 0 if no repeater yet).
  // Dummy 3-byte 000000 hashes at the start of the path (see FirewallTable::realHopCount()) are skipped.
  static uint32_t hashIdOf(uint8_t src_hash, const mesh::Packet* packet) {
    uint32_t id = (uint32_t)src_hash << 24;
    uint8_t size = packet->getPathHashSize();
    uint8_t count = packet->getPathHashCount();
    for (uint8_t h = 0; h < count; h++) {
      const uint8_t* hash = &packet->path[h * size];
      if (size == 3 && hash[0] == 0 && hash[1] == 0 && hash[2] == 0) continue;   // dummy
      for (uint8_t i = 0; i < size && i < 3; i++) id |= (uint32_t)hash[i] << (16 - 8 * i);
      break;
    }
    return id;
  }

  // Firewall check (tl:sendtrk) for rule slot 'rule': true if the packet is over its sender's allowance of
  // 'limit_burst', then 1 per 'limit_recovery' seconds (rounded up to whole minutes). Within it: the packet is
  // counted, false. Adverts: the signed public key. Anon requests: the public key after the dest hash (can't be
  // verified). req / resp / txt / path: the source hash and first repeater hash (can't be verified). Other packet
  // types, or a payload too short: false (not handled). Expects Packet.h to be included first, as MyMesh.h does.
  // The sender as the firewall log shows it: adverts and anon requests the first 4 public key bytes (how nodes are
  // known, unlike the middle bytes keyIdOf() tracks), req / resp / txt / path the same id as hashIdOf(). 0 for
  // other packet types.
  static uint32_t logKeyOf(const mesh::Packet* packet) {
    uint8_t type = packet->getPayloadType();
    const uint8_t* key = nullptr;
    if (type == PAYLOAD_TYPE_ADVERT && packet->payload_len >= PUB_KEY_SIZE) {
      key = packet->payload;
    } else if (type == PAYLOAD_TYPE_ANON_REQ && packet->payload_len >= PATH_HASH_SIZE + PUB_KEY_SIZE) {
      key = &packet->payload[PATH_HASH_SIZE];
    } else if ((type == PAYLOAD_TYPE_REQ || type == PAYLOAD_TYPE_RESPONSE || type == PAYLOAD_TYPE_TXT_MSG
                || type == PAYLOAD_TYPE_PATH) && packet->payload_len >= 2 * PATH_HASH_SIZE) {
      return hashIdOf(packet->payload[PATH_HASH_SIZE], packet);
    }
    if (key == nullptr) return 0;
    return ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) | ((uint32_t)key[2] << 8) | (uint32_t)key[3];
  }

  bool isOverLimit(const mesh::Packet* packet, int rule, uint64_t uptime_millis, uint32_t limit_recovery,
                   uint8_t limit_burst) {
    uint8_t type = packet->getPayloadType();
    uint32_t id;
    if (type == PAYLOAD_TYPE_ADVERT) {
      if (packet->payload_len < PUB_KEY_SIZE) return false;
      id = keyIdOf(packet->payload);
    } else if (type == PAYLOAD_TYPE_ANON_REQ) {
      if (packet->payload_len < PATH_HASH_SIZE + PUB_KEY_SIZE) return false;
      id = keyIdOf(&packet->payload[PATH_HASH_SIZE]);
    } else if (type == PAYLOAD_TYPE_REQ || type == PAYLOAD_TYPE_RESPONSE || type == PAYLOAD_TYPE_TXT_MSG
               || type == PAYLOAD_TYPE_PATH) {
      if (packet->payload_len < 2 * PATH_HASH_SIZE) return false;
      id = hashIdOf(packet->payload[PATH_HASH_SIZE], packet);
    } else {
      return false;   // not a packet type this table handles
    }
    uint32_t minutes = (limit_recovery + 59) / 60;   // senders are tracked in whole minutes
    if (minutes > 0xFFFF) minutes = 0xFFFF;
    return !add(id, (uint8_t)rule, uptime_millis, (uint16_t)minutes, limit_burst);
  }

  // For 'fw senders', before getRecord(): moves clocks that are behind now up to now, so a clock left untouched for
  // longer than the 16-bit range (no sendtrk packets for ~22 days) doesn't look ahead again
  void recover(uint64_t uptime_millis) { recoverAll((uint32_t)(uptime_millis / 60000)); }

  // For 'fw senders': record 'i' (0..getCount()-1): its rule slot, and minutes its clock is ahead of now (0: fully
  // recovered, no limit in effect).
  int getCount() const { return _count; }
  void getRecord(int i, uint64_t uptime_millis, int& rule, int& ahead_minutes) const {
    rule = _rules[i];
    ahead_minutes = timeLeft(i, (uint16_t)(uptime_millis / 60000));
  }

  // For 'fw senders': records replaced while their limits were still in effect (the table was full), since boot
  uint32_t getReplaced() const { return _replaced; }

  // forgets every clock (the rules were replaced)
  void clear() { _count = 0; }

  // forgets rule slot 'rule's clocks (the rule was replaced or removed)
  void forgetRule(int rule) {
    for (int i = 0; i < _count; ) {
      if (_rules[i] == rule) {   // the last record fills the gap
        --_count;
        _ids[i] = _ids[_count];
        _rules[i] = _rules[_count];
        _recovery_clocks[i] = _recovery_clocks[_count];
      } else {
        i++;
      }
    }
  }

  // moves the clocks of rule slots first..last to slot + delta (the rules moved, 'fw insert' / 'fw collapse')
  void moveRules(int first, int last, int delta) {
    for (int i = 0; i < _count; i++) {
      if (_rules[i] >= first && _rules[i] <= last) _rules[i] = (uint8_t)(_rules[i] + delta);
    }
  }

private:
  // Records a packet for clock (id, rule slot). Returns true if it's within the allowance (the clock moves
  // forward), false if it's over (nothing changes). limit_burst 0: false.
  // 'uptime_millis' must be 64-bit (32-bit millis() wraps after ~49.7 days).
  bool add(uint32_t id, uint8_t rule, uint64_t uptime_millis, uint16_t limit_recovery_minutes, uint8_t limit_burst) {
    if (limit_burst == 0) return false;   // nothing allowed: don't add the sender
    uint32_t window = (uint32_t)limit_burst * limit_recovery_minutes;
    if (limit_recovery_minutes == 0 || window > SENDER_TRACKING_MAX_WINDOW) return false;

    uint32_t now_minutes = (uint32_t)(uptime_millis / 60000);
    if (now_minutes - _last_recover >= SENDER_TRACKING_RECOVER_MINUTES) recoverAll(now_minutes);
    uint16_t now = (uint16_t)now_minutes;

    int r = -1;
    for (int i = 0; i < _count; i++) {
      if (_ids[i] == id && _rules[i] == rule) {
        r = i;
        break;
      }
    }
    if (r < 0) {   // new sender for this rule
      if (_count < SENDER_TRACKING_SIZE) {
        r = _count++;
      } else {
        r = leastTimeLeft(now);
        if (timeLeft(r, now) > 0) _replaced++;   // its limits are lost early
      }
      _ids[r] = id;
      _rules[r] = rule;
      _recovery_clocks[r] = now;
    }

    uint16_t& clock = _recovery_clocks[r];
    if ((int16_t)(clock - now) < 0) clock = now;                // 1. behind now: fully recovered
    uint16_t after = clock + limit_recovery_minutes;            // 2. push forward one timespan
    if ((uint16_t)(after - now) > window) return false;         // 3. too far ahead: over the limit
    clock = after;
    return true;
  }

  // minutes until record 'i' is fully recovered
  uint16_t timeLeft(int i, uint16_t now) const {
    int16_t ahead = (int16_t)(_recovery_clocks[i] - now);
    return ahead > 0 ? (uint16_t)ahead : 0;
  }

  // the record to replace when the table is full: the one with the least time left
  int leastTimeLeft(uint16_t now) const {
    int best = 0;
    uint16_t best_left = timeLeft(0, now);
    for (int i = 1; i < _count && best_left > 0; i++) {
      uint16_t left = timeLeft(i, now);
      if (left < best_left) {
        best_left = left;
        best = i;
      }
    }
    return best;
  }

  // Moves clocks that are behind now up to now (no allowance changes), so none falls far enough behind to look
  // ahead after the 16-bit wrap. Run by add() every SENDER_TRACKING_RECOVER_MINUTES.
  void recoverAll(uint32_t now_minutes) {
    uint16_t now = (uint16_t)now_minutes;
    bool all = now_minutes - _last_recover > SENDER_TRACKING_MAX_WINDOW;
    for (int i = 0; i < _count; i++) {
      if (all || (int16_t)(_recovery_clocks[i] - now) < 0) _recovery_clocks[i] = now;
    }
    _last_recover = now_minutes;
  }
};
