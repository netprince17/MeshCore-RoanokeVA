#pragma once

#include <stdint.h>

// Per-sender allowances (firewall tl:sendtrk with lb / lr). Every sendtrk rule has its own clock for each sender, so
// rules (eg. hop bands) never share or double count an allowance. The sender is:
//   adverts, anon requests:    4 middle bytes of the public key, one clock per sender (and packet type)
//   req, resp, txt, path:      the 1-byte source hash, one clock per destination hash (the src -> dest pair)
// An allowed packet pushes its clock forward limit_recovery, and it may not get more than limit_burst x
// limit_recovery ahead of now. When full, a new record replaces the one with the least time left. RAM only.

#ifndef SENDER_TRACKING_SIZE
  #if defined(STM32_PLATFORM)
    #define SENDER_TRACKING_SIZE    512        // 4 KB, STM32WL only has 64 KB RAM
  #else
    #define SENDER_TRACKING_SIZE    2048       // 16 KB
  #endif
#endif

// Longest allowance, limit_burst x limit_recovery, in minutes (~22 days: half the 16-bit clock range).
#define SENDER_TRACKING_MAX_WINDOW      32767

// How often add() moves clocks that are behind now up to now, in minutes (see recoverAll())
#define SENDER_TRACKING_RECOVER_MINUTES 60

// SenderRecord::rule: the rule slot in the low 7 bits, and this flag if 'id' is a 1-byte source hash
#define SENDER_TRACKING_RULE_MASK       0x7F
#define SENDER_TRACKING_ID_IS_HASH      0x80

struct SenderRecord {
  uint32_t id;     // sender: 4 middle public key bytes (adverts, anon requests), or the 1-byte source hash
  uint8_t  rule;   // firewall rule slot owning this clock, | SENDER_TRACKING_ID_IS_HASH for a source hash
  uint8_t  dest;   // destination hash for a source hash id, else the payload type (adverts, anon requests apart)
  uint16_t next;   // allowance clock: repeater uptime in minutes, now or ahead of now while recovering
};
static_assert(sizeof(SenderRecord) == 8, "sender record must stay 8 bytes");

class SenderTracking {
  SenderRecord _records[SENDER_TRACKING_SIZE];
  int _count;              // records in use (0..SENDER_TRACKING_SIZE)
  uint32_t _last_recover;  // uptime minutes of the last recoverAll()

public:
  SenderTracking(): _count(0), _last_recover(0) { }

  // sender id: 4 middle bytes of the public key (resists vanity-key grinding of the first bytes)
  static uint32_t idOf(const uint8_t* pub_key) {
    return ((uint32_t)pub_key[8]  << 24) | ((uint32_t)pub_key[14] << 16) |
           ((uint32_t)pub_key[20] <<  8) |  (uint32_t)pub_key[26];
  }

  // Firewall check (tl:sendtrk) for rule slot 'rule': true if the packet is over its sender's allowance of
  // 'limit_burst', then 1 per 'limit_recovery' seconds (rounded up to whole minutes). Within it: the packet is
  // counted, false. Adverts: the signed public key. Anon requests: the public key after the dest hash (can't be
  // verified). req / resp / txt / path: the source hash, per destination hash (can't be verified). Other packet
  // types, or a payload too short: false (not handled). Expects Packet.h to be included first, as MyMesh.h does.
  bool isOverLimit(const mesh::Packet* packet, int rule, uint64_t uptime_millis, uint32_t limit_recovery,
                   uint8_t limit_burst) {
    uint8_t type = packet->getPayloadType();
    uint32_t id;
    uint8_t tag = (uint8_t)(rule & SENDER_TRACKING_RULE_MASK);
    uint8_t dest = type;   // key ids: the type keeps a sender's adverts and anon requests apart (rules without pt)
    if (type == PAYLOAD_TYPE_ADVERT) {
      if (packet->payload_len < PUB_KEY_SIZE) return false;
      id = idOf(packet->payload);
    } else if (type == PAYLOAD_TYPE_ANON_REQ) {
      if (packet->payload_len < PATH_HASH_SIZE + PUB_KEY_SIZE) return false;
      id = idOf(&packet->payload[PATH_HASH_SIZE]);
    } else if (type == PAYLOAD_TYPE_REQ || type == PAYLOAD_TYPE_RESPONSE || type == PAYLOAD_TYPE_TXT_MSG
               || type == PAYLOAD_TYPE_PATH) {
      if (packet->payload_len < 2 * PATH_HASH_SIZE) return false;
      dest = packet->payload[0];
      id = packet->payload[PATH_HASH_SIZE];
      tag |= SENDER_TRACKING_ID_IS_HASH;
    } else {
      return false;   // not a packet type this table handles
    }
    uint32_t minutes = (limit_recovery + 59) / 60;   // senders are tracked in whole minutes
    if (minutes > 0xFFFF) minutes = 0xFFFF;
    return !add(id, tag, dest, uptime_millis, (uint16_t)minutes, limit_burst);
  }

  // Records a packet for clock (id, tag, dest), tag: the rule slot and SENDER_TRACKING_ID_IS_HASH. Returns true if
  // it's within the allowance (the clock moves forward), false if it's over (nothing changes). limit_burst 0: false.
  // 'uptime_millis' must be 64-bit (32-bit millis() wraps after ~49.7 days).
  bool add(uint32_t id, uint8_t tag, uint8_t dest, uint64_t uptime_millis, uint16_t limit_recovery_minutes,
           uint8_t limit_burst) {
    if (limit_burst == 0) return false;   // nothing allowed: don't add the sender
    uint32_t window = (uint32_t)limit_burst * limit_recovery_minutes;
    if (limit_recovery_minutes == 0 || window > SENDER_TRACKING_MAX_WINDOW) return false;

    uint32_t now_minutes = (uint32_t)(uptime_millis / 60000);
    if (now_minutes - _last_recover >= SENDER_TRACKING_RECOVER_MINUTES) recoverAll(now_minutes);
    uint16_t now = (uint16_t)now_minutes;

    SenderRecord* r = nullptr;
    for (int i = 0; i < _count; i++) {
      if (_records[i].id == id && _records[i].rule == tag && _records[i].dest == dest) {
        r = &_records[i];
        break;
      }
    }
    if (r == nullptr) {   // new sender for this rule
      if (_count < SENDER_TRACKING_SIZE) {
        r = &_records[_count++];
      } else {
        r = leastTimeLeft(now);
      }
      r->id = id;
      r->rule = tag;
      r->dest = dest;
      r->next = now;
    }

    if ((int16_t)(r->next - now) < 0) r->next = now;            // 1. behind now: fully recovered
    uint16_t after = r->next + limit_recovery_minutes;          // 2. push forward one timespan
    if ((uint16_t)(after - now) > window) return false;         // 3. too far ahead: over the limit
    r->next = after;
    return true;
  }

  // For 'fw senders', before getRecord(): moves clocks that are behind now up to now, so a clock left untouched for
  // longer than the 16-bit range (no sendtrk packets for ~22 days) doesn't look ahead again
  void recover(uint64_t uptime_millis) { recoverAll((uint32_t)(uptime_millis / 60000)); }

  // For 'fw senders': record 'i' (0..getCount()-1): its rule slot, and minutes its clock is ahead of now (0: fully
  // recovered, no limit in effect).
  int getCount() const { return _count; }
  void getRecord(int i, uint64_t uptime_millis, int& rule, int& ahead_minutes) const {
    uint16_t now = (uint16_t)(uptime_millis / 60000);
    rule = _records[i].rule & SENDER_TRACKING_RULE_MASK;
    int16_t ahead = (int16_t)(_records[i].next - now);
    ahead_minutes = ahead > 0 ? ahead : 0;
  }

  // forgets every clock (the rules were replaced)
  void clear() { _count = 0; }

  // forgets rule slot 'rule's clocks (the rule was replaced or removed)
  void forgetRule(int rule) {
    for (int i = 0; i < _count; ) {
      if ((_records[i].rule & SENDER_TRACKING_RULE_MASK) == rule) {
        _records[i] = _records[--_count];   // the last record fills the gap
      } else {
        i++;
      }
    }
  }

  // moves the clocks of rule slots first..last to slot + delta (the rules moved, 'fw insert' / 'fw collapse')
  void moveRules(int first, int last, int delta) {
    for (int i = 0; i < _count; i++) {
      int rule = _records[i].rule & SENDER_TRACKING_RULE_MASK;
      if (rule < first || rule > last) continue;
      _records[i].rule = (uint8_t)(((rule + delta) & SENDER_TRACKING_RULE_MASK)
                                   | (_records[i].rule & SENDER_TRACKING_ID_IS_HASH));
    }
  }

private:
  // minutes until the record is fully recovered
  static uint16_t timeLeft(const SenderRecord* r, uint16_t now) {
    int16_t ahead = (int16_t)(r->next - now);
    return ahead > 0 ? (uint16_t)ahead : 0;
  }

  // the record to replace when the table is full: the one with the least time left
  SenderRecord* leastTimeLeft(uint16_t now) {
    SenderRecord* best = &_records[0];
    uint16_t best_left = timeLeft(best, now);
    for (int i = 1; i < _count && best_left > 0; i++) {
      uint16_t left = timeLeft(&_records[i], now);
      if (left < best_left) {
        best_left = left;
        best = &_records[i];
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
      SenderRecord* r = &_records[i];
      if (all || (int16_t)(r->next - now) < 0) r->next = now;
    }
    _last_recover = now_minutes;
  }
};
