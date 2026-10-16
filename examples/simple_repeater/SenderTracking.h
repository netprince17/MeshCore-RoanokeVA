#pragma once

#include <stdint.h>

// Per-sender allowances for adverts and anon requests (firewall tl:sendtrk with lb / lr), by public key. Each
// sender has a clock per type: an allowed packet pushes it forward limit_recovery, and it may not get more than
// limit_burst x limit_recovery ahead of now. When full, a new sender replaces the record with the least time left.
// RAM only.

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

struct SenderRecord {
  uint32_t id;               // pubkey bytes 8, 14, 20, 26 (middle bytes, resists vanity-key grinding)
  uint16_t advert_next;      // advert clock: repeater uptime in minutes, now or ahead of now while recovering
  uint16_t anonreq_next;     // anon request clock, same as advert_next
};
static_assert(sizeof(SenderRecord) == 8, "sender record must stay 8 bytes");

class SenderTracking {
  SenderRecord _records[SENDER_TRACKING_SIZE];
  int _count;              // records in use (0..SENDER_TRACKING_SIZE)
  uint32_t _last_recover;  // uptime minutes of the last recoverAll()

public:
  SenderTracking(): _count(0), _last_recover(0) { }

  // sender id: 4 middle bytes of the public key
  static uint32_t idOf(const uint8_t* pub_key) {
    return ((uint32_t)pub_key[8]  << 24) | ((uint32_t)pub_key[14] << 16) |
           ((uint32_t)pub_key[20] <<  8) |  (uint32_t)pub_key[26];
  }

  // Firewall check (tl:sendtrk): true if an advert or anon request is over its sender's allowance of 'limit_burst',
  // then 1 per 'limit_recovery' seconds (rounded up to whole minutes). Within it: the packet is counted, false. The sender is its
  // public key (an anon request's comes after its dest hash, and can't be verified). Other packet types, or a
  // payload too short to hold the key: false (not handled). Expects Packet.h to be included first, as MyMesh.h does.
  bool isOverLimit(const mesh::Packet* packet, uint64_t uptime_millis, uint32_t limit_recovery, uint8_t limit_burst) {
    uint8_t type = packet->getPayloadType();
    const uint8_t* key;
    if (type == PAYLOAD_TYPE_ADVERT) {
      if (packet->payload_len < PUB_KEY_SIZE) return false;
      key = packet->payload;
    } else if (type == PAYLOAD_TYPE_ANON_REQ) {
      if (packet->payload_len < PATH_HASH_SIZE + PUB_KEY_SIZE) return false;
      key = &packet->payload[PATH_HASH_SIZE];
    } else {
      return false;   // not a packet type this table handles
    }
    uint32_t minutes = (limit_recovery + 59) / 60;   // senders are tracked in whole minutes
    if (minutes > 0xFFFF) minutes = 0xFFFF;
    return !add(key, uptime_millis, (uint16_t)minutes, limit_burst, type == PAYLOAD_TYPE_ADVERT);
  }

  // For 'fw senders': the senders still tracked (a clock ahead of now, so their limits are in effect), and of those,
  // the ones whose advert / anon request clock is ahead.
  void countTracking(uint64_t uptime_millis, int& tracking, int& adverts, int& anonreqs) const {
    uint16_t now = (uint16_t)(uptime_millis / 60000);
    tracking = adverts = anonreqs = 0;
    for (int i = 0; i < _count; i++) {
      bool advert = (int16_t)(_records[i].advert_next - now) > 0;
      bool anonreq = (int16_t)(_records[i].anonreq_next - now) > 0;
      if (advert) adverts++;
      if (anonreq) anonreqs++;
      if (advert || anonreq) tracking++;
    }
  }

  // Records a packet from 'pub_key' ('is_advert': advert or anon request clock). Returns true if it's within the
  // sender's allowance (the clock moves forward), false if it's over (nothing changes). limit_burst 0: false.
  // 'uptime_millis' must be 64-bit (32-bit millis() wraps after ~49.7 days).
  bool add(const uint8_t* pub_key, uint64_t uptime_millis, uint16_t limit_recovery_minutes, uint8_t limit_burst,
           bool is_advert) {
    if (limit_burst == 0) return false;   // nothing allowed: don't add the sender
    uint32_t window = (uint32_t)limit_burst * limit_recovery_minutes;
    if (limit_recovery_minutes == 0 || window > SENDER_TRACKING_MAX_WINDOW) return false;

    uint32_t now_minutes = (uint32_t)(uptime_millis / 60000);
    if (now_minutes - _last_recover >= SENDER_TRACKING_RECOVER_MINUTES) recoverAll(now_minutes);
    uint16_t now = (uint16_t)now_minutes;

    uint32_t id = idOf(pub_key);
    SenderRecord* r = nullptr;
    for (int i = 0; i < _count; i++) {
      if (_records[i].id == id) {
        r = &_records[i];
        break;
      }
    }
    if (r == nullptr) {   // new sender
      if (_count < SENDER_TRACKING_SIZE) {
        r = &_records[_count++];
      } else {
        r = leastTimeLeft(now);
      }
      r->id = id;
      r->advert_next = now;
      r->anonreq_next = now;
    }

    uint16_t* next;
    if (is_advert) {
      next = &r->advert_next;
    } else {
      next = &r->anonreq_next;
    }
    if ((int16_t)(*next - now) < 0) *next = now;            // 1. behind now: fully recovered
    uint16_t after = *next + limit_recovery_minutes;          // 2. push forward one timespan
    if ((uint16_t)(after - now) > window) return false;       // 3. too far ahead: over the limit
    *next = after;
    return true;
  }

private:
  // minutes until the sender is fully recovered (the larger of its two clocks' time ahead of now)
  static uint16_t timeLeft(const SenderRecord* r, uint16_t now) {
    int16_t advert_ahead = (int16_t)(r->advert_next - now);
    int16_t anonreq_ahead = (int16_t)(r->anonreq_next - now);
    int16_t left = 0;
    if (advert_ahead > left) left = advert_ahead;
    if (anonreq_ahead > left) left = anonreq_ahead;
    return (uint16_t)left;
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
      if (all || (int16_t)(r->advert_next - now) < 0) r->advert_next = now;
      if (all || (int16_t)(r->anonreq_next - now) < 0) r->anonreq_next = now;
    }
    _last_recover = now_minutes;
  }
};
