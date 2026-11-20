#pragma once

#include <stdint.h>
#include <stdio.h>
#include "RoutePolicy.h"
#include "HopPolicy.h"

// The most recent packets the firewall dropped (FirewallTable::isPacketAllowedForward()), newest first: which rule
// dropped each one, its payload type, hop count, and the key its rule's table used. A ring buffer: the newest entry
// replaces the oldest. RAM only, left out on STM32 (FirewallTable: FIREWALL_LOG_ENABLED). Shown by 'fw log'.

#define FIREWALL_LOG_SIZE          128    // entries kept (12 bytes each, 1.5 KB; at most 255: uint8_t indexes)
#define FIREWALL_LOG_PAGE_ENTRIES  5      // entries per 'fw log<p>' page (the longest 5 fit one reply)
#define FIREWALL_LOG_NO_RULE       0xFF   // FirewallLogEntry::rule: no rule matched, dropped at the end of the list
#define FIREWALL_LOG_OLD_RULE      0xFE   // FirewallLogEntry::rule: the rule was replaced or its slot emptied since

// FirewallLogEntry::table: the table the rule used (as FIREWALL_LOOKUP_*, kept in step by FirewallTable)
#define FIREWALL_LOG_TABLE_NONE      0
#define FIREWALL_LOG_TABLE_ROUTEPOL  1    // key: route policy slot
#define FIREWALL_LOG_TABLE_HOPPOL    2    // key: hop policy entry
#define FIREWALL_LOG_TABLE_SENDTRK   3    // key: adverts, anon requests: the first 4 public key bytes; req, resp,
                                          // txt, path: source hash << 24, then the first repeater's hash (1-3 bytes)
#define FIREWALL_LOG_TABLE_CHANTRK   4    // key: channel hash
#define FIREWALL_LOG_TABLE_PKTTRK    5    // key: ls slot

// One dropped packet, 12 bytes
struct FirewallLogEntry {
  uint32_t uptime_secs;   // when it was dropped, repeater uptime in seconds
  uint32_t key;           // the table's key for the packet (see FIREWALL_LOG_TABLE_*), 0 without a table
  uint8_t  rule;          // firewall slot that dropped it, or FIREWALL_LOG_NO_RULE / FIREWALL_LOG_OLD_RULE
  uint8_t  type;          // payload type (bits 0-3), route type (bits 4-5), path hash size, 1-3 (bits 6-7)
  uint8_t  hops;          // real hop count: repeaters passed, not counting dummy hashes
  uint8_t  table;         // FIREWALL_LOG_TABLE_*

  uint8_t payloadType() const { return type & 0x0F; }
  uint8_t routeType() const { return (type >> 4) & 0x03; }
  uint8_t hashSize() const { return type >> 6; }
};
static_assert(sizeof(FirewallLogEntry) == 12, "firewall log entry must stay 12 bytes");
static_assert(FIREWALL_LOG_SIZE <= 255, "the firewall log keeps its indexes in 8 bits");

class FirewallLog {
  FirewallLogEntry _entries[FIREWALL_LOG_SIZE];   // ring buffer, _newest the latest
  uint8_t  _newest;      // index of the newest entry
  uint8_t  _count;       // entries in use, 0..FIREWALL_LOG_SIZE
  uint32_t _total;       // drops since boot (not reset by clear())
  uint32_t _no_rule;     // of those, drops with no rule matched

public:
  FirewallLog(): _entries(), _newest(FIREWALL_LOG_SIZE - 1), _count(0), _total(0), _no_rule(0) { }

  // Logs a dropped packet. 'payload_type', 'route_type' and 'hash_size' as the packet has them.
  void add(uint64_t uptime_millis, uint8_t rule, uint8_t payload_type, uint8_t route_type, uint8_t hash_size,
           uint8_t hops, uint8_t table, uint32_t key) {
    _newest = (_newest + 1) % FIREWALL_LOG_SIZE;
    if (_count < FIREWALL_LOG_SIZE) _count++;
    FirewallLogEntry& e = _entries[_newest];
    e.uptime_secs = (uint32_t)(uptime_millis / 1000);
    e.key = key;
    e.rule = rule;
    e.type = (payload_type & 0x0F) | ((route_type & 0x03) << 4) | ((hash_size & 0x03) << 6);
    e.hops = hops;
    e.table = table;
    _total++;
    if (rule == FIREWALL_LOG_NO_RULE) _no_rule++;
  }

  // empties the log (the since-boot counts stay)
  void clear() { _count = 0; }

  int getCount() const { return _count; }
  uint32_t getTotal() const { return _total; }
  uint32_t getNoRuleTotal() const { return _no_rule; }

  // entry 'age' (0 = the newest), or nullptr past the oldest
  const FirewallLogEntry* getEntry(int age) const {
    if (age < 0 || age >= _count) return nullptr;
    return &_entries[(_newest - age + FIREWALL_LOG_SIZE) % FIREWALL_LOG_SIZE];
  }

  // A rule was replaced or its slot emptied: its entries are kept, marked as from an old rule.
  void forgetRule(int rule) {
    for (int i = 0; i < _count; i++) {
      FirewallLogEntry& e = _entries[(_newest - i + FIREWALL_LOG_SIZE) % FIREWALL_LOG_SIZE];
      if (e.rule == rule) e.rule = FIREWALL_LOG_OLD_RULE;
    }
  }

  // 'fw insert' / 'fw collapse': entries of rules first..last move with them, by 'delta' slots
  void moveRules(int first, int last, int delta) {
    for (int i = 0; i < _count; i++) {
      FirewallLogEntry& e = _entries[(_newest - i + FIREWALL_LOG_SIZE) % FIREWALL_LOG_SIZE];
      if (e.rule >= first && e.rule <= last) e.rule = (uint8_t)(e.rule + delta);
    }
  }

  // Writes how long ago 'uptime_secs' was, in at most 3 characters: "12s", "40m", "23h", "9d" (99d at most).
  // Returns the length.
  static int formatAge(uint32_t uptime_secs, uint64_t uptime_millis, char* dest) {
    uint32_t now = (uint32_t)(uptime_millis / 1000);
    uint32_t age = now >= uptime_secs ? now - uptime_secs : 0;
    if (age < 60) return sprintf(dest, "%lus", (unsigned long)age);
    if (age < 60UL * 60) return sprintf(dest, "%lum", (unsigned long)(age / 60));
    if (age < 24UL * 60 * 60) return sprintf(dest, "%luh", (unsigned long)(age / (60UL * 60)));
    uint32_t days = age / (24UL * 60 * 60);
    if (days > 99) days = 99;
    return sprintf(dest, "%lud", (unsigned long)days);
  }

  // Writes entry 'e's key: 'labelled' for 'fw log' ("pre a1b2c3d4", "src 3a via 9e", "ch 5e", "ls 0",
  // "route 2 (north)", "hop req"), else the bare value for pages ("a1b2c3d4", "3a/9e", "5e", "0", "2", "req").
  // Nothing without a table. Returns the length.
  static int formatKey(const FirewallLogEntry* e, bool labelled, const RoutePolicy& routes, char* dest) {
    dest[0] = 0;
    switch (e->table) {
      case FIREWALL_LOG_TABLE_SENDTRK:
        if (e->payloadType() == PAYLOAD_TYPE_ADVERT || e->payloadType() == PAYLOAD_TYPE_ANON_REQ) {
          return sprintf(dest, labelled ? "pre %08lx" : "%08lx", (unsigned long)e->key);
        } else {
          int n = sprintf(dest, labelled ? "src %02x" : "%02x", (unsigned)(e->key >> 24));
          if (e->hops == 0) return n;   // heard straight from the sender: no first repeater
          n += sprintf(&dest[n], labelled ? " via " : "/");
          int size = e->hashSize();
          if (size < 1 || size > 3) size = 1;
          for (int i = 0; i < size; i++) n += sprintf(&dest[n], "%02x", (unsigned)((e->key >> (16 - 8 * i)) & 0xFF));
          return n;
        }
      case FIREWALL_LOG_TABLE_CHANTRK:
        return sprintf(dest, labelled ? "ch %02x" : "%02x", (unsigned)(e->key & 0xFF));
      case FIREWALL_LOG_TABLE_PKTTRK:
        return sprintf(dest, labelled ? "ls %lu" : "%lu", (unsigned long)e->key);
      case FIREWALL_LOG_TABLE_ROUTEPOL: {
        if (!labelled) return sprintf(dest, "%lu", (unsigned long)e->key);
        const RoutePolicyEntry* r = routes.getEntry((int)e->key);
        if (r != nullptr && r->name[0] != 0) return sprintf(dest, "route %lu (%s)", (unsigned long)e->key, r->name);
        return sprintf(dest, "route %lu", (unsigned long)e->key);
      }
      case FIREWALL_LOG_TABLE_HOPPOL: {
        const HopPolicyEntry* h = HopPolicy::getEntry((int)e->key);
        const char* name = h != nullptr ? h->name : "?";
        return sprintf(dest, labelled ? "hop %s" : "%s", name);
      }
      default:
        return 0;
    }
  }
};
