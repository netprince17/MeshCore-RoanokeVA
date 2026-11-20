#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "SenderTracking.h"
#include "ChannelTracking.h"
#include "PacketTracking.h"
#include "RoutePolicy.h"
#include "HopPolicy.h"
#include "TableFile.h"
#include "TableCli.h"

// The log of recently dropped packets ('fw log'), left out on STM32 (STM32WL has 64 KB RAM)
#if !defined(STM32_PLATFORM)
  #define FIREWALL_LOG_ENABLED  1
  #include "FirewallLog.h"
  // 'fw log' filters (parseLogFilter()): FIREWALL_LOG_FILTER_ALL, a rule slot, or FIREWALL_LOG_NO_RULE
  #define FIREWALL_LOG_FILTER_ALL     -1
  #define FIREWALL_LOG_FILTER_BAD     -2    // not a filter
  #define FIREWALL_LOG_FILTER_EMPTY   -3    // an empty slot
  #define FIREWALL_LOG_REPLY_MAX      159   // longest 'fw log<p>' reply (the reply buffer holds 160 with the NUL)
#else
  #define FIREWALL_LOG_ENABLED  0
#endif

// Firewall rules: decide which received flood packets are forwarded (MyMesh::allowPacketForward()).
// Loaded at boot from FIREWALL_FILE, or FIREWALL_DEFAULT_RULES if nothing is saved.

#ifndef FIREWALL_MAX_RULES
  #define FIREWALL_MAX_RULES    32
#endif

// FirewallRule::param_set bits: which fields are set (an unset field matches anything). 0 = empty slot.
#define FIREWALL_HAS_PACKET_TYPE           0x01
#define FIREWALL_HAS_HOP_COUNT             0x02
#define FIREWALL_HAS_LIMIT_BURST           0x04
#define FIREWALL_HAS_LIMIT_RECOVERY        0x08
#define FIREWALL_HAS_CHANNEL_HASH          0x10
#define FIREWALL_HAS_ROUTE_BYTES           0x20
#define FIREWALL_HAS_REGION                0x40
#define FIREWALL_HAS_ROUTE_TYPE            0x80
#define FIREWALL_HAS_LIMIT_SLOT            0x0100
#define FIREWALL_HAS_TABLE_LOOKUP          0x0400

// FirewallRule::table_lookup: the one lookup table the packet is checked against (tl:)
#define FIREWALL_LOOKUP_NONE               0
#define FIREWALL_LOOKUP_ROUTE_POLICY       1      // routepol: the packet's path must match one of its routes
#define FIREWALL_LOOKUP_HOP_POLICY         2      // hoppol: the packet must be over a hop limit that applies to it
#define FIREWALL_LOOKUP_SENDER_TRACKING    3      // sendtrk: the sender is over lb / lr (adv, anonreq, req, resp, txt, path)
#define FIREWALL_LOOKUP_CHANNEL_TRACKING   4      // chantrk: the channel (channel messages) is over lb / lr
#define FIREWALL_LOOKUP_PACKET_TRACKING    5      // pkttrk: slot ls (any packet the rule matches) is over lb / lr

// FirewallRule::action: what a rule does with a packet it matches, once all its used checks pass
#define FIREWALL_ACTION_DROP               0
#define FIREWALL_ACTION_FORWARD            1

#define FIREWALL_NAME_LEN  8      // max characters in a rule name

#define FIREWALL_FILE  "/fw_rules_v1"   // saved rules: one "<n> - <config>" line per rule (a new format: _v2)

// CLI (handleCommand())
#define FIREWALL_PAGE_SLOTS    6     // slots per 'fw show<p>' page (more don't fit a reply with large match counts)
#define FIREWALL_SENDER_PAGE_RULES 4 // sendtrk rules per 'fw senders<p>' page
#define FIREWALL_COMMAND_MAX   160   // longest 'fw' command
// rule field keys, in format() order, each followed by a space
#define FIREWALL_FIELD_KEYS    "nm pt hp rb rt ch rg lb lr ls tl ac "
// 'cmds fw' (one reply): x[p] = x<p> a page, plain x serial console only; * = serial console only
#if FIREWALL_LOG_ENABLED
  #define FIREWALL_HELP  "fw [<n> [-] [k:v|k]]|show[p]|counts*|senders[p]|log[p] [n|-]|log csv*|log clear|insert <n>|collapse <n>|clear|setdefault|save|reload|unsave; set fw.enabled 0|1"
#else
  #define FIREWALL_HELP  "fw [<n> [-] [k:v|k]]|show[p]|counts*|senders[p]|insert <n>|collapse <n>|clear|setdefault|save|reload|unsave; set fw.enabled 0|1"
#endif

// Default rules (loadDefaults(), when none are saved, or 'fw setdefault'): set() configs, into slots 0, 1, 2...
// "" leaves its slot empty; nullptr ends the list.
static const char* const FIREWALL_DEFAULT_RULES[] = {
  // check for blocked routes first
  "nm:routepol                        tl:routepol                   ac:drop",

  // drop packets over the hop policy's limits
  "nm:hoppol                          tl:hoppol                     ac:drop",

  // track and restrict advertisements
  "nm:advlm1   pt:adv     hp:0-4      tl:sendtrk       lb:15 lr:30m ac:drop",
  "nm:advlm2   pt:adv     hp:5-8      tl:sendtrk       lb:15 lr:60m ac:drop",
  "nm:advlm3   pt:adv     hp:9-63     tl:sendtrk       lb:1  lr:3d  ac:drop",

  // track and restrict flooded anonymous requests
  "nm:anrqlm1  pt:anonreq hp:0-4      tl:sendtrk       lb:15 lr:30m ac:drop",
  "nm:anrqlm2  pt:anonreq hp:5-8      tl:sendtrk       lb:15 lr:60m ac:drop",

  // track and restrict flooded requests
  "nm:reqlm1   pt:req     hp:0-4      tl:sendtrk       lb:15 lr:30m ac:drop",
  "nm:reqlm2   pt:req     hp:5-8      tl:sendtrk       lb:15 lr:60m ac:drop",

  // track and restrict flooded responses (later maybe, these are sent from room/repeaters)
  //"nm:rsplm1   pt:resp    hp:0-4      tl:sendtrk       lb:15 lr:30m ac:drop",
  //"nm:rsplm2   pt:resp    hp:5-12      tl:sendtrk       lb:15 lr:60m ac:drop",

  // track and restrict flooded txts (later maybe, these are sent from room/repeaters)
  //"nm:txtlm1   pt:txt     hp:0-4      tl:sendtrk       lb:15 lr:30m ac:drop",
  //"nm:txtlm2   pt:txt     hp:5-12      tl:sendtrk       lb:15 lr:60m ac:drop",

  // track and restrict flooded paths (later maybe, these are sent from room/repeaters)
  //"nm:pthlm1   pt:path    hp:0-4      tl:sendtrk       lb:15 lr:30m ac:drop",
  //"nm:pthlm2   pt:path    hp:5-12      tl:sendtrk       lb:15 lr:60m ac:drop",

  // wardriving should be stopped locally
  "nm:wrdrvlm  pt:grptxt  hp:3-63 ch:81                             ac:drop",

  // limit distant messages to each channel, prioritize local messages
  "nm:chanlm1             hp:0-8      tl:chantrk       lb:8  lr:15s ac:fwd",
  "nm:chanlm2             hp:9-63     tl:chantrk       lb:6  lr:15s ac:drop",

  // total cap on distant tracking tables (chantrk and sendtrk can be abused)
  "nm:chandos1 pt:grptxt  hp:9-63     tl:pkttrk        ls:0 lb:10 lr:6s ac:drop",
  "nm:senddos1 pt:adv     hp:9-63     tl:pkttrk        ls:1 lb:8  lr:5s ac:drop",

  // accept remaining traffic
  "nm:acptfld  rt:flood                                             ac:fwd",
  "nm:acpttfld rt:tflood                                            ac:fwd",

  nullptr
};

struct FirewallRule {
  char     name[FIREWALL_NAME_LEN + 1];   // rule name, null-terminated, empty = no name
  uint16_t param_set;              // FIREWALL_HAS_* bits: which fields below are set, 0 = empty slot

  // packet matches
  uint8_t  packet_type;            // PAYLOAD_TYPE_* the rule applies to
  uint8_t  hop_min;                // lowest hop count the rule applies to (hp), 0-63
  uint8_t  route_bytes;            // path hash size the rule applies to: bytes per hop in the path, 1, 2 or 3

  // packet checks
  uint8_t  route_type;             // ROUTE_TYPE_* the packet must have (exact: scoped/un-scoped flood or direct)
  uint8_t  channel_hash;           // channel hash (payload[0] of GRP_TXT / GRP_DATA) the rule applies to
  uint8_t  table_lookup;           // FIREWALL_LOOKUP_*: the lookup table the packet is checked against
  uint8_t  limit_burst;            // packets allowed in a row: per sender, channel or slot (lb)
  uint8_t  limit_slot;             // PacketTracking slot (ls), for tl:pkttrk
  uint32_t limit_recovery;         // seconds per packet earned back after the burst, 1 or more
  uint16_t region_id;              // RegionEntry::id the packet must be in, 0 = '*' (un-scoped flood packets)

  // rule action
  uint8_t  action;                 // FIREWALL_ACTION_DROP or FIREWALL_ACTION_FORWARD
  uint8_t  hop_max;                // highest hop count the rule applies to (hp), hop_min-63

  // packet stats
  uint32_t match_count;            // times this rule has taken action (runtime counter, not a setting)
};
static_assert(sizeof(FirewallRule) == 32, "firewall rule must stay 32 bytes");
static_assert(FIREWALL_MAX_RULES <= 256, "sender tracking keeps rule slots in 8 bits");
#if FIREWALL_LOG_ENABLED
static_assert(FIREWALL_MAX_RULES < FIREWALL_LOG_OLD_RULE, "the firewall log keeps rule slots in 8 bits");
static_assert(FIREWALL_LOG_TABLE_ROUTEPOL == FIREWALL_LOOKUP_ROUTE_POLICY && FIREWALL_LOG_TABLE_HOPPOL == FIREWALL_LOOKUP_HOP_POLICY
              && FIREWALL_LOG_TABLE_SENDTRK == FIREWALL_LOOKUP_SENDER_TRACKING
              && FIREWALL_LOG_TABLE_CHANTRK == FIREWALL_LOOKUP_CHANNEL_TRACKING
              && FIREWALL_LOG_TABLE_PKTTRK == FIREWALL_LOOKUP_PACKET_TRACKING, "firewall log tables must match tl:");
#endif

class FirewallTable : private TableCli {
  FirewallRule _rules[FIREWALL_MAX_RULES];   // rules in slot order, empty slots (param_set 0) anywhere
  SenderTracking _senders;                   // allowances per sender, for rules with FIREWALL_LOOKUP_SENDER_TRACKING
  ChannelTracking _channels;                 // allowances per channel, for rules with FIREWALL_LOOKUP_CHANNEL_TRACKING
  PacketTracking<PACKET_TRACKING_SLOTS> _packets;   // numbered allowances, for rules with FIREWALL_LOOKUP_PACKET_TRACKING
  RoutePolicy _route_policy;                 // repeater routes, for rules with FIREWALL_LOOKUP_ROUTE_POLICY
  HopPolicy _hop_policy;                     // hop limits per packet property, for rules with FIREWALL_LOOKUP_HOP_POLICY
#if FIREWALL_LOG_ENABLED
  FirewallLog _log;                          // recently dropped packets ('fw log')
#endif
  FILESYSTEM* _fs;                          // where the rules are saved, set by begin()
  RegionMap* _regions;                       // the region list, for rg names (rules keep region ids), set by begin()
  bool _unknown_region;                      // set by parseRegion(): the last rg name isn't in the region list
  int _skipped;                              // rules skipped by the last load() (unknown region)
  char _skipped_note[48];                    // the first one skipped, eg. "rule 5: unknown region us-vx"

public:
  FirewallTable(): _rules(), _fs(nullptr), _regions(nullptr), _unknown_region(false), _skipped(0) {
    _skipped_note[0] = 0;
  }   // _rules() zero-fills: every slot starts empty

  // At boot: loads the saved rules, route policy and hop policy, or the defaults of any not saved (or that fail
  // to load, printed in debug builds). 'regions' must already be loaded, for rules with rg names.
  void begin(FILESYSTEM* fs, RegionMap* regions) {
    _fs = fs;
    _regions = regions;
    _route_policy.begin(fs);
    _hop_policy.begin(fs);
    if (fs->exists(FIREWALL_FILE)) {
      const char* err = load();   // falls back to the defaults if it fails
      if (err != nullptr) MESH_DEBUG_PRINTLN("FirewallTable: saved rules not loaded (%s), using the defaults", err);
      if (_skipped > 0) MESH_DEBUG_PRINTLN("FirewallTable: %d saved rules skipped (%s)", _skipped, _skipped_note);
    } else {
      loadDefaults();
    }
  }

  // Saves the rules to FIREWALL_FILE (not the match counts). Returns the number saved, or -1 if it failed.
  int save() {
    if (_fs == nullptr) return -1;
    File file = tableFileOpenWrite(_fs, FIREWALL_FILE);
    if (!file) return -1;
    char line[FIREWALL_COMMAND_MAX];
    int count = 0;
    bool ok = true;
    for (int i = 0; i < FIREWALL_MAX_RULES && ok; i++) {
      if (getRule(i) == nullptr) continue;
      formatLine(i, line);
      ok = tableFileWriteLine(file, line);
      count++;
    }
    file.close();
    if (!ok) return -1;
    return count;
  }

  // Replaces the rules with the saved ones. A rule whose region isn't in the region list is skipped (its slot left
  // empty; counted in _skipped). If the file can't be read or another line fails, loads the defaults instead
  // (nothing changes if nothing is saved). Returns nullptr, or an error message.
  const char* load() {
    static char err[64];
    _skipped = 0;
    _skipped_note[0] = 0;
    if (_fs == nullptr) return "no storage";
    if (!_fs->exists(FIREWALL_FILE)) return "nothing saved";
    File file = tableFileOpenRead(_fs, FIREWALL_FILE);
    if (!file) {
      loadDefaults();
      return "can't open the saved rules";
    }
    clear();

    char line[FIREWALL_COMMAND_MAX + 1];
    int line_number = 0;
    bool too_long;
    const char* fail = nullptr;
    while (tableFileReadLine(file, line, FIREWALL_COMMAND_MAX, too_long)) {
      line_number++;
      if (too_long) {
        fail = "line too long";
        break;
      }
      // "<n> - <config>"
      const char* p = line;
      while (*p == ' ') p++;
      if (*p == 0) continue;   // blank line
      int number = parseSlotNumber(p);
      if (number < 0 || number >= FIREWALL_MAX_RULES) {
        fail = "bad rule number";
        break;
      }
      if (*p == '-' && (p[1] == 0 || p[1] == ' ')) {
        p++;
        while (*p == ' ') p++;
      }
      fail = set(number, true, p);
      if (fail != nullptr && _unknown_region) {   // region gone from the region list: skip this rule only
        if (_skipped == 0) snprintf(_skipped_note, sizeof(_skipped_note), "rule %d: %s", number, fail);
        _skipped++;
        fail = nullptr;
      }
      if (fail != nullptr) break;
    }
    file.close();

    if (fail != nullptr) {
      snprintf(err, sizeof(err), "line %d: %s", line_number, fail);   // before loadDefaults(), which may reuse fail's buffer
      loadDefaults();
      return err;
    }
    return nullptr;
  }

  // the route policy (rules with tl:routepol)
  RoutePolicy* getRoutePolicy() { return &_route_policy; }

  // the hop policy (rules with tl:hoppol)
  HopPolicy* getHopPolicy() { return &_hop_policy; }

  // Checks a flood packet against the rules in slot order. The first rule whose set fields all match decides:
  // returns true for fwd, false for drop (its match_count goes up). No rule decides: false.
  // Expects Packet.h and RegionMap.h to be included first, as MyMesh.h does.

  bool isPacketAllowedForward(const mesh::Packet* packet, const RegionEntry* region, uint64_t uptime_millis) {
    uint8_t packet_type = packet->getPayloadType();
    uint8_t hop_count = realHopCount(packet);
    bool is_channel = (packet_type == PAYLOAD_TYPE_GRP_TXT || packet_type == PAYLOAD_TYPE_GRP_DATA)
                      && packet->payload_len > 0;

    for (int i = 0; i < FIREWALL_MAX_RULES; i++) {
      FirewallRule* r = &_rules[i];

      // empty slot: no rule here
      if (r->param_set == 0) continue;

      // packet matches, does this rule apply to the packet?
      // packet type set: the rule only applies to packets of that type
      if ((r->param_set & FIREWALL_HAS_PACKET_TYPE) && r->packet_type != packet_type) continue;

      // hop count set: the rule only applies to packets whose hop count (repeaters passed) is in the rule's
      // range, hop_min to hop_max
      if ((r->param_set & FIREWALL_HAS_HOP_COUNT) && (hop_count < r->hop_min || hop_count > r->hop_max)) continue;

      // route bytes set: the rule only applies to packets whose path uses that many bytes per hop (1, 2 or 3)
      if ((r->param_set & FIREWALL_HAS_ROUTE_BYTES) && packet->getPathHashSize() != r->route_bytes) continue;

      // packet checks, all of them must pass
      // route type check: the packet must have exactly that ROUTE_TYPE_* (scoped/un-scoped flood or direct)
      if ((r->param_set & FIREWALL_HAS_ROUTE_TYPE) && packet->getRouteType() != r->route_type) continue;

      // channel hash check: the packet must be a channel message on the rule's channel
      if ((r->param_set & FIREWALL_HAS_CHANNEL_HASH) && (!is_channel || packet->payload[0] != r->channel_hash)) continue;

      // region check: the packet must be in the rule's region, or for 0 ('*') be an un-scoped flood packet
      if (r->param_set & FIREWALL_HAS_REGION) {
        if (r->region_id == 0) {
          if (packet->getRouteType() != ROUTE_TYPE_FLOOD) continue;      // '*': un-scoped floods only
        } else {
          if (region == nullptr || region->id != r->region_id) continue;    // must be in the rule's region
        }
      }

      // table lookup check, last (the tracking tables count the packet): the packet must match the rule's table.
      // The tracking tables match a packet over its allowance; one within it is counted and goes on to the next
      // rule. A packet type the table doesn't handle doesn't match. Route / hop entries that matched are counted if
      // the rule acts.
      int route_slot = -1;   // route policy slot that matched
      int hop_entry = -1;    // hop policy entry that matched
      uint8_t log_table = FIREWALL_LOOKUP_NONE;   // the table, and its key for the packet, for the firewall log
      uint32_t log_key = 0;
      if (r->param_set & FIREWALL_HAS_TABLE_LOOKUP) {
        if (r->table_lookup == FIREWALL_LOOKUP_ROUTE_POLICY) {         // the path matches one of its routes
          route_slot = _route_policy.findMatch(packet->path, packet->getPathHashSize(), packet->getPathHashCount());
          if (route_slot < 0) continue;
          log_key = route_slot;
        } else if (r->table_lookup == FIREWALL_LOOKUP_HOP_POLICY) {    // over a hop limit that applies to it
          hop_entry = _hop_policy.findMatch(packet, hop_count);
          if (hop_entry < 0) continue;
          log_key = hop_entry;
        } else if (r->table_lookup == FIREWALL_LOOKUP_SENDER_TRACKING) {   // sender over lb / lr (this rule's clock)
          if (!_senders.isOverLimit(packet, i, uptime_millis, r->limit_recovery, r->limit_burst)) continue;
          log_key = SenderTracking::logKeyOf(packet);
        } else if (r->table_lookup == FIREWALL_LOOKUP_CHANNEL_TRACKING) {  // channel over lb / lr
          if (!_channels.isOverLimit(packet, uptime_millis, r->limit_recovery, r->limit_burst)) continue;
          log_key = packet->payload[0];   // the channel hash (isOverLimit() only matches channel messages)
        } else if (r->table_lookup == FIREWALL_LOOKUP_PACKET_TRACKING) {   // slot ls over lb / lr
          if (!_packets.isOverLimit(r->limit_slot, uptime_millis, r->limit_recovery, r->limit_burst)) continue;
          log_key = r->limit_slot;
        } else {
          continue;   // unknown table
        }
        log_table = r->table_lookup;
      }

      // all used checks passed: this rule decides, using its action
      r->match_count++;
      if (route_slot >= 0) _route_policy.addMatch(route_slot);
      if (hop_entry >= 0) _hop_policy.addMatch(hop_entry);
#if FIREWALL_LOG_ENABLED
      if (r->action != FIREWALL_ACTION_FORWARD) {
        _log.add(uptime_millis, i, packet_type, packet->getRouteType(), packet->getPathHashSize(), hop_count,
                 log_table, log_key);
      }
#endif
      return r->action == FIREWALL_ACTION_FORWARD;
    }
#if FIREWALL_LOG_ENABLED
    _log.add(uptime_millis, FIREWALL_LOG_NO_RULE, packet_type, packet->getRouteType(), packet->getPathHashSize(),
             hop_count, FIREWALL_LOOKUP_NONE, 0);
#endif
    return false;   // no rule decided: drop
  }

  // Sets rule 'number' from 'config', "key:value" fields (key:- unsets). reset: start from an empty slot (and
  // match_count 0), otherwise only the fields named change. An empty config with reset empties the slot.
  // A rule needs a match/check field, and a new rule needs ac. lb / lr go with tl:sendtrk, chantrk or pkttrk
  // (both needed, and ls for pkttrk; lb x lr at most 32767 minutes for sendtrk). All or nothing. Returns nullptr,
  // or an error message. Keys and values:
  //   nm:<name, 8>  pt:<type name|0-15>  hp:<N|A-B|<N|>N>  rb:<1-3>  rt:<tflood|flood|direct|tdirect|0-3>
  //   ch:<hex>  rg:<region name|*>  lb:<0-255>  lr:<N minutes | Ns | Nm | Nh | Nd>
  //   tl:<routepol|hoppol|sendtrk|chantrk|pkttrk>  ls:<0-15>  ac:<drop|fwd>
  const char* set(int number, bool reset, const char* config) {
    _unknown_region = false;   // set by parseRegion() if the rg name isn't in the region list
    if (number < 0 || number >= FIREWALL_MAX_RULES) return "bad rule number";

    FirewallRule r;   // parsed into a copy, written to the slot only if all fields are valid
    if (reset) {
      r = FirewallRule();
    } else {
      r = _rules[number];
    }
    bool from_empty = (r.param_set == 0);   // a new rule: it needs ac, there's no default action
    bool any_field = false;
    bool has_action = false;

    const char* p = config;
    while (true) {
      while (*p == ' ') p++;   // skip spaces between fields
      if (*p == 0) break;

      // one field: "xx:value"
      const char* field = p;
      while (*p != 0 && *p != ' ') p++;
      int field_len = p - field;
      if (field_len < 4 || field[2] != ':') return "bad field, use xx:value";
      const char* v = field + 3;   // the value
      int v_len = field_len - 3;
      bool unset = (v_len == 1 && v[0] == '-');
      uint32_t n;
      any_field = true;

      if (isKey(field, "nm")) {          // name
        if (unset) {
          r.name[0] = 0;
        } else {
          if (v_len > FIREWALL_NAME_LEN) return "bad nm value, up to 8 characters";
          for (int i = 0; i < v_len; i++) r.name[i] = v[i];
          r.name[v_len] = 0;
        }

      } else if (isKey(field, "pt")) {   // packet type
        if (unset) {
          r.param_set &= ~FIREWALL_HAS_PACKET_TYPE;
        } else {
          if (!parsePacketType(v, v_len, r.packet_type)) return "bad pt value, name or 0-15";
          r.param_set |= FIREWALL_HAS_PACKET_TYPE;
        }

      } else if (isKey(field, "hp")) {   // hop count: N exactly, A-B from A to B, <N less than, >N greater than
        if (unset) {
          r.param_set &= ~FIREWALL_HAS_HOP_COUNT;
        } else {
          // a path holds at most 63 hops: 64 is taken as 63 at the top of a range
          const char* hp_err = "bad hp value, 0-63, A-B (B up to 64), <1-63 or >0-62";
          const char* dash = (const char*)memchr(v, '-', v_len);
          uint32_t lo, hi;
          if (v[0] == '<') {
            if (!parseDecimal(v + 1, v_len - 1, 63, hi) || hi < 1) return hp_err;   // <0 would never match
            lo = 0;
            hi -= 1;
          } else if (v[0] == '>') {
            if (!parseDecimal(v + 1, v_len - 1, 62, lo)) return hp_err;            // >63 would never match
            lo += 1;
            hi = 63;
          } else if (dash != nullptr) {
            int lo_len = dash - v;
            if (!parseDecimal(v, lo_len, 63, lo) || !parseDecimal(dash + 1, v_len - lo_len - 1, 64, hi))
              return hp_err;
            if (hi > 63) hi = 63;
            if (lo > hi) return hp_err;
          } else {
            if (!parseDecimal(v, v_len, 63, lo)) return hp_err;
            hi = lo;
          }
          r.hop_min = lo;
          r.hop_max = hi;
          r.param_set |= FIREWALL_HAS_HOP_COUNT;
        }

      } else if (isKey(field, "rb")) {   // route bytes per hop
        if (unset) {
          r.param_set &= ~FIREWALL_HAS_ROUTE_BYTES;
        } else {
          if (!parseDecimal(v, v_len, 3, n) || n < 1) return "bad rb value, 1-3";
          r.route_bytes = n;
          r.param_set |= FIREWALL_HAS_ROUTE_BYTES;
        }

      } else if (isKey(field, "rt")) {   // route type
        if (unset) {
          r.param_set &= ~FIREWALL_HAS_ROUTE_TYPE;
        } else {
          if (!parseRouteType(v, v_len, r.route_type)) return "bad rt value, tflood, flood, direct, tdirect or 0-3";
          r.param_set |= FIREWALL_HAS_ROUTE_TYPE;
        }

      } else if (isKey(field, "ch")) {   // channel hash
        if (unset) {
          r.param_set &= ~FIREWALL_HAS_CHANNEL_HASH;
        } else {
          if (!parseHexByte(v, v_len, r.channel_hash)) return "bad ch value, hex 00-ff";
          r.param_set |= FIREWALL_HAS_CHANNEL_HASH;
        }

      } else if (isKey(field, "rg")) {   // region name ('*' = un-scoped), kept as the region's id
        if (unset) {
          r.param_set &= ~FIREWALL_HAS_REGION;
        } else {
          const char* err = parseRegion(v, v_len, r.region_id);
          if (err != nullptr) return err;
          r.param_set |= FIREWALL_HAS_REGION;
        }

      } else if (isKey(field, "lb")) {   // limit burst: packets allowed in a row
        if (unset) {
          r.param_set &= ~FIREWALL_HAS_LIMIT_BURST;
        } else {
          if (!parseDecimal(v, v_len, 255, n)) return "bad lb value, 0-255";
          r.limit_burst = n;
          r.param_set |= FIREWALL_HAS_LIMIT_BURST;
        }

      } else if (isKey(field, "ls")) {   // limit slot, for tl:pkttrk
        if (unset) {
          r.param_set &= ~FIREWALL_HAS_LIMIT_SLOT;
        } else {
          if (!parseDecimal(v, v_len, PACKET_TRACKING_SLOTS - 1, n)) return "bad ls value, 0-15";
          r.limit_slot = n;
          r.param_set |= FIREWALL_HAS_LIMIT_SLOT;
        }

      } else if (isKey(field, "lr")) {   // limit recovery: time per packet earned back (minutes, or with s/m/h/d)
        if (unset) {
          r.param_set &= ~FIREWALL_HAS_LIMIT_RECOVERY;
        } else {
          if (!parseRecovery(v, v_len, r.limit_recovery)) return "bad lr value, eg. 30s, 240 (minutes), 4h or 2d";
          r.param_set |= FIREWALL_HAS_LIMIT_RECOVERY;
        }

      } else if (isKey(field, "ac")) {   // action
        if (isWord(v, v_len, "drop")) {
          r.action = FIREWALL_ACTION_DROP;
        } else if (isWord(v, v_len, "fwd")) {
          r.action = FIREWALL_ACTION_FORWARD;
        } else {
          return "bad ac value, drop or fwd";
        }
        has_action = true;

      } else if (isKey(field, "tl")) {   // table lookup
        if (unset) {
          r.table_lookup = FIREWALL_LOOKUP_NONE;
          r.param_set &= ~FIREWALL_HAS_TABLE_LOOKUP;
        } else {
          if (!parseTableLookup(v, v_len, r.table_lookup)) return "bad tl value, routepol, hoppol, sendtrk, chantrk or pkttrk";
          r.param_set |= FIREWALL_HAS_TABLE_LOOKUP;
        }

      } else {
        return unknownField(field);
      }
    }

    // the whole rule: checked here, as fields can be set in different calls
    if (r.param_set == 0) {
      if (any_field) return "rule needs a match or check field";   // eg. only nm / ac
      _rules[number] = FirewallRule();   // empty config: empty slot
      _senders.forgetRule(number);
#if FIREWALL_LOG_ENABLED
      _log.forgetRule(number);           // its log entries are kept, as from an old rule
#endif
      return nullptr;
    }
    if (from_empty && !has_action) return "ac needed, drop or fwd";

    // limit: checked on the whole rule, as tl, lb, lr and ls can be set in different calls. lb / lr go with a
    // tracking table, ls with pkttrk. sendtrk's 16-bit clocks count minutes, so its window is limited.
    bool tracking = (r.param_set & FIREWALL_HAS_TABLE_LOOKUP)
                    && (r.table_lookup == FIREWALL_LOOKUP_SENDER_TRACKING || r.table_lookup == FIREWALL_LOOKUP_CHANNEL_TRACKING
                        || r.table_lookup == FIREWALL_LOOKUP_PACKET_TRACKING);
    bool packet_tracking = tracking && r.table_lookup == FIREWALL_LOOKUP_PACKET_TRACKING;
    bool has_limit = (r.param_set & FIREWALL_HAS_LIMIT_BURST) && (r.param_set & FIREWALL_HAS_LIMIT_RECOVERY);
    if (tracking && !has_limit) return "tl:sendtrk / chantrk / pkttrk need lb and lr";
    if (!tracking && (r.param_set & (FIREWALL_HAS_LIMIT_BURST | FIREWALL_HAS_LIMIT_RECOVERY))) {
      return "lb / lr need tl:sendtrk, chantrk or pkttrk";
    }
    if (packet_tracking && !(r.param_set & FIREWALL_HAS_LIMIT_SLOT)) return "tl:pkttrk needs ls";
    if (!packet_tracking && (r.param_set & FIREWALL_HAS_LIMIT_SLOT)) return "ls needs tl:pkttrk";
    if (tracking && r.table_lookup == FIREWALL_LOOKUP_SENDER_TRACKING
        && (uint32_t)r.limit_burst * ((r.limit_recovery + 59) / 60) > SENDER_TRACKING_MAX_WINDOW) {
      static char err[64];
      int n = sprintf(err, "lr too long, for lb:%d the longest is lr:", r.limit_burst);
      formatRecovery((uint32_t)(SENDER_TRACKING_MAX_WINDOW / r.limit_burst) * 60, &err[n]);
      return err;
    }

    if (reset) {   // a new rule: its sender clocks start over (field edits keep them)
      r.match_count = 0;
      _senders.forgetRule(number);
#if FIREWALL_LOG_ENABLED
      _log.forgetRule(number);   // the old rule's log entries aren't the new rule's drops
#endif
    }
    _rules[number] = r;
    return nullptr;
  }

  // Replaces all rules with FIREWALL_DEFAULT_RULES. A default rule that fails to parse is left empty (debug builds
  // print why).
  void loadDefaults() {
    clear();
    for (int i = 0; i < FIREWALL_MAX_RULES && FIREWALL_DEFAULT_RULES[i] != nullptr; i++) {
      const char* err = set(i, true, FIREWALL_DEFAULT_RULES[i]);
      if (err != nullptr) MESH_DEBUG_PRINTLN("FirewallTable: default rule %d: %s, left empty", i, err);
    }
  }

  // empties every slot (and forgets every sender clock, and empties the firewall log)
  void clear() {
    for (int i = 0; i < FIREWALL_MAX_RULES; i++) _rules[i] = FirewallRule();
    _senders.clear();
#if FIREWALL_LOG_ENABLED
    _log.clear();
#endif
  }

  // number of slots holding a rule
  int getCount() const {
    int n = 0;
    for (int i = 0; i < FIREWALL_MAX_RULES; i++) {
      if (_rules[i].param_set != 0) n++;
    }
    return n;
  }

  // the rule in slot 'number' (0..FIREWALL_MAX_RULES-1), or nullptr if the slot is empty or out of range
  const FirewallRule* getRule(int number) const {
    if (number < 0 || number >= FIREWALL_MAX_RULES) return nullptr;
    if (_rules[number].param_set == 0) return nullptr;
    return &_rules[number];
  }

  // Repeaters the packet has really passed: its path hashes, less any dummy 3-byte 000000 hashes at the start (a
  // sender can pre-fill the path with them so the packet is relayed only a few times, as reports do).
  static uint8_t realHopCount(const mesh::Packet* packet) {
    uint8_t count = packet->getPathHashCount();
    if (packet->getPathHashSize() != 3) return count;
    uint8_t dummy = 0;
    while (dummy < count) {
      const uint8_t* h = &packet->path[dummy * 3];
      if (h[0] != 0 || h[1] != 0 || h[2] != 0) break;
      dummy++;
    }
    return count - dummy;
  }

  // set() name of a PAYLOAD_TYPE_* value, or "" if it has none (use the number)
  static const char* packetTypeName(uint8_t type) {
    // names, indexed by PAYLOAD_TYPE_* value ("" = unused type)
    static const char* names[16] = { "req", "resp", "txt", "ack", "adv", "grptxt", "grpdata", "anonreq",
                                     "path", "trace", "multi", "ctrl", "", "", "", "raw" };
    if (type >= 16) return "";
    return names[type];
  }

  // set() name of a ROUTE_TYPE_* value, or "" if it has none (use the number)
  static const char* routeTypeName(uint8_t type) {
    static const char* names[4] = { "tflood", "flood", "direct", "tdirect" };   // indexed by ROUTE_TYPE_* value
    if (type >= 4) return "";
    return names[type];
  }

  // Writes the value of field 'key' of rule 'r', as set() takes it. Returns the length, or -1 if it isn't set.
  int formatField(const FirewallRule* r, const char* key, char* dest) const {
    if (isKey(key, "nm")) {
      if (r->name[0] == 0) return -1;
      return sprintf(dest, "%s", r->name);
    }
    if (isKey(key, "pt")) {
      if (!(r->param_set & FIREWALL_HAS_PACKET_TYPE)) return -1;
      const char* name = packetTypeName(r->packet_type);
      if (name[0] != 0) return sprintf(dest, "%s", name);
      return sprintf(dest, "%d", r->packet_type);
    }
    if (isKey(key, "hp")) {   // N, or a range A-B
      if (!(r->param_set & FIREWALL_HAS_HOP_COUNT)) return -1;
      if (r->hop_min == r->hop_max) return sprintf(dest, "%d", r->hop_min);
      return sprintf(dest, "%d-%d", r->hop_min, r->hop_max);
    }
    if (isKey(key, "rb")) {
      if (!(r->param_set & FIREWALL_HAS_ROUTE_BYTES)) return -1;
      return sprintf(dest, "%d", r->route_bytes);
    }
    if (isKey(key, "rt")) {
      if (!(r->param_set & FIREWALL_HAS_ROUTE_TYPE)) return -1;
      return sprintf(dest, "%s", routeTypeName(r->route_type));
    }
    if (isKey(key, "ch")) {
      if (!(r->param_set & FIREWALL_HAS_CHANNEL_HASH)) return -1;
      return sprintf(dest, "%02x", r->channel_hash);
    }
    if (isKey(key, "rg")) {   // the region's name ("#<id>?" if it's no longer in the region list)
      if (!(r->param_set & FIREWALL_HAS_REGION)) return -1;
      if (r->region_id == 0) return sprintf(dest, "*");
      RegionEntry* region = nullptr;
      if (_regions != nullptr) region = _regions->findById(r->region_id);
      if (region == nullptr) return sprintf(dest, "#%d?", r->region_id);
      return sprintf(dest, "%s", region->name);
    }
    if (isKey(key, "lb")) {
      if (!(r->param_set & FIREWALL_HAS_LIMIT_BURST)) return -1;
      return sprintf(dest, "%d", r->limit_burst);
    }
    if (isKey(key, "ls")) {
      if (!(r->param_set & FIREWALL_HAS_LIMIT_SLOT)) return -1;
      return sprintf(dest, "%d", r->limit_slot);
    }
    if (isKey(key, "lr")) {
      if (!(r->param_set & FIREWALL_HAS_LIMIT_RECOVERY)) return -1;
      return formatRecovery(r->limit_recovery, dest);
    }
    if (isKey(key, "tl")) {
      if (!(r->param_set & FIREWALL_HAS_TABLE_LOOKUP)) return -1;
      const char* name = tableLookupName(r->table_lookup);
      if (name[0] == 0) return sprintf(dest, "%d", r->table_lookup);
      return sprintf(dest, "%s", name);
    }
    if (isKey(key, "ac")) {
      if (r->action == FIREWALL_ACTION_FORWARD) return sprintf(dest, "fwd");
      return sprintf(dest, "drop");
    }
    return -1;
  }

  // Writes rule 'number' as set() config (up to ~120 characters). Returns the length, 0 if the slot is empty.
  int format(int number, char* dest) const {
    dest[0] = 0;
    const FirewallRule* r = getRule(number);
    if (r == nullptr) return 0;

    int n = 0;
    for (const char* key = FIREWALL_FIELD_KEYS; *key != 0; key += 3) {
      int start = n;
      if (n > 0) dest[n++] = ' ';
      n += sprintf(&dest[n], "%.2s:", key);
      int len = formatField(r, key, &dest[n]);
      if (len < 0) {
        n = start;   // field not set: take its key back out
        dest[n] = 0;
      } else {
        n += len;
      }
    }
    return n;
  }

  // Writes every rule as a command that recreates it ("fw <n> - <config>"), one per line, after a
  // "set fw.enabled" line. For the serial console ('fw show'): too long for one reply.
  void printAll(Print& out, bool enabled) const {
    if (enabled) {
      out.print("set fw.enabled 1\n");
    } else {
      out.print("set fw.enabled 0\n");
    }
    char line[FIREWALL_COMMAND_MAX + 8];
    for (int i = 0; i < FIREWALL_MAX_RULES; i++) {
      if (getRule(i) == nullptr) continue;
      formatLine(i, line);   // "<n> - <config>", as in the saved file
      out.print("fw ");
      out.print(line);
      out.print("\n");
    }
  }

  // Every rule's match count, for the serial console ('fw counts'): too long for one reply. "firewall on" / "off",
  // then a header and one "slot name action matches" line per rule.
  void printCounts(Print& out, bool enabled) const {
    out.print(enabled ? "firewall on\n" : "firewall off\n");
    char line[64];
    sprintf(line, "%-11s %-4s %10s\n", "rule", "ac", "matches");
    out.print(line);
    int rules = 0;
    for (int i = 0; i < FIREWALL_MAX_RULES; i++) {
      const FirewallRule* r = getRule(i);
      if (r == nullptr) continue;
      const char* name = r->name;
      if (name[0] == 0) name = "?";
      sprintf(line, "%2d %-8s %-4s %10lu\n", i, name, r->action == FIREWALL_ACTION_FORWARD ? "fwd" : "drop",
              (unsigned long)r->match_count);
      out.print(line);
      rules++;
    }
    if (rules == 0) out.print("no rules\n");
  }

  // The sender tracking table, every sendtrk rule, for the serial console ('fw senders'): too long for one reply.
  //   senders: <tracked> tracked, <in use>/<size> records, <n> replaced since boot
  //   one line per sendtrk rule: slot, name, tracked, maxed (its next packet would be dropped), dropped (the
  //   rule's match count), window (lb x lr)
  //   left over from old rules: <n>   (clocks of slots that no longer hold a sendtrk rule)
  // tracked: clocks still in effect. replaced: records whose limits were lost early, as the table was full.
  void printSenders(Print& out, uint64_t uptime_millis) {
    int tracked[FIREWALL_MAX_RULES];
    int maxed[FIREWALL_MAX_RULES];
    int total, left_over;
    countSenders(uptime_millis, tracked, maxed, total, left_over);

    char line[100];
    sprintf(line, "senders: %d tracked, %d/%d records, %lu replaced since boot\n", total, _senders.getCount(),
            SENDER_TRACKING_SIZE, (unsigned long)_senders.getReplaced());
    out.print(line);
    sprintf(line, "%-11s %8s %9s %9s  %s\n", "# rule", "tracked", "maxed", "dropped", "window");
    out.print(line);
    int rules = 0;
    for (int i = 0; i < FIREWALL_MAX_RULES; i++) {
      const FirewallRule* r = getRule(i);
      if (r == nullptr || !isSenderTracking(r)) continue;
      const char* name = r->name;
      if (name[0] == 0) name = "?";
      char window[16];
      formatWindow(senderWindowMinutes(r), window);
      // dropped: the rule's match count (an ac:fwd rule forwards those packets instead: marked "fwd")
      sprintf(line, "%2d %-8s %8d %9d %9lu  %s%s\n", i, name, tracked[i], maxed[i], (unsigned long)r->match_count,
              window, r->action == FIREWALL_ACTION_FORWARD ? "  (fwd: forwarded, not dropped)" : "");
      out.print(line);
      rules++;
    }
    if (rules == 0) out.print("no sendtrk rules\n");
    sprintf(line, "left over from old rules: %d\n", left_over);
    out.print(line);
  }

#if FIREWALL_LOG_ENABLED
  // 'fw log' / 'fw log <n>' / 'fw log -' for the serial console: too long for one reply. 'command' is the text
  // after "fw". Prints the count since boot and the entries logged, then every logged drop (of rule n, or with no
  // rule matched), newest first:
  //   age, rule (slot and name, "- (none)": no rule matched, "- (old)": a rule since replaced), payload type,
  //   route type, hop count, the key of the rule's table ("pre a1b2c3d4", "src 3a via 9e", "ch 5e", "ls 0",
  //   "route 2 (north)", "hop req")
  // A filtered log leaves out the rule column. 'fw log csv [<n>|-]': the same drops as CSV (printLogCsv()).
  // Returns false (nothing printed) if 'command' isn't one of these, for handleCommand() to reply to.
  bool printLog(Print& out, const char* command, uint64_t uptime_millis) {
    while (*command == ' ') command++;
    if (memcmp(command, "log", 3) != 0 || (command[3] != 0 && command[3] != ' ')) return false;
    const char* p = &command[3];
    while (*p == ' ') p++;
    if (strcmp(p, "clear") == 0) return false;
    bool csv = isCommand(p, "csv");
    if (csv) p += 3;
    int filter = parseLogFilter(p);
    if (filter < FIREWALL_LOG_FILTER_ALL) return false;
    if (csv) {
      printLogCsv(out, filter, uptime_millis);
      return true;
    }

    char line[96];
    int logged = 0;
    for (int age = 0; age < _log.getCount(); age++) {
      if (logMatches(_log.getEntry(age), filter)) logged++;
    }
    int n = formatLogTotal(filter, line);
    sprintf(&line[n], " since boot, %d logged\n", logged);
    out.print(line);
    if (logged == 0) return true;
    if (filter == FIREWALL_LOG_FILTER_ALL) {
      sprintf(line, "%-5s %-12s %-8s %-7s %4s  %s\n", "# age", "rule", "type", "route", "hops", "key");
    } else {
      sprintf(line, "%-5s %-8s %-7s %4s  %s\n", "# age", "type", "route", "hops", "key");
    }
    out.print(line);

    for (int age = 0; age < _log.getCount(); age++) {
      const FirewallLogEntry* e = _log.getEntry(age);
      if (!logMatches(e, filter)) continue;
      char when[8], type[8], key[32];
      FirewallLog::formatAge(e->uptime_secs, uptime_millis, when);
      formatLogType(e, type);
      FirewallLog::formatKey(e, true, _route_policy, key);
      const char* route = routeTypeName(e->routeType());
      if (filter == FIREWALL_LOG_FILTER_ALL) {
        char slot[4];
        const char* name;
        if (e->rule == FIREWALL_LOG_NO_RULE) {
          strcpy(slot, "-");
          name = "(none)";
        } else if (e->rule == FIREWALL_LOG_OLD_RULE) {
          strcpy(slot, "-");
          name = "(old)";
        } else {
          sprintf(slot, "%d", e->rule);
          const FirewallRule* r = getRule(e->rule);
          name = (r != nullptr && r->name[0] != 0) ? r->name : "?";
        }
        sprintf(line, "%5s %2s %-9s %-8s %-7s %4d  %s\n", when, slot, name, type, route, e->hops, key);
      } else {
        sprintf(line, "%5s %-8s %-7s %4d  %s\n", when, type, route, e->hops, key);
      }
      out.print(line);
    }
    return true;
  }
#endif

  // CLI 'fw' ('command' is the text after "fw"). Replies, except show pages, can be pasted back as commands.
  // 'enabled': the fw.enabled setting, shown by the slot list and show pages.
  //   fw                     slots in use, eg. "0,1,2" (then " (firewall off)" if it's off)
  //   fw show                every rule, serial console only: handled by MyMesh (printAll())
  //   fw show<p>             page p of FIREWALL_PAGE_SLOTS slots: "firewall on" / "firewall off", then
  //                          "slot name match_count" lines
  //   fw <n>                 rule n, eg. "nm:advlm1 pt:adv ac:fwd", "-" if empty (the same as 'fw <n> show')
  //   fw <n> <words>         key:value sets a field, key shows it, show the whole rule, - clears the slot
  //                          first. All or nothing. Replies the shown values, or "OK".
  //   fw insert <n>          opens slot n, moving rules down to the next empty slot
  //   fw collapse <n>        removes empty slot n, moving all later slots up
  //   fw clear | setdefault | save | reload   (setdefault isn't saved until 'fw save')
  //   fw unsave              removes the saved rules (the current ones stay): the defaults load at boot
  //   fw senders             the whole sender tracking table, serial console only: handled by MyMesh (printSenders())
  //   fw senders<p>          page p of the sender tracking table (tl:sendtrk): senders still tracked (limits in
  //                          effect), then "slot name tracked/maxed (dropped)" per sendtrk rule, maxed: senders whose
  //                          next packet would be dropped, dropped: the rule's match count. 'uptime_millis': now.
  //   fw log [<n>|-]         the firewall log, serial console only: handled by MyMesh (printLog())
  //   fw log<p> [<n>|-]      page p of FIREWALL_LOG_PAGE_ENTRIES logged drops, newest first (of rule n, or with no
  //                          rule matched): "drops: <since boot>" (or "rule <n> <name>: <its drops> drops", "no
  //                          rule: <n> drops"), then "<age> <slot> <type> <hops> <key>" lines (no slot when
  //                          filtered), the key without its label (see formatLogPage())
  //   fw log csv [<n>|-]     the firewall log as CSV, serial console only: handled by MyMesh (printLogCsv())
  //   fw log clear           empties the log (the counts since boot stay)
  void handleCommand(const char* command, char* reply, bool enabled, uint64_t uptime_millis) {
    while (*command == ' ') command++;

    if (*command == 0) {   // the slots in use
      int n = 0;
      for (int i = 0; i < FIREWALL_MAX_RULES; i++) {
        if (getRule(i) == nullptr) continue;
        n = addSlotToList(reply, n, i);
      }
      if (n == 0) n = sprintf(reply, "none");
      if (!enabled) strcpy(&reply[n], " (firewall off)");

    } else if (strcmp(command, "clear") == 0) {
      clear();
      strcpy(reply, "OK - all rules cleared, no flood-routed packets are forwarded");

    } else if (isCommand(command, "insert") || isCommand(command, "collapse")) {
      bool insert = command[0] == 'i';
      const char* p = command;
      while (*p != 0 && *p != ' ') p++;   // skip the command word
      while (*p == ' ') p++;
      int number = parseSlotNumber(p);
      if (number < 0 || number >= FIREWALL_MAX_RULES || *p != 0) {
        if (insert) {
          sprintf(reply, "Err - use: fw insert <0-%d>", FIREWALL_MAX_RULES - 1);
        } else {
          sprintf(reply, "Err - use: fw collapse <0-%d>", FIREWALL_MAX_RULES - 1);
        }
        return;
      }
      if (insert) {
        insertSlot(number, reply);
      } else {
        collapseSlot(number, reply);
      }

    } else if (strcmp(command, "setdefault") == 0) {
      loadDefaults();
      sprintf(reply, "OK - %d default rules loaded, not saved", getCount());

    } else if (strcmp(command, "save") == 0) {
      int count = save();
      if (count < 0) {
        strcpy(reply, "Err - save failed");
      } else {
        sprintf(reply, "OK - %d rules saved", count);
      }

    } else if (strcmp(command, "reload") == 0) {
      if (_fs == nullptr || !_fs->exists(FIREWALL_FILE)) {
        strcpy(reply, "Err - nothing saved, nothing changed");
        return;
      }
      const char* err = load();
      if (err != nullptr) {
        sprintf(reply, "Err - %s, defaults loaded (not saved)", err);
      } else {
        int n = sprintf(reply, "OK - %d rules loaded", getCount());
        if (_skipped > 0) sprintf(&reply[n], ", %d skipped (%s)", _skipped, _skipped_note);
      }

    } else if (memcmp(command, "senders", 7) == 0) {   // the sender tracking table, per sendtrk rule
      const char* p = &command[7];
      if (*p == 0) {   // the whole table: serial console only, printed by MyMesh
        strcpy(reply, "Err - fw senders: serial console only, use fw senders<p>");
        return;
      }
      int page = parseSlotNumber(p);
      if (page < 1 || *p != 0) {
        strcpy(reply, "Err - use: fw senders<p>");
        return;
      }
      formatSenders(page, uptime_millis, reply);

    } else if (memcmp(command, "log", 3) == 0) {   // the firewall log: recently dropped packets
#if FIREWALL_LOG_ENABLED
      handleLogCommand(&command[3], reply, uptime_millis);
#else
      strcpy(reply, "Err - no firewall log in this build");
#endif

    } else if (strcmp(command, "unsave") == 0) {   // remove the saved rules, so the defaults load at boot
      if (_fs == nullptr || !_fs->exists(FIREWALL_FILE)) {
        strcpy(reply, "OK - nothing saved");
      } else if (!_fs->remove(FIREWALL_FILE)) {
        strcpy(reply, "Err - remove failed");
      } else {
        strcpy(reply, "OK - saved rules removed, defaults load at boot (or fw setdefault)");
      }

    } else if (memcmp(command, "show", 4) == 0) {   // a page of slots
      const char* p = &command[4];
      int page = parseSlotNumber(p);
      int first = (page - 1) * FIREWALL_PAGE_SLOTS;
      if (page < 1 || first >= FIREWALL_MAX_RULES || *p != 0) {
        sprintf(reply, "Err - use: fw show<1-%d>", (FIREWALL_MAX_RULES + FIREWALL_PAGE_SLOTS - 1) / FIREWALL_PAGE_SLOTS);
        return;
      }
      // "firewall on" / "off", then one line per rule: slot, name, match count (the first line keeps the rules
      // left-aligned in clients that put a prompt before it)
      int n;
      if (enabled) {
        n = sprintf(reply, "firewall on");
      } else {
        n = sprintf(reply, "firewall off");
      }
      int more = 0;
      int shown = 0;
      for (int i = first; i < first + FIREWALL_PAGE_SLOTS && i < FIREWALL_MAX_RULES; i++) {
        const FirewallRule* r = getRule(i);
        if (r == nullptr) continue;
        const char* name = r->name;
        if (name[0] == 0) name = "?";
        char item[32];
        int len = sprintf(item, "%d %s %lu", i, name, (unsigned long)r->match_count);
        n = addLine(reply, n, item, len, more);
        shown++;
      }
      if (shown == 0 && more == 0) {   // the page's slot range, eg. "no rules 6-11"
        int last = first + FIREWALL_PAGE_SLOTS - 1;
        if (last >= FIREWALL_MAX_RULES) last = FIREWALL_MAX_RULES - 1;
        sprintf(reply, "no rules %d-%d", first, last);
      } else if (more > 0) {
        sprintf(&reply[n], "\n+%d more", more);
      }
      // "..." on its own line: a later page has rules
      for (int i = first + FIREWALL_PAGE_SLOTS; i < FIREWALL_MAX_RULES; i++) {
        if (getRule(i) != nullptr) {
          strcat(reply, "\n...");
          break;
        }
      }

    } else {   // one slot
      const char* p = command;
      int number = parseSlotNumber(p);
      if (number < 0 || number >= FIREWALL_MAX_RULES) {
        sprintf(reply, "Err - use: fw [<0-%d> [-] [key:value|key ...]]|show<p>|insert <n>|collapse <n>|clear|setdefault|save|reload|unsave|senders<p>|log<p>",
                FIREWALL_MAX_RULES - 1);
        return;
      }

      if (*p == 0) {   // no words: the whole rule
        formatRule(number, reply);
        return;
      }

      // check every word, and gather the sets into one set() config
      char config[FIREWALL_COMMAND_MAX + 1];
      int config_len = 0;
      bool reset = false;
      bool any_show = false;
      const char* q = p;
      while (true) {
        while (*q == ' ') q++;
        if (*q == 0) break;
        const char* word = q;
        while (*q != 0 && *q != ' ') q++;
        int len = q - word;

        if (len == 1 && word[0] == '-') {   // clear the slot first
          reset = true;
        } else if (len == 4 && memcmp(word, "show", 4) == 0) {   // show the whole rule
          any_show = true;
        } else if (memchr(word, ':', len) != nullptr) {   // a set: checked by set()
          if (config_len + len + 1 > FIREWALL_COMMAND_MAX) {
            strcpy(reply, "Err - command too long");
            return;
          }
          memcpy(&config[config_len], word, len);
          config_len += len;
          config[config_len++] = ' ';
        } else if (len == 2 && isFieldKey(word)) {   // a show: a field key
          any_show = true;
        } else {
          if (len > 12) len = 12;
          sprintf(reply, "Err - unknown field %.*s", len, word);
          return;
        }
      }
      config[config_len] = 0;

      if (reset || config_len > 0) {
        const char* err = set(number, reset, config);
        if (err != nullptr) {
          sprintf(reply, "Err - %s", err);
          return;
        }
      }
      if (!any_show) {
        strcpy(reply, "OK");
        return;
      }

      // the shown values, in the order asked, after the changes
      const FirewallRule* r = getRule(number);
      int n = 0;
      int more = 0;
      reply[0] = 0;
      q = p;
      while (true) {
        while (*q == ' ') q++;
        if (*q == 0) break;
        const char* word = q;
        while (*q != 0 && *q != ' ') q++;
        int len = q - word;
        char item[FIREWALL_COMMAND_MAX];
        int item_len;
        if (len == 4 && memcmp(word, "show", 4) == 0) {   // the whole rule
          item_len = formatRule(number, item);
        } else if (len != 2 || !isFieldKey(word)) {       // a set or '-'
          continue;
        } else {
          item_len = sprintf(item, "%.2s:", word);
          int v = -1;
          if (r != nullptr) v = formatField(r, word, &item[item_len]);
          if (v < 0) {
            item_len += sprintf(&item[item_len], "-");
          } else {
            item_len += v;
          }
        }
        if (n + 1 + item_len > TABLE_REPLY_MAX) {
          more++;
          continue;
        }
        if (n > 0) reply[n++] = ' ';
        strcpy(&reply[n], item);
        n += item_len;
      }
      if (more > 0) sprintf(&reply[n], " +%d more", more);
    }
  }

private:
  // handleCommand() helpers

  // true if 'command' is the word 'word', alone or followed by a space
  static bool isCommand(const char* command, const char* word) {
    int len = strlen(word);
    return memcmp(command, word, len) == 0 && (command[len] == 0 || command[len] == ' ');
  }

  // true if rule 'r' checks the sender tracking table (tl:sendtrk)
  static bool isSenderTracking(const FirewallRule* r) {
    return (r->param_set & FIREWALL_HAS_TABLE_LOOKUP) && r->table_lookup == FIREWALL_LOOKUP_SENDER_TRACKING;
  }

  // a sendtrk rule's window, lb x lr, in whole minutes (as SenderTracking counts)
  static uint32_t senderWindowMinutes(const FirewallRule* r) {
    return (uint32_t)r->limit_burst * ((r->limit_recovery + 59) / 60);
  }

  // Counts the sender clocks still in effect (ahead of now, after moving clocks long behind up to now): 'total',
  // per rule slot 'tracked' and 'maxed' (its next packet would be over the rule's limit), and 'left_over' (clocks
  // of slots that no longer hold a sendtrk rule).
  void countSenders(uint64_t uptime_millis, int tracked[FIREWALL_MAX_RULES], int maxed[FIREWALL_MAX_RULES],
                    int& total, int& left_over) {
    _senders.recover(uptime_millis);
    total = 0;
    left_over = 0;
    for (int i = 0; i < FIREWALL_MAX_RULES; i++) tracked[i] = maxed[i] = 0;
    for (int i = 0; i < _senders.getCount(); i++) {
      int rule, ahead;
      _senders.getRecord(i, uptime_millis, rule, ahead);
      if (ahead == 0 || rule >= FIREWALL_MAX_RULES) continue;   // fully recovered: no limit in effect
      total++;
      const FirewallRule* r = getRule(rule);
      if (r == nullptr || !isSenderTracking(r)) {   // left over from an old rule
        left_over++;
        continue;
      }
      tracked[rule]++;
      uint32_t lr = (r->limit_recovery + 59) / 60;   // whole minutes, as SenderTracking counts
      if ((uint32_t)ahead + lr > senderWindowMinutes(r)) maxed[rule]++;
    }
  }

  // Writes a window in minutes as days, hours and minutes, eg. "3d", "10h", "2h30m". Returns the length.
  static int formatWindow(uint32_t minutes, char* dest) {
    unsigned long d = minutes / 1440, h = (minutes % 1440) / 60, m = minutes % 60;
    int n = 0;
    if (d > 0) n += sprintf(&dest[n], "%lud", d);
    if (h > 0) n += sprintf(&dest[n], "%luh", h);
    if (m > 0 || n == 0) n += sprintf(&dest[n], "%lum", m);
    return n;
  }

  // 'fw senders<p>': "senders: <tracked>/<size>" (records whose limits are still in effect), " (overwriting)" if
  // they all are (a new sender then replaces the one closest to fully recovered, so its limits are lost early), then
  // "# rule tracked/maxed (dropped)", then page 'page' of the sendtrk rules, "<slot> <name> <tracked>/<maxed>
  // (<dropped>)": maxed: senders whose next packet would be dropped, dropped: the rule's match count (" fwd" after
  // it for an ac:fwd rule, which forwards them). "..." on its own line: a later page has rules.
  void formatSenders(int page, uint64_t uptime_millis, char* reply) {
    int tracked[FIREWALL_MAX_RULES];
    int maxed[FIREWALL_MAX_RULES];
    int total, left_over;
    countSenders(uptime_millis, tracked, maxed, total, left_over);

    int n = sprintf(reply, "senders: %d/%d", total, SENDER_TRACKING_SIZE);
    if (total >= SENDER_TRACKING_SIZE) n += sprintf(&reply[n], " (overwriting)");
    n += sprintf(&reply[n], "\n# rule tracked/maxed (dropped)");

    int first = (page - 1) * FIREWALL_SENDER_PAGE_RULES;   // index of the page's first sendtrk rule
    int index = 0;
    int shown = 0;
    int more = 0;
    bool later = false;
    for (int i = 0; i < FIREWALL_MAX_RULES; i++) {
      const FirewallRule* r = getRule(i);
      if (r == nullptr || !isSenderTracking(r)) continue;
      if (index++ < first) continue;
      if (shown == FIREWALL_SENDER_PAGE_RULES) {
        later = true;
        break;
      }
      const char* name = r->name;
      if (name[0] == 0) name = "?";
      char item[40];
      // dropped: the rule's match count (an ac:fwd rule forwards those packets instead: marked "fwd")
      int len = sprintf(item, "%d %s %d/%d (%lu%s)", i, name, tracked[i], maxed[i], (unsigned long)r->match_count,
                        r->action == FIREWALL_ACTION_FORWARD ? " fwd" : "");
      n = addLine(reply, n, item, len, more);
      shown++;
    }
    if (shown == 0) {
      if (index == 0) {
        strcpy(&reply[n], "\nno sendtrk rules");
      } else {
        sprintf(reply, "Err - no page %d, %d sendtrk rules", page, index);
      }
      return;
    }
    if (more > 0) n += sprintf(&reply[n], "\n+%d more", more);
    if (later) strcpy(&reply[n], "\n...");
  }

#if FIREWALL_LOG_ENABLED
  // The filter at 'p' (the rest of the command): "" all drops, "<n>" rule n's, "-" drops with no rule matched.
  int parseLogFilter(const char* p) const {
    while (*p == ' ') p++;
    if (*p == 0) return FIREWALL_LOG_FILTER_ALL;
    if (p[0] == '-' && p[1] == 0) return FIREWALL_LOG_NO_RULE;
    int number = parseSlotNumber(p);
    if (number < 0 || number >= FIREWALL_MAX_RULES || *p != 0) return FIREWALL_LOG_FILTER_BAD;
    if (getRule(number) == nullptr) return FIREWALL_LOG_FILTER_EMPTY;
    return number;
  }

  static bool logMatches(const FirewallLogEntry* e, int filter) {
    return filter == FIREWALL_LOG_FILTER_ALL || e->rule == filter;
  }

  // Writes the since-boot count for 'filter': "drops: <n>", "rule <n> <name>: <its drops> drops" (its match count),
  // or "no rule: <n> drops". Returns the length.
  int formatLogTotal(int filter, char* dest) const {
    if (filter == FIREWALL_LOG_FILTER_ALL) return sprintf(dest, "drops: %lu", (unsigned long)_log.getTotal());
    if (filter == FIREWALL_LOG_NO_RULE) return sprintf(dest, "no rule: %lu drops", (unsigned long)_log.getNoRuleTotal());
    const FirewallRule* r = getRule(filter);
    const char* name = (r != nullptr && r->name[0] != 0) ? r->name : "?";
    return sprintf(dest, "rule %d %s: %lu drops", filter, name, r != nullptr ? (unsigned long)r->match_count : 0UL);
  }

  // Writes an entry's payload type name (its number if it has none). Returns the length.
  static int formatLogType(const FirewallLogEntry* e, char* dest) {
    const char* name = packetTypeName(e->payloadType());
    if (name[0] != 0) return sprintf(dest, "%s", name);
    return sprintf(dest, "%d", e->payloadType());
  }

  // 'fw log...' ('p' is the text after "log"): a page, 'clear', or the serial console only error.
  void handleLogCommand(const char* p, char* reply, uint64_t uptime_millis) {
    static const char* usage = "Err - use: fw log<p> [<n>|-] or fw log clear";
    if (*p == 0) {   // the whole log: serial console only, printed by MyMesh
      strcpy(reply, "Err - fw log: serial console only, use fw log<p>");
      return;
    }
    if (*p == ' ') {
      while (*p == ' ') p++;
      if (strcmp(p, "clear") == 0) {
        _log.clear();
        strcpy(reply, "OK - firewall log cleared");
        return;
      }
      if (isCommand(p, "csv")) {   // CSV: serial console only, printed by MyMesh
        strcpy(reply, "Err - fw log csv: serial console only, use fw log<p>");
        return;
      }
      int filter = parseLogFilter(p);
      if (filter == FIREWALL_LOG_FILTER_EMPTY) {
        strcpy(reply, "Err - that slot is empty");
      } else if (filter < FIREWALL_LOG_FILTER_ALL) {
        strcpy(reply, usage);
      } else {   // the whole log of one rule: serial console only, printed by MyMesh
        strcpy(reply, "Err - fw log <n>: serial console only, use fw log<p> <n>");
      }
      return;
    }
    int page = parseSlotNumber(p);   // moves past the number and its spaces
    if (page < 1) {
      strcpy(reply, usage);
      return;
    }
    int filter = parseLogFilter(p);
    if (filter == FIREWALL_LOG_FILTER_EMPTY) {
      strcpy(reply, "Err - that slot is empty");
      return;
    }
    if (filter < FIREWALL_LOG_FILTER_ALL) {
      strcpy(reply, usage);
      return;
    }
    formatLogPage(page, filter, uptime_millis, reply);
  }

  // Page 'page' of the logged drops matching 'filter', newest first: the since-boot count (formatLogTotal()),
  // then FIREWALL_LOG_PAGE_ENTRIES "<age> <slot> <type> <hops> <key>" lines ("-": no rule matched, "old": a rule
  // since replaced; no slot when filtered), the key without its label ("a1b2c3d4", "3a/9e", "5e", "0", "2",
  // "rb2"; none for a hop policy packet type entry, which repeats the type), then "..." on its own line if a later
  // page has drops. The longest 5 entries fit one reply.
  void formatLogPage(int page, int filter, uint64_t uptime_millis, char* reply) const {
    int n = formatLogTotal(filter, reply);
    int first = (page - 1) * FIREWALL_LOG_PAGE_ENTRIES;   // index of the page's first matching entry
    int index = 0;
    int shown = 0;
    bool later = false;
    for (int age = 0; age < _log.getCount(); age++) {
      const FirewallLogEntry* e = _log.getEntry(age);
      if (!logMatches(e, filter)) continue;
      if (index++ < first) continue;
      if (shown == FIREWALL_LOG_PAGE_ENTRIES) {
        later = true;
        break;
      }
      char item[48];
      int len = FirewallLog::formatAge(e->uptime_secs, uptime_millis, item);
      if (filter == FIREWALL_LOG_FILTER_ALL) {
        if (e->rule == FIREWALL_LOG_NO_RULE) {
          len += sprintf(&item[len], " -");
        } else if (e->rule == FIREWALL_LOG_OLD_RULE) {
          len += sprintf(&item[len], " old");
        } else {
          len += sprintf(&item[len], " %d", e->rule);
        }
      }
      item[len++] = ' ';
      len += formatLogType(e, &item[len]);
      len += sprintf(&item[len], " %d", e->hops);
      const HopPolicyEntry* hop = e->table == FIREWALL_LOG_TABLE_HOPPOL ? HopPolicy::getEntry((int)e->key) : nullptr;
      bool repeats_type = hop != nullptr && hop->property == HOP_POLICY_PACKET_TYPE;   // eg. 'req': the type again
      if (e->table != FIREWALL_LOG_TABLE_NONE && !repeats_type) {
        item[len++] = ' ';
        len += FirewallLog::formatKey(e, false, _route_policy, &item[len]);
      }
      // The longest 5 entries fit with a count of up to 8 digits. Past 100 million drops a page of long entries
      // can run out of room: it ends early and that entry isn't shown (the next page starts after it).
      if (n + 1 + len + 4 > FIREWALL_LOG_REPLY_MAX) {
        later = true;
        break;
      }
      reply[n++] = '\n';
      memcpy(&reply[n], item, len);
      n += len;
      reply[n] = 0;
      shown++;
    }
    if (shown == 0) {
      if (page == 1) {
        strcpy(&reply[n], "\nnone logged");
      } else {
        sprintf(reply, "Err - no page %d, %d logged", page, index);
      }
      return;
    }
    if (later) strcpy(&reply[n], "\n...");
  }

  // 'fw log csv': the logged drops matching 'filter' as CSV, newest first, one line each:
  //   age_s,uptime_s,rule,name,type,route,hops,table,key
  // age_s: seconds ago ('stats csv' min_ago x 60), uptime_s: the repeater's uptime when dropped, rule: the
  // slot, or "-" (name "(none)": no rule matched, "(old)": a rule since replaced), table: the tl name, key: the
  // table's key without its label (as the pages: "a1b2c3d4", "3a/9e", "5e", "0", "2", "req"), empty without one.
  void printLogCsv(Print& out, int filter, uint64_t uptime_millis) const {
    out.print("age_s,uptime_s,rule,name,type,route,hops,table,key\n");
    uint32_t now = (uint32_t)(uptime_millis / 1000);
    for (int age = 0; age < _log.getCount(); age++) {
      const FirewallLogEntry* e = _log.getEntry(age);
      if (!logMatches(e, filter)) continue;
      char slot[4], type[8], key[32], line[96];
      const char* name;
      if (e->rule == FIREWALL_LOG_NO_RULE) {
        strcpy(slot, "-");
        name = "(none)";
      } else if (e->rule == FIREWALL_LOG_OLD_RULE) {
        strcpy(slot, "-");
        name = "(old)";
      } else {
        sprintf(slot, "%d", e->rule);
        const FirewallRule* r = getRule(e->rule);
        name = (r != nullptr && r->name[0] != 0) ? r->name : "";
      }
      formatLogType(e, type);
      FirewallLog::formatKey(e, false, _route_policy, key);
      uint32_t ago = now >= e->uptime_secs ? now - e->uptime_secs : 0;
      sprintf(line, "%lu,%lu,%s,%s,%s,%s,%d,%s,%s\n", (unsigned long)ago, (unsigned long)e->uptime_secs, slot, name,
              type, routeTypeName(e->routeType()), e->hops, tableLookupName(e->table), key);
      out.print(line);
    }
  }
#endif

  // 'fw insert <n>': moves rules number.. down one, up to the first empty slot.
  void insertSlot(int number, char* reply) {
    int free_slot = -1;   // first empty slot from 'number' on
    for (int i = number; i < FIREWALL_MAX_RULES; i++) {
      if (_rules[i].param_set == 0) {
        free_slot = i;
        break;
      }
    }
    if (free_slot < 0) {
      sprintf(reply, "Err - no free slot after %d, nothing changed", number);
      return;
    }
    if (free_slot == number) {
      sprintf(reply, "OK - slot %d already empty, nothing moved", number);
      return;
    }
    for (int i = free_slot; i > number; i--) _rules[i] = _rules[i - 1];
    _rules[number] = FirewallRule();
    _senders.forgetRule(free_slot);                  // left over from an old rule there, if any
    _senders.moveRules(number, free_slot - 1, 1);   // sender clocks move with their rules
#if FIREWALL_LOG_ENABLED
    _log.forgetRule(free_slot);                      // as the sender clocks
    _log.moveRules(number, free_slot - 1, 1);
#endif
    sprintf(reply, "OK - slot %d opened", number);
  }

  // 'fw collapse <n>': removes empty slot 'number', moving every later slot up one.
  void collapseSlot(int number, char* reply) {
    if (_rules[number].param_set != 0) {
      sprintf(reply, "Err - slot %d is not empty, nothing changed", number);
      return;
    }
    int last = -1;   // last slot holding a rule, after 'number'
    for (int i = number + 1; i < FIREWALL_MAX_RULES; i++) {
      if (_rules[i].param_set != 0) last = i;
    }
    if (last < 0) {
      sprintf(reply, "OK - no rules after slot %d, nothing moved", number);
      return;
    }
    for (int i = number; i < FIREWALL_MAX_RULES - 1; i++) _rules[i] = _rules[i + 1];
    _rules[FIREWALL_MAX_RULES - 1] = FirewallRule();
    _senders.forgetRule(number);                                // left over from an old rule there, if any
    _senders.moveRules(number + 1, FIREWALL_MAX_RULES - 1, -1);   // sender clocks move with their rules
#if FIREWALL_LOG_ENABLED
    _log.forgetRule(number);                                    // as the sender clocks
    _log.moveRules(number + 1, FIREWALL_MAX_RULES - 1, -1);
#endif
    sprintf(reply, "OK - slot %d removed", number);
  }

  // Writes rule 'number' as its config, or "-" if the slot is empty (the slot number is in the command). Returns
  // the length.
  int formatRule(int number, char* dest) const {
    int n = format(number, dest);
    if (n == 0) n = sprintf(dest, "-");
    return n;
  }

  // Writes rule 'number' as "<n> - <config>" ("<n> -" if empty): "fw " + that recreates it. Returns the length.
  int formatLine(int number, char* dest) const {
    int n = sprintf(dest, "%d -", number);
    if (getRule(number) == nullptr) return n;
    dest[n++] = ' ';
    n += format(number, &dest[n]);
    return n;
  }

  // true if the 2 letters at 'key' are a rule field key (FIREWALL_FIELD_KEYS)
  static bool isFieldKey(const char* key) {
    for (const char* k = FIREWALL_FIELD_KEYS; *k != 0; k += 3) {
      if (isKey(key, k)) return true;
    }
    return false;
  }

  // set() parsing helpers, on a value given by its start and length (not null-terminated).

  // decimal digits only, at most 'max'
  static bool parseDecimal(const char* s, int len, uint32_t max, uint32_t& out) {
    if (len == 0 || len > 10) return false;
    uint32_t v = 0;
    for (int i = 0; i < len; i++) {
      if (s[i] < '0' || s[i] > '9') return false;
      v = v * 10 + (s[i] - '0');
      if (v > max) return false;
    }
    out = v;
    return true;
  }

  // 1 or 2 hex digits, eg "5e"
  static bool parseHexByte(const char* s, int len, uint8_t& out) {
    if (len < 1 || len > 2) return false;
    uint8_t v = 0;
    for (int i = 0; i < len; i++) {
      char c = s[i];
      uint8_t d;
      if (c >= '0' && c <= '9') {
        d = c - '0';
      } else if (c >= 'a' && c <= 'f') {
        d = c - 'a' + 10;
      } else if (c >= 'A' && c <= 'F') {
        d = c - 'A' + 10;
      } else {
        return false;
      }
      v = (v << 4) | d;
    }
    out = v;
    return true;
  }

  // Writes an lr value in its largest whole unit: days, hours, minutes (no unit) or seconds. Returns the length.
  static int formatRecovery(uint32_t secs, char* dest) {
    unsigned long s = secs;
    if (s % 86400 == 0) return sprintf(dest, "%lud", s / 86400);
    if (s % 3600 == 0) return sprintf(dest, "%luh", s / 3600);
    if (s % 60 == 0) return sprintf(dest, "%lu", s / 60);
    return sprintf(dest, "%lus", s);
  }

  // lr value: a number of minutes, or a number with a unit: s (seconds), m (minutes), h (hours) or d (days), eg.
  // 30s, 240, 4h, 2d.
  // 1 second up to SENDER_TRACKING_MAX_WINDOW minutes. 'secs' is unchanged if it isn't valid.
  static bool parseRecovery(const char* s, int len, uint32_t& secs) {
    if (len < 1) return false;
    uint32_t unit = 60;   // no unit: minutes
    char last = s[len - 1];
    if (last == 's') {
      unit = 1;
      len--;
    } else if (last == 'm') {
      len--;
    } else if (last == 'h') {
      unit = 3600;
      len--;
    } else if (last == 'd') {
      unit = 86400;
      len--;
    }
    uint32_t n;
    uint32_t max_secs = (uint32_t)SENDER_TRACKING_MAX_WINDOW * 60;
    if (!parseDecimal(s, len, max_secs / unit, n) || n < 1) return false;
    secs = n * unit;
    return true;
  }

  // a PAYLOAD_TYPE_* number 0-15, or its name
  static bool parsePacketType(const char* s, int len, uint8_t& out) {
    for (int i = 0; i < 16; i++) {
      const char* name = packetTypeName(i);
      if (name[0] != 0 && isWord(s, len, name)) {
        out = i;
        return true;
      }
    }
    uint32_t n;
    if (!parseDecimal(s, len, 15, n)) return false;
    out = n;
    return true;
  }

  // rg value: a region name in the region list (its id goes in 'id'), or '*' (id 0, un-scoped). Returns nullptr,
  // or an error message.
  const char* parseRegion(const char* s, int len, uint16_t& id) {
    static char err[48];
    if (len == 1 && s[0] == '*') {
      id = 0;
      return nullptr;
    }
    char name[sizeof(((RegionEntry*)0)->name)];   // findByName() needs it null-terminated
    if (len >= (int)sizeof(name)) return "bad rg value, region name or *";
    memcpy(name, s, len);
    name[len] = 0;
    RegionEntry* region = nullptr;
    if (_regions != nullptr) region = _regions->findByName(name);
    if (region == nullptr) {
      snprintf(err, sizeof(err), "unknown region %s", name);
      _unknown_region = true;
      return err;
    }
    id = region->id;
    return nullptr;
  }

  // tl name of a FIREWALL_LOOKUP_* table, or "" if it has none
  static const char* tableLookupName(uint8_t table) {
    if (table == FIREWALL_LOOKUP_ROUTE_POLICY) return "routepol";
    if (table == FIREWALL_LOOKUP_HOP_POLICY) return "hoppol";
    if (table == FIREWALL_LOOKUP_SENDER_TRACKING) return "sendtrk";
    if (table == FIREWALL_LOOKUP_CHANNEL_TRACKING) return "chantrk";
    if (table == FIREWALL_LOOKUP_PACKET_TRACKING) return "pkttrk";
    return "";
  }

  // tl value: one table name (routepol, hoppol, sendtrk, chantrk, pkttrk)
  static bool parseTableLookup(const char* s, int len, uint8_t& out) {
    for (uint8_t table = FIREWALL_LOOKUP_ROUTE_POLICY; table <= FIREWALL_LOOKUP_PACKET_TRACKING; table++) {
      if (isWord(s, len, tableLookupName(table))) {
        out = table;
        return true;
      }
    }
    return false;
  }

  // a ROUTE_TYPE_* number 0-3, or its name
  static bool parseRouteType(const char* s, int len, uint8_t& out) {
    for (int i = 0; i < 4; i++) {
      if (isWord(s, len, routeTypeName(i))) {
        out = i;
        return true;
      }
    }
    uint32_t n;
    if (!parseDecimal(s, len, 3, n)) return false;
    out = n;
    return true;
  }
};
