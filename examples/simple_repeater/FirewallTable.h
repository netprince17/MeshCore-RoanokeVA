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
#define FIREWALL_LOOKUP_SENDER_TRACKING    3      // sendtrk: the sender (adverts, anon requests) is over lb / lr
#define FIREWALL_LOOKUP_CHANNEL_TRACKING   4      // chantrk: the channel (channel messages) is over lb / lr
#define FIREWALL_LOOKUP_PACKET_TRACKING    5      // pkttrk: slot ls (any packet the rule matches) is over lb / lr

// FirewallRule::hop_compare: how the packet's hop count is compared with hop_count (set() hp:N, hp:<N, hp:>N)
#define FIREWALL_HOPS_EQUAL                0
#define FIREWALL_HOPS_LESS                 1
#define FIREWALL_HOPS_GREATER              2

// FirewallRule::action: what a rule does with a packet it matches, once all its used checks pass
#define FIREWALL_ACTION_DROP               0
#define FIREWALL_ACTION_FORWARD            1

#define FIREWALL_NAME_LEN  8      // max characters in a rule name

#define FIREWALL_FILE  "/fw_rules_v1"   // saved rules: one "<n> - <config>" line per rule (a new format: _v2)

// CLI (handleCommand())
#define FIREWALL_PAGE_SLOTS    6     // slots per 'fw show<p>' page (more don't fit a reply with large match counts)
#define FIREWALL_COMMAND_MAX   160   // longest 'fw' command
// rule field keys, in format() order, each followed by a space
#define FIREWALL_FIELD_KEYS    "nm pt hp rb rt ch rg lb lr ls tl ac "

// Default rules (loadDefaults(), when none are saved, or 'fw setdefault'): set() configs, into slots 0, 1, 2...
// "" leaves its slot empty; nullptr ends the list.
static const char* const FIREWALL_DEFAULT_RULES[] = {
  // check for blocked routes first
  "nm:routepol                        tl:routepol                   ac:drop",

  // drop packets over the hop policy's limits
  "nm:hoppol                          tl:hoppol                     ac:drop",

  // track and restrict advertisements
  "nm:advlm1   pt:adv     hp:<7       tl:sendtrk       lb:6  lr:12h ac:drop",
  "nm:advlm2   pt:adv     hp:>6       tl:sendtrk       lb:1  lr:3d  ac:drop",

  // track and restrict anonymous requests
  "nm:anrqlm1  pt:anonreq hp:<7       tl:sendtrk       lb:6  lr:12h ac:drop",
  "nm:anrqlm2  pt:anonreq hp:>6       tl:sendtrk       lb:6  lr:3d  ac:drop",

  // wardriving should be stopped locally
  "nm:wrdrvlm  pt:grptxt  hp:>2 ch:81                               ac:drop",

  // limit distant messages to each channel, prioritize local channels
  "nm:chanlm1             hp:<7       tl:chantrk       lb:8  lr:15s ac:fwd",
  "nm:chanlm2             hp:>6       tl:chantrk       lb:6  lr:15s ac:drop",

  // total cap on distant tracking tables (chantrk and sendtrk can be abused)
  "nm:chandos1 pt:grptxt  hp:>6       tl:pkttrk   ls:0 lb:10 lr:6s  ac:drop",
  "nm:senddos1 pt:adv     hp:>6       tl:pkttrk   ls:1 lb:8 lr:15s  ac:drop",
  "nm:senddos2 pt:anonreq hp:>6       tl:pkttrk   ls:1 lb:8 lr:15s  ac:drop",

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
  uint8_t  hop_count;              // hop count the rule applies to, compared as hop_compare says
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
  uint8_t  hop_compare;            // FIREWALL_HOPS_EQUAL, _LESS or _GREATER: packet hop count vs hop_count

  // packet stats
  uint32_t match_count;            // times this rule has taken action (runtime counter, not a setting)
};
static_assert(sizeof(FirewallRule) == 32, "firewall rule must stay 32 bytes");

class FirewallTable : private TableCli {
  FirewallRule _rules[FIREWALL_MAX_RULES];   // rules in slot order, empty slots (param_set 0) anywhere
  SenderTracking _senders;                   // allowances per sender, for rules with FIREWALL_LOOKUP_SENDER_TRACKING
  ChannelTracking _channels;                 // allowances per channel, for rules with FIREWALL_LOOKUP_CHANNEL_TRACKING
  PacketTracking<PACKET_TRACKING_SLOTS> _packets;   // numbered allowances, for rules with FIREWALL_LOOKUP_PACKET_TRACKING
  RoutePolicy _route_policy;                 // repeater routes, for rules with FIREWALL_LOOKUP_ROUTE_POLICY
  HopPolicy _hop_policy;                     // hop limits per packet property, for rules with FIREWALL_LOOKUP_HOP_POLICY
  FILESYSTEM* _fs;                           // where the rules are saved, set by begin()
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

      // hop count set: the rule only applies to packets whose hop count (repeaters passed) is equal to,
      // less than, or greater than the rule's hop_count
      if (r->param_set & FIREWALL_HAS_HOP_COUNT) {
        if (r->hop_compare == FIREWALL_HOPS_LESS) {
          if (hop_count >= r->hop_count) continue;
        } else if (r->hop_compare == FIREWALL_HOPS_GREATER) {
          if (hop_count <= r->hop_count) continue;
        } else {
          if (hop_count != r->hop_count) continue;
        }
      }

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
      if (r->param_set & FIREWALL_HAS_TABLE_LOOKUP) {
        if (r->table_lookup == FIREWALL_LOOKUP_ROUTE_POLICY) {         // the path matches one of its routes
          route_slot = _route_policy.findMatch(packet->path, packet->getPathHashSize(), packet->getPathHashCount());
          if (route_slot < 0) continue;
        } else if (r->table_lookup == FIREWALL_LOOKUP_HOP_POLICY) {    // over a hop limit that applies to it
          hop_entry = _hop_policy.findMatch(packet, hop_count);
          if (hop_entry < 0) continue;
        } else if (r->table_lookup == FIREWALL_LOOKUP_SENDER_TRACKING) {   // sender over lb / lr
          if (!_senders.isOverLimit(packet, uptime_millis, r->limit_recovery, r->limit_burst)) continue;
        } else if (r->table_lookup == FIREWALL_LOOKUP_CHANNEL_TRACKING) {  // channel over lb / lr
          if (!_channels.isOverLimit(packet, uptime_millis, r->limit_recovery, r->limit_burst)) continue;
        } else if (r->table_lookup == FIREWALL_LOOKUP_PACKET_TRACKING) {   // slot ls over lb / lr
          if (!_packets.isOverLimit(r->limit_slot, uptime_millis, r->limit_recovery, r->limit_burst)) continue;
        } else {
          continue;   // unknown table
        }
      }

      // all used checks passed: this rule decides, using its action
      r->match_count++;
      if (route_slot >= 0) _route_policy.addMatch(route_slot);
      if (hop_entry >= 0) _hop_policy.addMatch(hop_entry);
      return r->action == FIREWALL_ACTION_FORWARD;
    }
    return false;   // no rule decided: drop
  }

  // Sets rule 'number' from 'config', "key:value" fields (key:- unsets). reset: start from an empty slot (and
  // match_count 0), otherwise only the fields named change. An empty config with reset empties the slot.
  // A rule needs a match/check field, and a new rule needs ac. lb / lr go with tl:sendtrk, chantrk or pkttrk
  // (both needed, and ls for pkttrk; lb x lr at most 32767 minutes for sendtrk). All or nothing. Returns nullptr,
  // or an error message. Keys and values:
  //   nm:<name, 8>  pt:<type name|0-15>  hp:<N|<N|>N>  rb:<1-3>  rt:<tflood|flood|direct|tdirect|0-3>
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

      } else if (isKey(field, "hp")) {   // hop count: N exactly, <N less than, >N greater than
        if (unset) {
          r.param_set &= ~FIREWALL_HAS_HOP_COUNT;
        } else {
          const char* hp_err = "bad hp value, 0-63, <1-63 or >0-62";
          if (v[0] == '<') {
            if (!parseDecimal(v + 1, v_len - 1, 63, n) || n < 1) return hp_err;   // <0 would never match
            r.hop_compare = FIREWALL_HOPS_LESS;
          } else if (v[0] == '>') {
            if (!parseDecimal(v + 1, v_len - 1, 62, n)) return hp_err;            // >63 would never match
            r.hop_compare = FIREWALL_HOPS_GREATER;
          } else {
            if (!parseDecimal(v, v_len, 63, n)) return hp_err;
            r.hop_compare = FIREWALL_HOPS_EQUAL;
          }
          r.hop_count = n;
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

    if (reset) r.match_count = 0;
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

  // empties every slot
  void clear() {
    for (int i = 0; i < FIREWALL_MAX_RULES; i++) _rules[i] = FirewallRule();
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
    if (isKey(key, "hp")) {
      if (!(r->param_set & FIREWALL_HAS_HOP_COUNT)) return -1;
      if (r->hop_compare == FIREWALL_HOPS_LESS) return sprintf(dest, "<%d", r->hop_count);
      if (r->hop_compare == FIREWALL_HOPS_GREATER) return sprintf(dest, ">%d", r->hop_count);
      return sprintf(dest, "%d", r->hop_count);
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
  //   fw senders             the sender tracking table (tl:sendtrk): senders still tracked (limits in effect), and
  //                          of those, the ones with adverts / anon requests. 'uptime_millis': now.
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

    } else if (strcmp(command, "senders") == 0) {   // the sender tracking table
      int tracking, adverts, anonreqs;
      _senders.countTracking(uptime_millis, tracking, adverts, anonreqs);
      int n = sprintf(reply, "tracking: %d/%d", tracking, SENDER_TRACKING_SIZE);
      // all tracked: a new sender replaces the one closest to fully recovered, so its limits are lost early
      if (tracking >= SENDER_TRACKING_SIZE) n += sprintf(&reply[n], " (overwriting)");
      sprintf(&reply[n], "\nadverts: %d\nanonreqs: %d", adverts, anonreqs);

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
      if (shown == 0 && more == 0) {
        strcpy(reply, "none");
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
        sprintf(reply, "Err - use: fw [<0-%d> [-] [key:value|key ...]]|show<p>|insert <n>|collapse <n>|clear|setdefault|save|reload|unsave|senders",
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
