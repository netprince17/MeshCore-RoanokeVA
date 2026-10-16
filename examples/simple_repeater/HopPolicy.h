#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "TableFile.h"
#include "TableCli.h"

// Hop policy, for firewall rules with tl:hoppol: a fixed list of packet properties (route type, path hash width,
// packet type), each with an optional hop limit (repeaters passed, as the firewall's hp). A packet matches if it
// is over any limit that applies to it. Loaded at boot from HOP_POLICY_FILE, or HOP_POLICY_DEFAULT_LIMITS.
// Hop limits for all floods and adverts are upstream's flood.max, flood.max.unscoped and flood.max.advert.

#define HOP_POLICY_NONE          0xFF   // _max_hops value: no limit
#define HOP_POLICY_MAX_HOPS      64     // highest limit that can be set (a path holds at most 63 hops, so 64 is
                                        // never exceeded: no limit in effect, but shown as 64, not '-')

// HopPolicyEntry::property: which packet property an entry checks
#define HOP_POLICY_ROUTE_TYPE    1      // value: ROUTE_TYPE_*
#define HOP_POLICY_ROUTE_BYTES   2      // value: path hash width, 1, 2 or 3 bytes
#define HOP_POLICY_PACKET_TYPE   3      // value: PAYLOAD_TYPE_*

#define HOP_POLICY_ENTRIES       20     // number of entries in the fixed list
#define HOP_POLICY_PAGE_ENTRIES  8      // entries per 'hoppol show<p>' page
#define HOP_POLICY_PAGES         ((HOP_POLICY_ENTRIES + HOP_POLICY_PAGE_ENTRIES - 1) / HOP_POLICY_PAGE_ENTRIES)
#define HOP_POLICY_NAME_LEN      7      // longest entry name, for aligned show pages

// Default limits (loadDefaults(), when none are saved, or 'hoppol setdefault'): "name:max" pairs, entries not
// named have no limit. nullptr ends the list.
static const char* const HOP_POLICY_DEFAULT_LIMITS[] = {
  "req:6",
  "anonreq:12",
  "resp:6",
  "path:12",
  "ack:12",
  "txt:12",
  "trace:6",
  "grpdata:6",
  "multi:6",
  "ctrl:1",
  "raw:6",
  nullptr
};

#define HOP_POLICY_FILE          "/hop_pol_v1"   // saved limits: "name:max" pairs, as 'hoppol' lists them (a new
                                                 // format: _v2)
#define HOP_POLICY_LINE_MAX      320    // longest line in HOP_POLICY_FILE (every entry with a 2-digit limit: ~250)

struct HopPolicyEntry {
  const char* name;    // CLI / config name
  uint8_t property;    // HOP_POLICY_ROUTE_TYPE, _ROUTE_BYTES or _PACKET_TYPE
  uint8_t value;       // the property value the entry applies to
};

class HopPolicy : private TableCli {
  uint8_t _max_hops[HOP_POLICY_ENTRIES];       // per entry: most hops allowed, HOP_POLICY_NONE = no limit
  uint32_t _match_counts[HOP_POLICY_ENTRIES];  // per entry: times its limit made a firewall rule act
  FILESYSTEM* _fs;                             // where the limits are saved, set by begin()

public:
  HopPolicy(): _fs(nullptr) { clear(); }   // no limits, counts 0

  // At boot (from FirewallTable::begin()): loads the saved limits, or the defaults.
  void begin(FILESYSTEM* fs) {
    _fs = fs;
    if (fs->exists(HOP_POLICY_FILE)) {
      const char* err = load();   // falls back to the defaults if it fails
      if (err != nullptr) MESH_DEBUG_PRINTLN("HopPolicy: saved limits not loaded (%s), using the defaults", err);
    } else {
      loadDefaults();
    }
  }

  // Saves the limits to HOP_POLICY_FILE (not the match counts). Returns the number saved, or -1 if it failed.
  int save() {
    if (_fs == nullptr) return -1;
    char line[HOP_POLICY_LINE_MAX + 1];
    int n = 0;
    int count = 0;
    line[0] = 0;
    for (int i = 0; i < HOP_POLICY_ENTRIES; i++) {
      if (_max_hops[i] == HOP_POLICY_NONE) continue;
      if (n > 0) line[n++] = ' ';
      n += sprintf(&line[n], "%s:", getEntry(i)->name);
      n += formatMax(&line[n], _max_hops[i]);
      count++;
    }
    File file = tableFileOpenWrite(_fs, HOP_POLICY_FILE);
    if (!file) return -1;
    bool ok = tableFileWriteLine(file, line);
    file.close();
    if (!ok) return -1;
    return count;
  }

  // Replaces the limits with the saved ones. If the file can't be read or a line fails, loads the defaults
  // instead (nothing changes if nothing is saved). Returns nullptr, or an error message.
  const char* load() {
    static char err[64];
    if (_fs == nullptr) return "no storage";
    if (!_fs->exists(HOP_POLICY_FILE)) return "nothing saved";
    File file = tableFileOpenRead(_fs, HOP_POLICY_FILE);
    if (!file) {
      loadDefaults();
      return "can't open the saved limits";
    }
    clear();

    char line[HOP_POLICY_LINE_MAX + 1];
    int line_number = 0;
    bool too_long;
    const char* fail = nullptr;
    while (tableFileReadLine(file, line, HOP_POLICY_LINE_MAX, too_long)) {
      line_number++;
      if (too_long) {
        fail = "line too long";
        break;
      }
      fail = set(line);
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

  // the fixed list of entries, in check order
  static const HopPolicyEntry* getEntry(int i) {
    static const HopPolicyEntry list[HOP_POLICY_ENTRIES] = {
      { "direct",  HOP_POLICY_ROUTE_TYPE,  ROUTE_TYPE_DIRECT },
      { "tdirect", HOP_POLICY_ROUTE_TYPE,  ROUTE_TYPE_TRANSPORT_DIRECT },
      { "rb1",     HOP_POLICY_ROUTE_BYTES, 1 },                            // 1-byte path hashes
      { "rb2",     HOP_POLICY_ROUTE_BYTES, 2 },
      { "rb3",     HOP_POLICY_ROUTE_BYTES, 3 },
      { "req",     HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_REQ },
      { "resp",    HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_RESPONSE },
      { "txt",     HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_TXT_MSG },
      { "ack",     HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_ACK },
      { "grptxt",  HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_GRP_TXT },
      { "grpdata", HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_GRP_DATA },
      { "anonreq", HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_ANON_REQ },
      { "path",    HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_PATH },
      { "trace",   HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_TRACE },            // direct only for now
      { "multi",   HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_MULTIPART },        // direct only for now
      { "ctrl",    HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_CONTROL },
      { "pt12",    HOP_POLICY_PACKET_TYPE, 0x0C },                          // not used yet
      { "pt13",    HOP_POLICY_PACKET_TYPE, 0x0D },                          // not used yet
      { "pt14",    HOP_POLICY_PACKET_TYPE, 0x0E },                          // not used yet
      { "raw",     HOP_POLICY_PACKET_TYPE, PAYLOAD_TYPE_RAW_CUSTOM },
    };
    if (i < 0 || i >= HOP_POLICY_ENTRIES) return nullptr;
    return &list[i];
  }

  // Index of the entry named 'name' ('len' characters, not null-terminated), or -1.
  static int findEntry(const char* name, int len) {
    for (int i = 0; i < HOP_POLICY_ENTRIES; i++) {
      if (isWord(name, len, getEntry(i)->name)) return i;
    }
    return -1;
  }

  // Returns the first entry that applies to the packet and whose limit it is over, or -1.
  int findMatch(const mesh::Packet* packet) const {
    uint8_t hop_count = packet->getPathHashCount();
    for (int i = 0; i < HOP_POLICY_ENTRIES; i++) {
      if (_max_hops[i] == HOP_POLICY_NONE) continue;   // no limit
      if (hop_count <= _max_hops[i]) continue;         // within the limit
      if (appliesTo(getEntry(i), packet)) return i;
    }
    return -1;
  }

  // Sets limits from "name:max" pairs (max 0-64, '-' none); entries not named don't change. All or nothing.
  // Returns nullptr, or an error message.
  const char* set(const char* config) {
    uint8_t max_hops[HOP_POLICY_ENTRIES];   // parsed into a copy, kept only if all pairs are valid
    for (int i = 0; i < HOP_POLICY_ENTRIES; i++) max_hops[i] = _max_hops[i];
    bool named[HOP_POLICY_ENTRIES] = { false };
    bool any_show = false;
    const char* err = parse(config, max_hops, named, any_show);
    if (err != nullptr) return err;
    if (any_show) return "use name:max";   // a name without a max isn't a setting
    apply(max_hops, named);
    return nullptr;
  }

  // number of entries with a limit
  int getCount() const {
    int n = 0;
    for (int i = 0; i < HOP_POLICY_ENTRIES; i++) {
      if (_max_hops[i] != HOP_POLICY_NONE) n++;
    }
    return n;
  }

  // removes every limit (and match count)
  void clear() {
    for (int i = 0; i < HOP_POLICY_ENTRIES; i++) {
      _max_hops[i] = HOP_POLICY_NONE;
      _match_counts[i] = 0;
    }
  }

  // counts a match for entry 'i' (when a rule acts because of it)
  void addMatch(int i) {
    if (i >= 0 && i < HOP_POLICY_ENTRIES) _match_counts[i]++;
  }

  // Replaces all limits with HOP_POLICY_DEFAULT_LIMITS. A default that fails to parse is skipped (debug builds
  // print why).
  void loadDefaults() {
    clear();
    for (int i = 0; HOP_POLICY_DEFAULT_LIMITS[i] != nullptr; i++) {
      const char* err = set(HOP_POLICY_DEFAULT_LIMITS[i]);
      if (err != nullptr) MESH_DEBUG_PRINTLN("HopPolicy: default %s: %s, skipped", HOP_POLICY_DEFAULT_LIMITS[i], err);
    }
  }

  // Writes every entry's limit ('-' none) as 'hoppol' commands that recreate them, HOP_POLICY_PAGE_ENTRIES per
  // line. For the serial console ('hoppol show'): too long for one reply.
  void printAll(Print& out) const {
    for (int i = 0; i < HOP_POLICY_ENTRIES; i++) {
      if (i % HOP_POLICY_PAGE_ENTRIES == 0) out.print("hoppol");
      char item[16];
      int n = sprintf(item, " %s:", getEntry(i)->name);
      formatMax(&item[n], _max_hops[i]);
      out.print(item);
      if (i % HOP_POLICY_PAGE_ENTRIES == HOP_POLICY_PAGE_ENTRIES - 1 || i == HOP_POLICY_ENTRIES - 1) out.print("\n");
    }
  }

  // CLI 'hoppol'. Replies, except show pages, can be pasted back as commands.
  //   hoppol                 entries with a limit, eg. "flood:8 adv:6"
  //   hoppol <words>         name:max sets a limit (0-64, '-' none), name shows one, show<p> a page of
  //                          HOP_POLICY_PAGE_ENTRIES ("OK", then "entry name match_count" lines).
  //                          All or nothing. Replies the shown values, or "OK".
  //   hoppol clear | setdefault | save | reload   (setdefault isn't saved until 'hoppol save')
  //   hoppol unsave          removes the saved limits (the current ones stay): the defaults load at boot
  //   hoppol show            every limit, serial console only: handled by MyMesh (printAll())
  void handleCommand(const char* command, char* reply) {
    while (*command == ' ') command++;

    if (*command == 0) {   // list the entries with a limit
      int n = 0;
      int more = 0;
      reply[0] = 0;
      for (int i = 0; i < HOP_POLICY_ENTRIES; i++) {
        if (_max_hops[i] == HOP_POLICY_NONE) continue;
        n = addValue(reply, n, i, false, more);
      }
      if (n == 0 && more == 0) {
        strcpy(reply, "none");
      } else if (more > 0) {
        sprintf(&reply[n], " +%d more", more);
      }

    } else if (strcmp(command, "clear") == 0) {
      clear();
      strcpy(reply, "OK - all hop limits removed");

    } else if (strcmp(command, "setdefault") == 0) {
      loadDefaults();
      sprintf(reply, "OK - %d default hop limits loaded, not saved", getCount());

    } else if (strcmp(command, "save") == 0) {
      int count = save();
      if (count < 0) {
        strcpy(reply, "Err - save failed");
      } else {
        sprintf(reply, "OK - %d hop limits saved", count);
      }

    } else if (strcmp(command, "reload") == 0) {
      if (_fs == nullptr || !_fs->exists(HOP_POLICY_FILE)) {
        strcpy(reply, "Err - nothing saved, nothing changed");
        return;
      }
      const char* err = load();
      if (err != nullptr) {
        sprintf(reply, "Err - %s, defaults loaded (not saved)", err);
      } else {
        strcpy(reply, "OK - hop limits loaded");
      }

    } else if (strcmp(command, "unsave") == 0) {   // remove the saved limits, so the defaults load at boot
      if (_fs == nullptr || !_fs->exists(HOP_POLICY_FILE)) {
        strcpy(reply, "OK - nothing saved");
      } else if (!_fs->remove(HOP_POLICY_FILE)) {
        strcpy(reply, "Err - remove failed");
      } else {
        strcpy(reply, "OK - saved limits removed, defaults load at boot (or hoppol setdefault)");
      }

    } else {
      // sets and shows, in any order: check them all, then apply the sets
      uint8_t max_hops[HOP_POLICY_ENTRIES];
      for (int i = 0; i < HOP_POLICY_ENTRIES; i++) max_hops[i] = _max_hops[i];
      bool named[HOP_POLICY_ENTRIES] = { false };
      bool any_show = false;
      const char* err = parse(command, max_hops, named, any_show);
      if (err != nullptr) {
        sprintf(reply, "Err - %s", err);
        return;
      }
      apply(max_hops, named);
      if (!any_show) {
        strcpy(reply, "OK");
        return;
      }

      // the shown entries, in the order asked, with their values after the sets. A show page starts the reply
      // with "OK", so its lines stay left-aligned in clients that put a prompt before the first line.
      int n = 0;
      int more = 0;
      reply[0] = 0;
      if (hasShowPage(command)) n = sprintf(reply, "OK");
      int last_page = 0;   // highest show page shown
      const char* p = command;
      while (true) {
        while (*p == ' ') p++;
        if (*p == 0) break;
        const char* word = p;
        while (*p != 0 && *p != ' ') p++;
        if (memchr(word, ':', p - word) != nullptr) continue;   // a set
        int page = showPage(word, p - word);
        if (page > 0) {
          if (page > last_page) last_page = page;
          int first = (page - 1) * HOP_POLICY_PAGE_ENTRIES;
          for (int i = first; i < first + HOP_POLICY_PAGE_ENTRIES && i < HOP_POLICY_ENTRIES; i++) {
            n = addValue(reply, n, i, true, more);
          }
        } else {
          n = addValue(reply, n, findEntry(word, p - word), false, more);
        }
      }
      if (more > 0) sprintf(&reply[n], " +%d more", more);
      if (last_page > 0 && last_page < HOP_POLICY_PAGES) strcat(reply, "\n...");   // more on the next page
    }
  }

private:
  // Parses words into 'max_hops': "name:max" sets an entry (marked in 'named'), "name" / show<p> is a show
  // (any_show). Returns nullptr, or an error message naming the bad word.
  static const char* parse(const char* config, uint8_t* max_hops, bool* named, bool& any_show) {
    static char err[48];
    const char* p = config;
    while (true) {
      while (*p == ' ') p++;   // skip spaces between words
      if (*p == 0) break;

      const char* word = p;
      while (*p != 0 && *p != ' ' && *p != ':') p++;
      int name_len = p - word;
      if (*p != ':' && showPage(word, name_len) != 0) {   // show<p>
        any_show = true;
        continue;
      }
      int i = findEntry(word, name_len);
      if (i < 0) {
        snprintf(err, sizeof(err), "unknown entry %.*s", name_len, word);
        return err;
      }

      if (*p == ':') {   // set
        p++;   // skip the ':'
        const char* v = p;
        while (*p != 0 && *p != ' ') p++;
        if (!parseMax(v, p - v, max_hops[i])) {
          snprintf(err, sizeof(err), "bad max for %s, 0-64 or -", getEntry(i)->name);
          return err;
        }
        named[i] = true;
      } else {           // show
        any_show = true;
      }
    }
    return nullptr;
  }

  // Takes the limits parsed by parse(), and resets the match counts of the entries that were set.
  void apply(const uint8_t* max_hops, const bool* named) {
    for (int i = 0; i < HOP_POLICY_ENTRIES; i++) {
      _max_hops[i] = max_hops[i];
      if (named[i]) _match_counts[i] = 0;
    }
  }

  // Writes a limit: the number, or '-' for none. Returns the length.
  static int formatMax(char* dest, uint8_t max_hops) {
    if (max_hops == HOP_POLICY_NONE) return sprintf(dest, "-");
    return sprintf(dest, "%d", max_hops);
  }

  // the page number of a "show<p>" word ('len' characters), or 0
  static int showPage(const char* word, int len) {
    if (len < 5 || len > 6 || memcmp(word, "show", 4) != 0) return 0;
    int page = 0;
    for (int i = 4; i < len; i++) {
      if (word[i] < '0' || word[i] > '9') return 0;
      page = page * 10 + (word[i] - '0');
    }
    if (page < 1 || page > HOP_POLICY_PAGES) return 0;
    return page;
  }

  // true if any word of 'command' is a show page
  static bool hasShowPage(const char* command) {
    const char* p = command;
    while (true) {
      while (*p == ' ') p++;
      if (*p == 0) return false;
      const char* word = p;
      while (*p != 0 && *p != ' ') p++;
      if (showPage(word, p - word) != 0) return true;
    }
  }

  // Adds "name:max" for entry 'i' at reply[n] (page: an aligned "entry name match_count" line), or counts
  // it in 'more' if the reply would get too long. Returns the length.
  int addValue(char* reply, int n, int i, bool page, int& more) const {
    char item[40];
    int len;
    if (page) {   // "entry name match_count", aligned
      len = sprintf(item, "%2d %-*s %lu", i, HOP_POLICY_NAME_LEN, getEntry(i)->name, (unsigned long)_match_counts[i]);
    } else {
      len = sprintf(item, "%s:", getEntry(i)->name);
      len += formatMax(&item[len], _max_hops[i]);
    }
    if (n + 1 + len > TABLE_REPLY_MAX) {
      more++;
      return n;
    }
    if (n > 0) {
      if (page) {
        reply[n++] = '\n';
      } else {
        reply[n++] = ' ';
      }
    }
    strcpy(&reply[n], item);
    return n + len;
  }

  // true if entry 'e' applies to the packet: the packet's property equals the entry's value
  static bool appliesTo(const HopPolicyEntry* e, const mesh::Packet* packet) {
    if (e->property == HOP_POLICY_ROUTE_TYPE) return packet->getRouteType() == e->value;
    if (e->property == HOP_POLICY_ROUTE_BYTES) return packet->getPathHashSize() == e->value;
    if (e->property == HOP_POLICY_PACKET_TYPE) return packet->getPayloadType() == e->value;
    return false;
  }

  // a limit: 0-64, or '-' for none (HOP_POLICY_NONE). 'out' is unchanged if it isn't valid.
  static bool parseMax(const char* s, int len, uint8_t& out) {
    if (len == 1 && s[0] == '-') {
      out = HOP_POLICY_NONE;
      return true;
    }
    if (len < 1 || len > 2) return false;
    int v = 0;
    for (int i = 0; i < len; i++) {
      if (s[i] < '0' || s[i] > '9') return false;
      v = v * 10 + (s[i] - '0');
    }
    if (v > HOP_POLICY_MAX_HOPS) return false;
    out = v;
    return true;
  }
};
