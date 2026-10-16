#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "TableFile.h"
#include "TableCli.h"

// Route policy, for firewall rules with tl:routepol: routes of 1-4 repeater hashes that a flood packet's path
// must contain, back to back and in order, at the path's start (near the sender, can be faked), end (our side)
// or anywhere. An entry hash matches a path hash it is the start of (9e matches 9e, 9e12...).
// Loaded at boot from ROUTE_POLICY_FILE, or ROUTE_POLICY_DEFAULT_ROUTES if nothing is saved.

#ifndef ROUTE_POLICY_MAX_ROUTES
  #define ROUTE_POLICY_MAX_ROUTES    32
#endif

#define ROUTE_POLICY_MAX_HASHES      4    // most repeater hashes in one entry's route
#define ROUTE_POLICY_MAX_HASH_SIZE   3    // most bytes per repeater hash
#define ROUTE_POLICY_NAME_LEN        8    // max characters in a route name

// CLI (handleCommand())
#define ROUTE_POLICY_PAGE_SLOTS      6    // slots per 'routepol show<p>' page (as FIREWALL_PAGE_SLOTS)
#define ROUTE_POLICY_COMMAND_MAX     160  // longest 'routepol' command

#define ROUTE_POLICY_FILE  "/route_pol_v1"   // saved routes: one "<n> - <config>" line per route (a new format: _v2)

// Default routes (as FIREWALL_DEFAULT_RULES): set() configs, into slots 0, 1, 2... nullptr ends the list. Example:
//   "nm:north rh:9e,4c ps:end",
//   "nm:town   rh:b7    ps:start",
static const char* const ROUTE_POLICY_DEFAULT_ROUTES[] = {
  nullptr
};

// RoutePolicyEntry::position: where in the path the entry's route must be
#define ROUTE_POLICY_ANYWHERE        0
#define ROUTE_POLICY_START           1
#define ROUTE_POLICY_END             2

struct RoutePolicyEntry {
  char    name[ROUTE_POLICY_NAME_LEN + 1];   // route name, null-terminated, empty = no name
  // the route's hashes, back to back, in the order the packet passes them (unused bytes 0)
  uint8_t hashes[ROUTE_POLICY_MAX_HASHES * ROUTE_POLICY_MAX_HASH_SIZE];
  uint8_t hash_size;    // bytes per hash: 1, 2 or 3
  uint8_t hash_count;   // repeaters in this route: 1-4, 0 = unused
  uint8_t position;     // ROUTE_POLICY_START, _END or _ANYWHERE: where in the path the route must be
};
static_assert(sizeof(RoutePolicyEntry) == 24, "route policy entry must stay 24 bytes");

class RoutePolicy : private TableCli {
  RoutePolicyEntry _entries[ROUTE_POLICY_MAX_ROUTES];   // entries in slot order, empty slots (hash_count 0) anywhere
  uint32_t _match_counts[ROUTE_POLICY_MAX_ROUTES];        // per slot: times the route made a firewall rule act
  FILESYSTEM* _fs;                                  // where the routes are saved, set by begin()

public:
  RoutePolicy(): _entries(), _match_counts(), _fs(nullptr) { }   // zero-filled: every slot starts empty

  // At boot (from FirewallTable::begin()): loads the saved routes, or the defaults.
  void begin(FILESYSTEM* fs) {
    _fs = fs;
    if (fs->exists(ROUTE_POLICY_FILE)) {
      const char* err = load();   // falls back to the defaults if it fails
      if (err != nullptr) MESH_DEBUG_PRINTLN("RoutePolicy: saved routes not loaded (%s), using the defaults", err);
    } else {
      loadDefaults();
    }
  }

  // Saves the routes to ROUTE_POLICY_FILE (not the match counts). Returns the number saved, or -1 if it failed.
  int save() {
    if (_fs == nullptr) return -1;
    File file = tableFileOpenWrite(_fs, ROUTE_POLICY_FILE);
    if (!file) return -1;
    char line[ROUTE_POLICY_COMMAND_MAX];
    int count = 0;
    bool ok = true;
    for (int i = 0; i < ROUTE_POLICY_MAX_ROUTES && ok; i++) {
      if (getEntry(i) == nullptr) continue;
      formatLine(i, line);
      ok = tableFileWriteLine(file, line);
      count++;
    }
    file.close();
    if (!ok) return -1;
    return count;
  }

  // Replaces the routes with the saved ones. If the file can't be read or a line fails, loads the defaults
  // instead (nothing changes if nothing is saved). Returns nullptr, or an error message.
  const char* load() {
    static char err[64];
    if (_fs == nullptr) return "no storage";
    if (!_fs->exists(ROUTE_POLICY_FILE)) return "nothing saved";
    File file = tableFileOpenRead(_fs, ROUTE_POLICY_FILE);
    if (!file) {
      loadDefaults();
      return "can't open the saved routes";
    }
    clear();

    char line[ROUTE_POLICY_COMMAND_MAX + 1];
    int line_number = 0;
    bool too_long;
    const char* fail = nullptr;
    while (tableFileReadLine(file, line, ROUTE_POLICY_COMMAND_MAX, too_long)) {
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
      if (number < 0 || number >= ROUTE_POLICY_MAX_ROUTES) {
        fail = "bad route number";
        break;
      }
      if (*p == '-' && (p[1] == 0 || p[1] == ' ')) {
        p++;
        while (*p == ' ') p++;
      }
      fail = set(number, true, p);
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

  // Sets route 'number' from 'config' (as FirewallTable::set()): nm:<name, 8>, rh:<1-4 hashes of 1-3 bytes,
  // eg. 9e,4c>, ps:<start|end|any, default any>. An entry needs rh, and can't repeat another slot's. All or nothing.
  // Returns nullptr, or an error message.
  const char* set(int number, bool reset, const char* config) {
    if (number < 0 || number >= ROUTE_POLICY_MAX_ROUTES) return "bad route number";

    RoutePolicyEntry e;   // parsed into a copy, written to the slot only if all fields are valid
    if (reset) {
      e = RoutePolicyEntry();
    } else {
      e = _entries[number];
    }

    bool any_field = false;
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
      any_field = true;

      if (isKey(field, "nm")) {          // name
        if (v_len == 1 && v[0] == '-') {
          e.name[0] = 0;
        } else {
          if (v_len > ROUTE_POLICY_NAME_LEN) return "bad nm value, up to 8 characters";
          for (int i = 0; i < v_len; i++) e.name[i] = v[i];
          e.name[v_len] = 0;
        }

      } else if (isKey(field, "rh")) {   // route hashes
        if (!parseHashes(v, v_len, e)) return "bad rh value, 1-4 hashes of 2, 4 or 6 hex digits, eg. 9e,4c";

      } else if (isKey(field, "ps")) {   // position
        if (isWord(v, v_len, "start")) {
          e.position = ROUTE_POLICY_START;
        } else if (isWord(v, v_len, "end")) {
          e.position = ROUTE_POLICY_END;
        } else if (isWord(v, v_len, "any")) {
          e.position = ROUTE_POLICY_ANYWHERE;
        } else {
          return "bad ps value, start, end or any";
        }

      } else {
        return unknownField(field);
      }
    }

    if (e.hash_count == 0) {
      if (any_field) return "rh needed";
      _entries[number] = RoutePolicyEntry();   // reset with an empty config: empty slot
      _match_counts[number] = 0;
      return nullptr;
    }
    int other = find(e.hashes, e.hash_size, e.hash_count, e.position);
    if (other >= 0 && other != number) return "route already in another slot";

    _entries[number] = e;
    if (reset) _match_counts[number] = 0;
    return nullptr;
  }

  // Returns the slot of the first route in the packet's path (flood packets), or -1. A 0-hop path matches none.
  int findMatch(const uint8_t* path, uint8_t path_hash_size, uint8_t path_hash_count) const {
    for (int i = 0; i < ROUTE_POLICY_MAX_ROUTES; i++) {
      const RoutePolicyEntry* e = &_entries[i];
      if (e->hash_count == 0) continue;                 // empty slot
      if (e->hash_size > path_hash_size) continue;     // path hashes too short to compare
      if (e->hash_count > path_hash_count) continue;    // path too short for the route
      int last_start = path_hash_count - e->hash_count;   // last path index the route can start at

      if (e->position == ROUTE_POLICY_START) {
        if (routeAt(e, path, path_hash_size, 0)) return i;
      } else if (e->position == ROUTE_POLICY_END) {
        if (routeAt(e, path, path_hash_size, last_start)) return i;
      } else {   // anywhere
        for (int start = 0; start <= last_start; start++) {
          if (routeAt(e, path, path_hash_size, start)) return i;
        }
      }
    }
    return -1;
  }

  // Replaces all routes with ROUTE_POLICY_DEFAULT_ROUTES. A default that fails to parse is left empty (debug
  // builds print why).
  void loadDefaults() {
    clear();
    for (int i = 0; i < ROUTE_POLICY_MAX_ROUTES && ROUTE_POLICY_DEFAULT_ROUTES[i] != nullptr; i++) {
      const char* err = set(i, true, ROUTE_POLICY_DEFAULT_ROUTES[i]);
      if (err != nullptr) MESH_DEBUG_PRINTLN("RoutePolicy: default route %d: %s, left empty", i, err);
    }
  }

  // empties every slot
  void clear() {
    for (int i = 0; i < ROUTE_POLICY_MAX_ROUTES; i++) {
      _entries[i] = RoutePolicyEntry();
      _match_counts[i] = 0;
    }
  }

  // counts a match for slot 'i' (when a rule acts because of it)
  void addMatch(int i) {
    if (i >= 0 && i < ROUTE_POLICY_MAX_ROUTES) _match_counts[i]++;
  }

  // number of slots holding an entry
  int getCount() const {
    int n = 0;
    for (int i = 0; i < ROUTE_POLICY_MAX_ROUTES; i++) {
      if (_entries[i].hash_count != 0) n++;
    }
    return n;
  }

  // the entry in slot 'i' (0..ROUTE_POLICY_MAX_ROUTES-1), or nullptr if the slot is empty or out of range
  const RoutePolicyEntry* getEntry(int i) const {
    if (i < 0 || i >= ROUTE_POLICY_MAX_ROUTES) return nullptr;
    if (_entries[i].hash_count == 0) return nullptr;
    return &_entries[i];
  }

  // Writes the value of field 'key' (nm, rh, ps) of entry 'e', as set() takes it. Returns the length, or -1
  // (no name, or not a field).
  static int formatField(const RoutePolicyEntry* e, const char* key, char* dest) {
    if (isKey(key, "nm")) {
      if (e->name[0] == 0) return -1;
      return sprintf(dest, "%s", e->name);
    }
    if (isKey(key, "rh")) {
      int n = 0;
      for (int k = 0; k < e->hash_count; k++) {
        if (k > 0) dest[n++] = ',';
        for (int b = 0; b < e->hash_size; b++) {
          n += sprintf(&dest[n], "%02x", e->hashes[k * e->hash_size + b]);
        }
      }
      dest[n] = 0;
      return n;
    }
    if (isKey(key, "ps")) {
      if (e->position == ROUTE_POLICY_START) return sprintf(dest, "start");
      if (e->position == ROUTE_POLICY_END) return sprintf(dest, "end");
      return sprintf(dest, "any");
    }
    return -1;
  }

  // Writes entry 'number' as set() config, eg. "nm:north rh:9e,4c ps:end". Returns the length, 0 if the slot is
  // empty.
  int format(int number, char* dest) const {
    dest[0] = 0;
    const RoutePolicyEntry* e = getEntry(number);
    if (e == nullptr) return 0;

    int n = 0;
    if (e->name[0] != 0) n = sprintf(dest, "nm:%s ", e->name);
    n += sprintf(&dest[n], "rh:");
    n += formatField(e, "rh", &dest[n]);
    n += sprintf(&dest[n], " ps:");
    n += formatField(e, "ps", &dest[n]);
    return n;
  }

  // Writes every route as a command that recreates it ("routepol <n> - <config>"), one per line. For the serial
  // console ('routepol show'): too long for one reply.
  void printAll(Print& out) const {
    char line[ROUTE_POLICY_COMMAND_MAX + 8];
    for (int i = 0; i < ROUTE_POLICY_MAX_ROUTES; i++) {
      if (getEntry(i) == nullptr) continue;
      formatLine(i, line);   // "<n> - <config>", as in the saved file
      out.print("routepol ");
      out.print(line);
      out.print("\n");
    }
  }

  // CLI 'routepol': the same commands as 'fw' (see FirewallTable::handleCommand()), without insert / collapse.
  // 'routepol show' (every route, serial console only) is handled by MyMesh (printAll()). Show pages: "OK", then
  // aligned "slot name match_count" lines.
  void handleCommand(const char* command, char* reply) {
    while (*command == ' ') command++;

    if (*command == 0) {   // the slots in use
      int n = 0;
      for (int i = 0; i < ROUTE_POLICY_MAX_ROUTES; i++) {
        if (getEntry(i) == nullptr) continue;
        n = addSlotToList(reply, n, i);
      }
      if (n == 0) strcpy(reply, "none");

    } else if (strcmp(command, "clear") == 0) {
      clear();
      strcpy(reply, "OK - all routes cleared");

    } else if (strcmp(command, "setdefault") == 0) {
      loadDefaults();
      sprintf(reply, "OK - %d default routes loaded, not saved", getCount());

    } else if (strcmp(command, "save") == 0) {
      int count = save();
      if (count < 0) {
        strcpy(reply, "Err - save failed");
      } else {
        sprintf(reply, "OK - %d routes saved", count);
      }

    } else if (strcmp(command, "reload") == 0) {
      if (_fs == nullptr || !_fs->exists(ROUTE_POLICY_FILE)) {
        strcpy(reply, "Err - nothing saved, nothing changed");
        return;
      }
      const char* err = load();
      if (err != nullptr) {
        sprintf(reply, "Err - %s, defaults loaded (not saved)", err);
      } else {
        sprintf(reply, "OK - %d routes loaded", getCount());
      }

    } else if (strcmp(command, "unsave") == 0) {   // remove the saved routes, so the defaults load at boot
      if (_fs == nullptr || !_fs->exists(ROUTE_POLICY_FILE)) {
        strcpy(reply, "OK - nothing saved");
      } else if (!_fs->remove(ROUTE_POLICY_FILE)) {
        strcpy(reply, "Err - remove failed");
      } else {
        strcpy(reply, "OK - saved routes removed, defaults load at boot (or routepol setdefault)");
      }

    } else if (memcmp(command, "show", 4) == 0) {   // a page of slots
      const char* p = &command[4];
      int page = parseSlotNumber(p);
      int first = (page - 1) * ROUTE_POLICY_PAGE_SLOTS;
      if (page < 1 || first >= ROUTE_POLICY_MAX_ROUTES || *p != 0) {
        sprintf(reply, "Err - use: routepol show<1-%d>",
                (ROUTE_POLICY_MAX_ROUTES + ROUTE_POLICY_PAGE_SLOTS - 1) / ROUTE_POLICY_PAGE_SLOTS);
        return;
      }
      // "OK" (keeps the lines left-aligned in clients that put a prompt before the first line), then one line per
      // route: slot, name, match count
      int n = sprintf(reply, "OK");
      int more = 0;
      int shown = 0;
      for (int i = first; i < first + ROUTE_POLICY_PAGE_SLOTS && i < ROUTE_POLICY_MAX_ROUTES; i++) {
        const RoutePolicyEntry* e = getEntry(i);
        if (e == nullptr) continue;
        const char* name = e->name;
        if (name[0] == 0) name = "?";
        char item[32];
        int len = sprintf(item, "%2d %-*s %lu", i, ROUTE_POLICY_NAME_LEN, name, (unsigned long)_match_counts[i]);
        n = addLine(reply, n, item, len, more);
        shown++;
      }
      if (shown == 0 && more == 0) {
        strcpy(reply, "none");
      } else if (more > 0) {
        sprintf(&reply[n], "\n+%d more", more);
      }
      // "..." on its own line: a later page has routes
      for (int i = first + ROUTE_POLICY_PAGE_SLOTS; i < ROUTE_POLICY_MAX_ROUTES; i++) {
        if (getEntry(i) != nullptr) {
          strcat(reply, "\n...");
          break;
        }
      }

    } else {   // one slot
      const char* p = command;
      int number = parseSlotNumber(p);
      if (number < 0 || number >= ROUTE_POLICY_MAX_ROUTES) {
        sprintf(reply, "Err - use: routepol [<0-%d> [-] [key:value|key ...]]|show<p>|clear|setdefault|save|reload|unsave", ROUTE_POLICY_MAX_ROUTES - 1);
        return;
      }

      if (*p == 0) {   // no words: the whole entry
        formatRule(number, reply);
        return;
      }

      // check every word, and gather the sets into one set() config
      char config[ROUTE_POLICY_COMMAND_MAX + 1];
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
        } else if (len == 4 && memcmp(word, "show", 4) == 0) {   // show the whole entry
          any_show = true;
        } else if (memchr(word, ':', len) != nullptr) {   // a set: checked by set()
          if (config_len + len + 1 > ROUTE_POLICY_COMMAND_MAX) {
            strcpy(reply, "Err - command too long");
            return;
          }
          memcpy(&config[config_len], word, len);
          config_len += len;
          config[config_len++] = ' ';
        } else if (len == 2 && isShowKey(word)) {   // a show: nm, rh or ps
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
      const RoutePolicyEntry* e = getEntry(number);
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
        char item[64];
        int item_len;
        if (len == 4 && memcmp(word, "show", 4) == 0) {   // the whole entry
          item_len = formatRule(number, item);
        } else if (len != 2 || !isShowKey(word)) {        // a set or '-'
          continue;
        } else {
          item_len = sprintf(item, "%.2s:", word);
          int v = -1;
          if (e != nullptr) v = formatField(e, word, &item[item_len]);
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

  // Writes entry 'number' as its config, or "-" if the slot is empty (the slot number is in the command). Returns
  // the length.
  int formatRule(int number, char* dest) const {
    int n = format(number, dest);
    if (n == 0) n = sprintf(dest, "-");
    return n;
  }

  // Writes entry 'number' as "<n> - <config>" ("<n> -" if empty): "routepol " + that recreates it.
  int formatLine(int number, char* dest) const {
    int n = sprintf(dest, "%d -", number);
    if (getEntry(number) == nullptr) return n;
    dest[n++] = ' ';
    n += format(number, &dest[n]);
    return n;
  }

  // true if the 2 letters at 'key' are an entry field key (nm, rh, ps)
  static bool isShowKey(const char* key) {
    return isKey(key, "nm") || isKey(key, "rh") || isKey(key, "ps");
  }

  // one hex digit, or -1
  static int hexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  }

  // rh value: 1-4 hashes of 2, 4 or 6 hex digits (all the same), separated by ','. e is unchanged if invalid.
  static bool parseHashes(const char* s, int len, RoutePolicyEntry& e) {
    uint8_t hashes[sizeof(e.hashes)] = { 0 };
    int hash_size = 0;
    int hash_count = 0;
    int i = 0;
    while (true) {
      // one hash, up to the next ',' or the end
      int start = i;
      while (i < len && s[i] != ',') i++;
      int digits = i - start;
      if (digits != 2 && digits != 4 && digits != 6) return false;
      if (hash_size == 0) {
        hash_size = digits / 2;
      } else if (digits / 2 != hash_size) {
        return false;   // hashes must all be the same size
      }
      if (hash_count >= ROUTE_POLICY_MAX_HASHES) return false;   // too many hashes
      for (int b = 0; b < hash_size; b++) {
        int hi = hexDigit(s[start + b * 2]);
        int lo = hexDigit(s[start + b * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        hashes[hash_count * hash_size + b] = (uint8_t)((hi << 4) | lo);
      }
      hash_count++;

      if (i >= len) break;   // end of the value
      i++;                   // skip the ','
    }

    for (int b = 0; b < (int)sizeof(e.hashes); b++) e.hashes[b] = hashes[b];
    e.hash_size = hash_size;
    e.hash_count = hash_count;
    return true;
  }

  // slot of the identical entry, or -1
  int find(const uint8_t* hashes, uint8_t hash_size, uint8_t hash_count, uint8_t position) const {
    int len = hash_count * hash_size;
    for (int i = 0; i < ROUTE_POLICY_MAX_ROUTES; i++) {
      const RoutePolicyEntry* e = &_entries[i];
      if (e->hash_count == 0) continue;   // empty slot
      if (e->hash_size != hash_size || e->hash_count != hash_count || e->position != position) continue;
      int j = 0;
      while (j < len && e->hashes[j] == hashes[j]) j++;
      if (j == len) return i;
    }
    return -1;
  }

  // true if the entry's route is in the path starting at path hash 'start'
  static bool routeAt(const RoutePolicyEntry* e, const uint8_t* path, uint8_t path_hash_size, int start) {
    for (int k = 0; k < e->hash_count; k++) {
      const uint8_t* entry_hash = &e->hashes[k * e->hash_size];
      const uint8_t* path_hash = &path[(start + k) * path_hash_size];
      for (int b = 0; b < e->hash_size; b++) {
        if (entry_hash[b] != path_hash[b]) return false;
      }
    }
    return true;
  }
};
