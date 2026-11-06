#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "TableFile.h"

// Backup mode (docs/backup_repeater.md): this repeater defers to up to 16 primary repeaters close by. It holds its
// flood-routed relays back for 'primary holdoff' times the packet's airtime
// (on top of the normal random delay), and doesn't relay a packet once a primary has been heard relaying it (its hash
// is the last one in the path): a queued relay is cancelled, a copy still waiting to be processed isn't relayed. A
// primary's own adverts (heard straight from it: empty path, its public key) aren't relayed either.
// Direct-routed packets aren't touched. On while the hold-off is above 0 (the default is 0: off) and a primary is
// set. Settings: 'primary' commands, in memory until 'primary save' (PRIMARY_FILE, loaded at boot).
// MyMesh only hooks it up: the relay delay, the send queue, allowPacketForward().
// Expects Mesh.h to be included first, as MyMesh.h does.

#define PRIMARY_FILE          "/primary_v1"  // saved settings: one command line each ("primary 0 cc12")
#define PRIMARY_SLOTS         16             // primary slots
#define PRIMARY_HASH_MAX      3              // primary hash bytes at most
#define PRIMARY_HOLDOFF_MAX   20             // hold-off at most: held relays use the shared packet pool
#define PRIMARY_RECENT        16             // packets a primary relayed, remembered for allowPacketForward()
#define PRIMARY_PAGE_SLOTS    6              // slots per 'primary show<p>' page (fits large counts, as fw)
#define PRIMARY_PAGES         ((PRIMARY_SLOTS + PRIMARY_PAGE_SLOTS - 1) / PRIMARY_PAGE_SLOTS)

#define PRIMARY_USAGE  "use: primary [<0-15> [<hash>|-]|holdoff [<0-20>]|save|unsave|reload|clearall|show<p>]"

class PrimaryRepeater {
  uint8_t _hash[PRIMARY_SLOTS][PRIMARY_HASH_MAX];     // 'primary <n>'
  uint8_t _hash_len[PRIMARY_SLOTS];                   // its bytes, 0 = empty
  uint8_t _holdoff;                                   // 'primary holdoff': times the packet's airtime, 0 = off
  uint32_t _skipped_since_boot[PRIMARY_SLOTS];        // relays skipped since boot (or the slot's hash changed)
  uint8_t _recent[PRIMARY_RECENT][MAX_HASH_SIZE];     // packet hashes of the newest primary relays heard: a ring
  int8_t _recent_slot[PRIMARY_RECENT];                // the primary that relayed each, -1 = unused
  int _recent_next;
  FILESYSTEM* _fs;

public:
  PrimaryRepeater(): _holdoff(0), _recent_next(0), _fs(nullptr) {
    memset(_hash, 0, sizeof(_hash));
    memset(_hash_len, 0, sizeof(_hash_len));
    memset(_skipped_since_boot, 0, sizeof(_skipped_since_boot));
    memset(_recent, 0, sizeof(_recent));
    memset(_recent_slot, -1, sizeof(_recent_slot));
  }

  // At boot: loads the saved settings, or keeps the defaults (off).
  void begin(FILESYSTEM* fs) {
    _fs = fs;
    if (fs->exists(PRIMARY_FILE)) load();
  }

  // true while the hold-off is above 0 and a primary is set
  bool isActive() const {
    if (_holdoff == 0) return false;
    for (int i = 0; i < PRIMARY_SLOTS; i++) {
      if (_hash_len[i] > 0) return true;
    }
    return false;
  }

  // From MyMesh::getRetransmitDelay(): the hold-off (ms) to add for 'packet', 'airtime' ms long: only a flood-routed
  // relay of ours (our hash 'self' last in the path), while active. Otherwise 0.
  uint32_t getHoldoff(const mesh::Packet* packet, const mesh::Identity& self, uint32_t airtime) const {
    if (!isActive() || !isOurRelay(packet, self)) return 0;
    return (uint32_t)_holdoff * airtime;
  }

  // true if 'packet' is a flood-routed relay of ours: our hash 'self' last in the path
  static bool isOurRelay(const mesh::Packet* packet, const mesh::Identity& self) {
    uint8_t n = packet->getPathHashCount();
    if (!packet->isRouteFlood() || n == 0) return false;
    uint8_t size = packet->getPathHashSize();
    return self.isHashMatch(&packet->path[(n - 1) * size], size);
  }

  // From MyMesh::logRx(), for every packet heard: true if it's a flood-routed relay by a primary (while active).
  // Then remembers its packet hash ('hash' gets it), for wasRelayedByPrimary().
  bool notePrimaryRelay(const mesh::Packet* packet, uint8_t* hash) {
    if (!packet->isRouteFlood() || !isActive()) return false;
    int slot = findPrimary(packet);
    if (slot < 0) return false;
    packet->calculatePacketHash(hash);
    memcpy(_recent[_recent_next], hash, MAX_HASH_SIZE);
    _recent_slot[_recent_next] = slot;
    _recent_next = (_recent_next + 1) % PRIMARY_RECENT;
    return true;
  }

  // From MyMesh::logRx(): our queued relay of the packet 'hash' was cancelled. Counts it for the primary that relayed
  // it (MyMesh counts it in the stats history).
  void countCancelled(const uint8_t* hash) {
    int i = findRecent(hash);
    if (i >= 0) countSkipped(_recent_slot[i]);
  }

  // From MyMesh::allowPacketForward(): true if a primary has already been heard relaying 'packet', or it's a
  // primary's own advert (then counted for that primary; MyMesh counts it in the stats history), so it isn't relayed.
  bool wasRelayedByPrimary(const mesh::Packet* packet) {
    if (!packet->isRouteFlood() || !isActive()) return false;
    int slot = findPrimaryAdvert(packet);
    if (slot >= 0) {
      countSkipped(slot);
      return true;
    }
    uint8_t hash[MAX_HASH_SIZE];
    packet->calculatePacketHash(hash);
    int i = findRecent(hash);
    if (i < 0) return false;
    countSkipped(_recent_slot[i]);
    return true;
  }

  // 'primary show' on the serial console: the header, then every slot in use (as the show pages), or "no primaries"
  void printAll(Print& out) const {
    char line[40];
    formatHeader(line);
    out.print(line);
    out.print("\n");
    bool any = false;
    for (int i = 0; i < PRIMARY_SLOTS; i++) {
      if (_hash_len[i] == 0) continue;
      formatSlotLine(i, line);
      out.print(line);
      out.print("\n");
      any = true;
    }
    if (!any) out.print("no primaries\n");
  }

  // CLI 'primary [<args>]', from MyMesh (trailing spaces trimmed): 'args' is what follows 'primary'.
  //   primary                  "on" / "off" (hold-off above 0 and a primary set), then the slots in use, eg.
  //                            "on 0:cc12 1:ab"
  //   primary <n> [<hash>|-]   shows slot n (0-15): "cc12 1234", hash and relays skipped since boot ("-" if empty),
  //                            or sets it to a 1-3 byte hash, or clears it (-)
  //   primary holdoff [<n>]    shows or sets the hold-off: 0 (off) or 1-20 times the packet's airtime
  //   primary save | unsave | reload    saves to / removes / loads again PRIMARY_FILE (changes stay in memory until
  //                            saved; unsave keeps the current settings until a reboot)
  //   primary clearall         empties every slot (the hold-off stays), not saved
  //   primary show             every slot in use, serial console only: handled by MyMesh (printAll())
  //   primary show<p>          page p of PRIMARY_PAGE_SLOTS slots: "primary on holdoff=10" / "primary off ...",
  //                            then "slot hash skipped" lines (relays skipped since boot) for the slots in use
  // A slot's count goes back to 0 when its hash changes.
  void handleCommand(const char* args, char* reply) {
    while (*args == ' ') args++;
    if (*args == 0) {   // 'primary': on or off, and the slots in use
      int n;
      if (isActive()) {
        n = sprintf(reply, "on");
      } else {
        n = sprintf(reply, "off");
      }
      for (int i = 0; i < PRIMARY_SLOTS; i++) {
        if (_hash_len[i] == 0) continue;
        n += sprintf(&reply[n], " %d:", i);
        n += formatHash(i, &reply[n]);
      }
      return;
    }
    const char* word = args;
    while (*args != 0 && *args != ' ') args++;
    int word_len = args - word;
    while (*args == ' ') args++;
    const char* value = args;

    if (*value != 0) {   // a setting, in memory only
      uint8_t old_hash[PRIMARY_SLOTS][PRIMARY_HASH_MAX], old_len[PRIMARY_SLOTS];
      keepSlots(old_hash, old_len);
      const char* err = set(word, word_len, value);
      resetChangedCounts(old_hash, old_len);
      if (err != nullptr) {
        sprintf(reply, "Err - %s", err);
      } else {
        strcpy(reply, "OK");
      }
    } else if (isWord(word, word_len, "save")) {
      if (save()) {
        strcpy(reply, "OK - saved");
      } else {
        strcpy(reply, "Err - save failed");
      }
    } else if (isWord(word, word_len, "unsave")) {   // remove the saved settings: off at boot
      if (_fs == nullptr || !_fs->exists(PRIMARY_FILE)) {
        strcpy(reply, "OK - nothing saved");
      } else if (!_fs->remove(PRIMARY_FILE)) {
        strcpy(reply, "Err - remove failed");
      } else {
        strcpy(reply, "OK - saved settings removed, off at boot");
      }
    } else if (isWord(word, word_len, "reload")) {
      if (_fs == nullptr || !_fs->exists(PRIMARY_FILE)) {
        strcpy(reply, "Err - nothing saved, nothing changed");
      } else if (!load()) {
        strcpy(reply, "Err - load failed, nothing changed");
      } else {
        strcpy(reply, "OK - saved settings loaded");
      }
    } else if (isWord(word, word_len, "clearall")) {
      uint8_t old_hash[PRIMARY_SLOTS][PRIMARY_HASH_MAX], old_len[PRIMARY_SLOTS];
      keepSlots(old_hash, old_len);
      memset(_hash_len, 0, sizeof(_hash_len));
      resetChangedCounts(old_hash, old_len);
      strcpy(reply, "OK - all slots cleared, not saved");
    } else if (word_len >= 4 && memcmp(word, "show", 4) == 0) {   // a page of slots
      int page = parseSlot(&word[4], word_len - 4);   // -1 if it isn't a number
      if (page < 1 || page > PRIMARY_PAGES) {
        sprintf(reply, "Err - use: primary show<1-%d>", PRIMARY_PAGES);
      } else {
        formatPage((page - 1) * PRIMARY_PAGE_SLOTS, reply);
      }
    } else if (isWord(word, word_len, "holdoff")) {
      sprintf(reply, "%d", _holdoff);
    } else if (word[0] < '0' || word[0] > '9') {
      strcpy(reply, "Err - " PRIMARY_USAGE);
    } else {   // 'primary <n>': shows the slot
      int slot = parseSlot(word, word_len);
      if (slot < 0) {
        strcpy(reply, "Err - slot is 0-15");
      } else if (_hash_len[slot] == 0) {
        strcpy(reply, "-");
      } else {
        formatHashAndCount(slot, reply);
      }
    }
  }

private:
  // the primary slot whose hash is 'packet's last path hash, or -1. Compared over the shorter of the two.
  int findPrimary(const mesh::Packet* packet) const {
    uint8_t n = packet->getPathHashCount();
    if (n == 0) return -1;
    uint8_t size = packet->getPathHashSize();
    const uint8_t* last = &packet->path[(n - 1) * size];
    for (int i = 0; i < PRIMARY_SLOTS; i++) {
      if (_hash_len[i] == 0) continue;
      uint8_t len = _hash_len[i];
      if (len > size) len = size;
      if (memcmp(last, _hash[i], len) == 0) return i;
    }
    return -1;
  }

  // the primary slot whose hash starts the public key of 'packet', if it's an advert heard straight from its sender
  // (empty path), or -1
  int findPrimaryAdvert(const mesh::Packet* packet) const {
    if (packet->getPayloadType() != PAYLOAD_TYPE_ADVERT || packet->getPathHashCount() != 0
        || packet->payload_len < PUB_KEY_SIZE) return -1;
    for (int i = 0; i < PRIMARY_SLOTS; i++) {
      if (_hash_len[i] > 0 && memcmp(packet->payload, _hash[i], _hash_len[i]) == 0) return i;
    }
    return -1;
  }

  // the _recent entry holding packet hash 'hash', or -1
  int findRecent(const uint8_t* hash) const {
    for (int i = 0; i < PRIMARY_RECENT; i++) {
      if (_recent_slot[i] >= 0 && memcmp(_recent[i], hash, MAX_HASH_SIZE) == 0) return i;
    }
    return -1;
  }

  // counts a skipped relay for primary 'slot', stopping at the maximum
  void countSkipped(int slot) {
    if (_skipped_since_boot[slot] < 0xFFFFFFFF) _skipped_since_boot[slot]++;
  }

  // copies the slots, for resetChangedCounts()
  void keepSlots(uint8_t old_hash[PRIMARY_SLOTS][PRIMARY_HASH_MAX], uint8_t old_len[PRIMARY_SLOTS]) const {
    memcpy(old_hash, _hash, sizeof(_hash));
    memcpy(old_len, _hash_len, sizeof(_hash_len));
  }

  // sets the count of every slot whose hash isn't the same as in the copy back to 0
  void resetChangedCounts(const uint8_t old_hash[PRIMARY_SLOTS][PRIMARY_HASH_MAX],
                          const uint8_t old_len[PRIMARY_SLOTS]) {
    for (int i = 0; i < PRIMARY_SLOTS; i++) {
      if (_hash_len[i] != old_len[i] || memcmp(_hash[i], old_hash[i], _hash_len[i]) != 0) {
        _skipped_since_boot[i] = 0;
      }
    }
  }

  // Writes slot 'slot's hash, lowercase hex. Returns the length.
  int formatHash(int slot, char* dest) const {
    int n = 0;
    for (int i = 0; i < _hash_len[slot]; i++) n += sprintf(&dest[n], "%02x", _hash[slot][i]);
    return n;
  }

  // 'primary show<p>': the header, then the slots in use from slot 'first' (PRIMARY_PAGE_SLOTS slots), or the page's
  // range if none are ("no primaries 6-11"). Then "..." on its own line if a later page has slots in use (as fw).
  void formatPage(int first, char* reply) const {
    int last = first + PRIMARY_PAGE_SLOTS - 1;
    if (last >= PRIMARY_SLOTS) last = PRIMARY_SLOTS - 1;
    int n = formatHeader(reply);
    bool any = false;
    for (int i = first; i <= last; i++) {
      if (_hash_len[i] == 0) continue;
      reply[n++] = '\n';
      n += formatSlotLine(i, &reply[n]);
      any = true;
    }
    if (!any) n = sprintf(reply, "no primaries %d-%d", first, last);
    for (int i = last + 1; i < PRIMARY_SLOTS; i++) {
      if (_hash_len[i] > 0) {
        strcpy(&reply[n], "\n...");
        break;
      }
    }
  }

  // "primary on holdoff=10" / "primary off holdoff=10". Returns the length.
  int formatHeader(char* dest) const {
    if (isActive()) return sprintf(dest, "primary on holdoff=%d", _holdoff);
    return sprintf(dest, "primary off holdoff=%d", _holdoff);
  }

  // "<slot> <hash> <skipped since boot>", a show page line. Returns the length.
  int formatSlotLine(int slot, char* dest) const {
    int n = sprintf(dest, "%d ", slot);
    return n + formatHashAndCount(slot, &dest[n]);
  }

  // "<hash> <skipped since boot>". Returns the length.
  int formatHashAndCount(int slot, char* dest) const {
    int n = formatHash(slot, dest);
    return n + sprintf(&dest[n], " %lu", (unsigned long)_skipped_since_boot[slot]);
  }

  // true if the 'len' chars at 'word' are 'name'
  static bool isWord(const char* word, int len, const char* name) {
    return (int)strlen(name) == len && memcmp(word, name, len) == 0;
  }

  // slot number 0-15 from 'len' chars, or -1
  static int parseSlot(const char* s, int len) {
    if (len < 1 || len > 2) return -1;
    int slot = 0;
    for (int i = 0; i < len; i++) {
      if (s[i] < '0' || s[i] > '9') return -1;
      slot = slot * 10 + (s[i] - '0');
    }
    if (slot >= PRIMARY_SLOTS) return -1;
    return slot;
  }

  // Sets one setting: 'key' ('key_len' chars) is 'holdoff' or a slot number, 'v' its value (a number; a hash or -),
  // trailing spaces trimmed. Doesn't touch the counts. Returns nullptr, or an error.
  const char* set(const char* key, int key_len, const char* v) {
    int v_len = strlen(v);
    while (v_len > 0 && v[v_len - 1] == ' ') v_len--;

    if (isWord(key, key_len, "holdoff")) {
      if (v_len < 1 || v_len > 2) return "holdoff is 0-20";
      int holdoff = 0;
      for (int i = 0; i < v_len; i++) {
        if (v[i] < '0' || v[i] > '9') return "holdoff is 0-20";
        holdoff = holdoff * 10 + (v[i] - '0');
      }
      if (holdoff > PRIMARY_HOLDOFF_MAX) return "holdoff is 0-20";
      _holdoff = holdoff;
      return nullptr;
    }
    if (key[0] < '0' || key[0] > '9') return PRIMARY_USAGE;
    int slot = parseSlot(key, key_len);
    if (slot < 0) return "slot is 0-15";
    if (v_len == 1 && v[0] == '-') {
      _hash_len[slot] = 0;
      return nullptr;
    }
    if (v_len != 2 && v_len != 4 && v_len != 6) return "hash is 2, 4 or 6 hex digits";
    for (int i = 0; i < v_len; i++) {
      if (!mesh::Utils::isHexChar(v[i])) return "hash is 2, 4 or 6 hex digits";
    }
    char hex[PRIMARY_HASH_MAX * 2 + 1];
    memcpy(hex, v, v_len);
    hex[v_len] = 0;
    memset(_hash[slot], 0, PRIMARY_HASH_MAX);
    mesh::Utils::fromHex(_hash[slot], v_len / 2, hex);
    _hash_len[slot] = v_len / 2;
    return nullptr;
  }

  // Loads PRIMARY_FILE in place of the current settings (a bad line is skipped). False if it couldn't be opened
  // (nothing changed).
  bool load() {
    File file = tableFileOpenRead(_fs, PRIMARY_FILE);
    if (!file) return false;
    uint8_t old_hash[PRIMARY_SLOTS][PRIMARY_HASH_MAX], old_len[PRIMARY_SLOTS];
    keepSlots(old_hash, old_len);
    _holdoff = 0;
    memset(_hash_len, 0, sizeof(_hash_len));
    char line[40];
    bool too_long;
    while (tableFileReadLine(file, line, sizeof(line) - 1, too_long)) {
      if (!too_long) setFromLine(line);
    }
    file.close();
    resetChangedCounts(old_hash, old_len);
    return true;
  }

  // Sets one setting from a saved line, a command: "primary holdoff <n>" or "primary <n> <hash>". Anything else is
  // skipped.
  void setFromLine(const char* line) {
    if (memcmp(line, "primary ", 8) != 0) return;
    const char* key = &line[8];
    while (*key == ' ') key++;
    const char* v = key;
    while (*v != 0 && *v != ' ') v++;
    int key_len = v - key;
    while (*v == ' ') v++;
    if (key_len > 0 && *v != 0) set(key, key_len, v);
  }

  // Saves the hold-off and the slots in use to PRIMARY_FILE, as command lines. False if it failed.
  bool save() {
    if (_fs == nullptr) return false;
    File file = tableFileOpenWrite(_fs, PRIMARY_FILE);
    if (!file) return false;
    char line[40];
    sprintf(line, "primary holdoff %d", _holdoff);
    bool ok = tableFileWriteLine(file, line);
    for (int i = 0; i < PRIMARY_SLOTS && ok; i++) {
      if (_hash_len[i] == 0) continue;
      int n = sprintf(line, "primary %d ", i);
      formatHash(i, &line[n]);
      ok = tableFileWriteLine(file, line);
    }
    file.close();
    return ok;
  }
};
