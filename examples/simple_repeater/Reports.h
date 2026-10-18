#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "StatsHistory.h"
#include "TableFile.h"

// Reports and alerts on a channel (by default the #repeaters hashtag channel), sent scoped to one region:
// Replies (reports.enabled, off by default) and alerts (alerts.enabled, on by default) are switched separately:
//   'report'        every repeater with reports on replies (random 1-30 s delay), at most once per cooldown
//   'report <name>' only the repeater with that name (not case-sensitive) replies, after 1-3 s, no cooldown
//   alerts          battery low, RX airtime high, noise floor up: each after 2 completed stats slots in a row out of
//                   range, at most once per alerts cooldown, from 15 minutes after boot (noise floor: 1 hour)
// Only requests sent in the region, and relayed at most reports.hops.max times, are answered; replies and alerts are
// relayed at most that many times too. Settings: 'set' / 'get' reports.* and alerts.*, saved in REPORTS_FILE.
// MyMesh only hooks it up: the channel, creating and sending the packets, and the values only it has.
// Expects Mesh.h, RegionMap.h and Utils.h to be included first, as MyMesh.h does. Not built for STM32 (it needs
// the stats history).

#if !defined(STM32_PLATFORM)

#define REPORTS_FILE                 "/reports_v1"   // saved settings: one 'set' line each ("reports.enabled 1")

#ifndef REPORTS_DEFAULT_KEY
  #define REPORTS_DEFAULT_KEY        "89db441e2814dccf0dbd2e8cc5f501a3"   // #repeaters: sha256("#repeaters")[:16]
#endif
#ifndef REPORTS_DEFAULT_REGION
  #define REPORTS_DEFAULT_REGION     "us-va"
#endif

#define REPORTS_MAX_HOPS             8         // reports.hops.max at most
#define REPORTS_MAX_TEXT             150       // "<name>: <text>" in a channel message
#define REPORTS_REPLY_DELAY_MIN      1000      // 'report': random delay, so repeaters don't all reply at once (ms)
#define REPORTS_REPLY_DELAY_MAX      30000
#define REPORTS_NAMED_DELAY_MIN      1000      // 'report <name>': only one repeater replies (ms)
#define REPORTS_NAMED_DELAY_MAX      3000
#define REPORTS_ALERT_START_MILLIS   (15UL * 60 * 1000)   // no alerts this soon after boot, eg. boot loops
#define REPORTS_NOISEFLOOR_MIN_SLOTS 12        // noise floor alert: at least 1 hour of stats history first

// the settings, saved in REPORTS_FILE
struct ReportSettings {
  uint8_t  enabled;               // reports.enabled: replies to 'report' / 'report <name>'
  uint8_t  key[16];               // reports.channel.key: the channel's secret
  char     region[31];            // reports.channel.region: required, the scope of everything sent and answered
  uint8_t  hops_max;              // reports.hops.max: 0-REPORTS_MAX_HOPS
  uint16_t cooldown_mins;         // reports.cooldown: between replies to 'report', 15-1440
  uint8_t  alerts_enabled;        // alerts.enabled: the alerts
  uint8_t  alert_battery;         // alerts.battery: tenths of a volt, 0 = off
  uint8_t  alert_noisefloor;      // alerts.noisefloor: dB above the history's average, 0 = off
  uint8_t  alert_airtime;         // alerts.airtime: RX airtime %, 0 = off
  uint16_t alert_cooldown_mins;   // alerts.cooldown: between repeats of the same alert, 15-1440
};

class Reports {
  ReportSettings _s;
  FILESYSTEM* _fs;
  mesh::GroupChannel _channel;      // made from _s.key
  uint64_t _next_reply_millis;      // 'report' answered again from this uptime
  uint8_t _battery_low_count;       // slot ends in a row with the battery low
  uint64_t _next_battery_alert, _next_airtime_alert, _next_noisefloor_alert;   // uptime each may repeat from

public:
  Reports(): _fs(nullptr), _next_reply_millis(0), _battery_low_count(0), _next_battery_alert(0),
             _next_airtime_alert(0), _next_noisefloor_alert(0) {
    setDefaults();
  }

  // At boot: loads the saved settings, or keeps the defaults.
  void begin(FILESYSTEM* fs) {
    _fs = fs;
    if (!fs->exists(REPORTS_FILE)) return;
    File file = tableFileOpenRead(fs, REPORTS_FILE);
    if (!file) return;
    char line[80];
    bool too_long;
    while (tableFileReadLine(file, line, sizeof(line) - 1, too_long)) {
      if (!too_long && line[0] != 0) set(line, false);   // a bad line keeps that setting's default
    }
    file.close();
  }

  bool isEnabled() const { return _s.enabled; }
  uint8_t getHopsMax() const { return _s.hops_max; }
  const mesh::GroupChannel& getChannel() const { return _channel; }

  // the scope to send with and to require on requests: reports.channel.region's key from the region list, or else
  // its public hashtag key (as RegionMap does for '#' regions). False if there's none.
  bool getScope(RegionMap& regions, TransportKey& dest) const {
    if (_s.region[0] == 0) return false;
    RegionEntry* r = regions.findByName(_s.region);
    if (r && !r->isWildcard() && regions.getTransportKeysFor(*r, &dest, 1) > 0) return true;
    char tag[sizeof(_s.region) + 1];
    tag[0] = '#';
    strcpy(&tag[1], _s.region);
    mesh::Utils::sha256(dest.key, sizeof(dest.key), (const uint8_t *)tag, strlen(tag));
    return true;
  }

  // From MyMesh::searchChannelsByHash(): true if reports are on and 'hash' is the channel's
  bool isChannel(const uint8_t* hash) const {
    return _s.enabled && hash[0] == _channel.hash[0];
  }

  // From MyMesh::onGroupDataRecv(): true if this repeater should reply to the channel message ('data', 'len'
  // bytes: timestamp, flags, then "<sender>: <msg>"): plain text 'report' or 'report <node_name>', sent in the
  // region and relayed at most reports.hops.max times. 'delay_millis' is the reply delay; a 'report' reply starts the
  // cooldown.
  bool acceptRequest(const mesh::Packet* packet, uint8_t type, const uint8_t* data, size_t len, RegionMap& regions,
                     const char* node_name, mesh::RNG* rng, uint64_t uptime_millis, uint32_t& delay_millis) {
    if (type != PAYLOAD_TYPE_GRP_TXT || len <= 5 || (data[4] >> 2) != 0) return false;   // plain text only
    if (packet->getPathHashCount() > _s.hops_max) return false;
    TransportKey scope;
    if (packet->getRouteType() != ROUTE_TYPE_TRANSPORT_FLOOD || !getScope(regions, scope)
        || packet->transport_codes[0] != scope.calcTransportCode(packet)) return false;   // not sent in the region

    bool named;
    if (!isRequest((const char *)&data[5], len - 5, node_name, named)) return false;
    if (named) {
      delay_millis = rng->nextInt(REPORTS_NAMED_DELAY_MIN, REPORTS_NAMED_DELAY_MAX);
      return true;
    }
    if (uptime_millis < _next_reply_millis) return false;   // 'report' cooldown
    _next_reply_millis = uptime_millis + (uint64_t)_s.cooldown_mins * 60000;
    delay_millis = rng->nextInt(REPORTS_REPLY_DELAY_MIN, REPORTS_REPLY_DELAY_MAX);
    return true;
  }

  // The 'report' reply, 4 lines: firmware; uptime, battery (1 V or less: left out) and airtime (60m); noise floor
  // (60m), firewall drops (24h) and neighbours ('neighbours' < 0: left out); packets sent / received / with errors
  // (24h). Items without data yet (just after boot) are left out.
  void formatReport(char* text, size_t size, const char* version, uint64_t uptime_millis, uint16_t batt_mv,
                    int neighbours, const StatsHistory& stats) const {
    StatsHistory::StatsHistoryTotals hour, day;
    stats.sumNewest(12, hour);
    stats.sumNewest(STATS_HISTORY_SLOTS, day);
    uint32_t up_hours = (uint32_t)(uptime_millis / 3600000);
    int n = snprintf(text, size, "%s\n%lud%luh", version, (unsigned long)(up_hours / 24),
                     (unsigned long)(up_hours % 24));
    if (batt_mv > 1000 && n < (int)size) {
      n += snprintf(&text[n], size - n, ", %u.%02uV", batt_mv / 1000, (batt_mv % 1000) / 10);
    }
    if (hour.slots > 0 && n < (int)size) {
      n += snprintf(&text[n], size - n, ", air %d%%/%d%% (60m)", StatsHistory::average(hour.airtime_rx_sum, hour.slots),
                    StatsHistory::average(hour.airtime_tx_sum, hour.slots));
    }
    if (n < (int)size) n += snprintf(&text[n], size - n, "\n");
    if (hour.noisefloor_slots > 0 && n < (int)size) {
      n += snprintf(&text[n], size - n, "nf %d, ", StatsHistory::average(hour.noisefloor_sum, hour.noisefloor_slots));
    }
    if (n < (int)size) n += snprintf(&text[n], size - n, "fw %lu (24h)", (unsigned long)day.fw_drops);
    if (neighbours >= 0 && n < (int)size) n += snprintf(&text[n], size - n, ", nb %d", neighbours);
    if (n < (int)size) {
      snprintf(&text[n], size - n, "\ntx %lu, rx %lu, err %lu (24h)", (unsigned long)day.tx_packets,
               (unsigned long)day.rx_packets, (unsigned long)day.rx_errors);
    }
  }

  // Writes a channel message: 'timestamp', flags (plain text), then "<node_name>: <text>" (at most
  // REPORTS_MAX_TEXT). 'data' holds 5 + REPORTS_MAX_TEXT + 1. Returns its length.
  static int buildMessage(uint8_t* data, uint32_t timestamp, const char* node_name, const char* text) {
    memcpy(data, &timestamp, 4);   // also helps make the packet hash unique
    data[4] = 0;                   // TXT_TYPE_PLAIN
    int len = snprintf((char *)&data[5], REPORTS_MAX_TEXT + 1, "%s: %s", node_name, text);
    if (len < 0) len = 0;
    if (len > REPORTS_MAX_TEXT) len = REPORTS_MAX_TEXT;
    return 5 + len;
  }

  // Makes 'pkt' a flood scoped with 'scope' (as Mesh::sendFlood() does), its path pre-filled with dummy 3-byte
  // hashes so only reports.hops.max slots are left: every repeater (stock firmware too) stops forwarding it once
  // the path is full.
  void prepareToSend(mesh::Packet* pkt, const TransportKey& scope) const {
    const int slots = MAX_PATH_SIZE / 3;
    pkt->header &= ~PH_ROUTE_MASK;
    pkt->header |= ROUTE_TYPE_TRANSPORT_FLOOD;
    pkt->transport_codes[0] = scope.calcTransportCode(pkt);
    pkt->transport_codes[1] = 0;
    int pad = slots - _s.hops_max;
    if (pad < 0) pad = 0;
    memset(pkt->path, 0, pad * 3);
    pkt->setPathHashSizeAndCount(3, pad);
  }

  // From MyMesh::loop() when a stats slot has just been stored: checks the alerts. Writes up to 3 alert texts
  // (each up to 64 chars) and returns how many. 'batt_mv': the battery now (1 V or less: no battery sensing).
  int checkAlerts(uint64_t uptime_millis, uint16_t batt_mv, const StatsHistory& stats, char texts[3][64]) {
    int n = 0;
    if (!_s.alerts_enabled) return 0;

    // battery: low at 2 slot ends in a row
    if (_s.alert_battery > 0 && batt_mv > 1000 && batt_mv < _s.alert_battery * 100) {
      if (_battery_low_count < 255) _battery_low_count++;
    } else {
      _battery_low_count = 0;
    }
    if (uptime_millis < REPORTS_ALERT_START_MILLIS) return 0;
    uint64_t cooldown = (uint64_t)_s.alert_cooldown_mins * 60000;
    if (_battery_low_count >= 2 && uptime_millis >= _next_battery_alert) {
      sprintf(texts[n++], "ALERT battery low %u.%02uV", batt_mv / 1000, (batt_mv % 1000) / 10);
      _next_battery_alert = uptime_millis + cooldown;
    }

    // RX airtime: at or above the limit in the newest 2 slots
    const StatsHistorySlot* s0 = stats.getSlot(0);
    const StatsHistorySlot* s1 = stats.getSlot(1);
    if (_s.alert_airtime > 0 && s0 != nullptr && s1 != nullptr && s0->airtime_rx_percent >= _s.alert_airtime
        && s1->airtime_rx_percent >= _s.alert_airtime && uptime_millis >= _next_airtime_alert) {
      sprintf(texts[n++], "ALERT rx airtime high %u%% (5m)", s0->airtime_rx_percent);
      _next_airtime_alert = uptime_millis + cooldown;
    }

    // noise floor: the newest 2 slots at least alert_noisefloor dB above the average of the slots before them
    if (_s.alert_noisefloor > 0 && stats.getCount() >= REPORTS_NOISEFLOOR_MIN_SLOTS && s0 != nullptr
        && s1 != nullptr && s0->noisefloor_dbm != STATS_HISTORY_NOISEFLOOR_NONE
        && s1->noisefloor_dbm != STATS_HISTORY_NOISEFLOOR_NONE && uptime_millis >= _next_noisefloor_alert) {
      int32_t sum = 0;
      int slots = 0;
      for (int age = 2; age < stats.getCount(); age++) {
        int8_t nf = stats.getSlot(age)->noisefloor_dbm;
        if (nf == STATS_HISTORY_NOISEFLOOR_NONE) continue;
        sum += nf;
        slots++;
      }
      if (slots > 0) {
        int avg = StatsHistory::average(sum, slots);
        if (s0->noisefloor_dbm >= avg + _s.alert_noisefloor && s1->noisefloor_dbm >= avg + _s.alert_noisefloor) {
          sprintf(texts[n++], "ALERT noise floor up %ddB: %ddBm (24h avg %ddBm)", s0->noisefloor_dbm - avg,
                  s0->noisefloor_dbm, avg);
          _next_noisefloor_alert = uptime_millis + cooldown;
        }
      }
    }
    return n;
  }

  // CLI: 'set reports.* / alerts.* <value>' or 'get reports.* / alerts.*' ('get reports' / 'get alerts' list them).
  // Returns false if 'command' isn't one of these (the shared CLI handles it).
  bool handleCommand(const char* command, char* reply) {
    if (memcmp(command, "set ", 4) == 0 && isOurs(&command[4])) {
      const char* err = set(&command[4], true);
      if (err != nullptr) {
        sprintf(reply, "Err - %s", err);
      } else if (!save()) {
        strcpy(reply, "Err - set, but saving failed");
      } else {
        strcpy(reply, "OK");
      }
      return true;
    }
    if (memcmp(command, "get ", 4) == 0) {
      const char* key = &command[4];
      while (*key == ' ') key++;
      if (strcmp(key, "reports") == 0) {
        char hex[33];
        keyToHex(hex);
        sprintf(reply, "> enabled=%d key=%s region=%s hops=%d cooldown=%d", _s.enabled, hex, _s.region,
                _s.hops_max, _s.cooldown_mins);
        return true;
      }
      if (strcmp(key, "alerts") == 0) {
        sprintf(reply, "> enabled=%d battery=%d noisefloor=%d airtime=%d cooldown=%d", _s.alerts_enabled,
                _s.alert_battery, _s.alert_noisefloor,
                _s.alert_airtime, _s.alert_cooldown_mins);
        return true;
      }
      if (!isOurs(key)) return false;
      int n = sprintf(reply, "> ");
      if (formatValue(key, &reply[n]) < 0) strcpy(reply, "Err - unknown setting");
      return true;
    }
    return false;
  }

private:
  // true if channel text ("<sender>: <msg>", 'len' chars, maybe not null-terminated) is 'report', or
  // 'report <node_name>' (not case-sensitive, then 'named')
  static bool isRequest(const char* t, size_t len, const char* node_name, bool& named) {
    size_t i = 0;
    while (i + 1 < len && t[i] != 0 && !(t[i] == ':' && t[i + 1] == ' ')) i++;
    if (i + 1 >= len || t[i] != ':') return false;   // no "<sender>: "
    i += 2;
    while (i < len && t[i] == ' ') i++;
    size_t e = i;
    while (e < len && t[e] != 0) e++;
    while (e > i && (t[e - 1] == ' ' || t[e - 1] == '\r' || t[e - 1] == '\n')) e--;
    if (e - i < 6 || strncasecmp(&t[i], "report", 6) != 0) return false;
    named = false;
    if (e - i > 6) {   // "report <name>": this repeater's whole name
      if (t[i + 6] != ' ') return false;   // eg. "reports"
      size_t s = i + 6;
      while (s < e && t[s] == ' ') s++;
      size_t name_len = strlen(node_name);
      if (e - s != name_len || strncasecmp(&t[s], node_name, name_len) != 0) return false;
      named = true;
    }
    return true;
  }

  // the setting keys, in REPORTS_FILE order
  static const char* const* keys() {
    static const char* const k[] = { "reports.enabled", "reports.channel.key", "reports.channel.region",
                                     "reports.hops.max", "reports.cooldown", "alerts.enabled", "alerts.battery",
                                     "alerts.noisefloor", "alerts.airtime", "alerts.cooldown", nullptr };
    return k;
  }

  // true if 'config' starts with "reports." or "alerts."
  static bool isOurs(const char* config) {
    while (*config == ' ') config++;
    return memcmp(config, "reports.", 8) == 0 || memcmp(config, "alerts.", 7) == 0;
  }

  void setDefaults() {
    memset(&_s, 0, sizeof(_s));
    _s.enabled = 0;
    mesh::Utils::fromHex(_s.key, sizeof(_s.key), REPORTS_DEFAULT_KEY);
    strncpy(_s.region, REPORTS_DEFAULT_REGION, sizeof(_s.region) - 1);
    _s.hops_max = 3;
    _s.cooldown_mins = 60;
    _s.alerts_enabled = 1;
    _s.alert_battery = 34;
    _s.alert_noisefloor = 10;
    _s.alert_airtime = 25;
    _s.alert_cooldown_mins = 60;
    makeChannel();
  }

  // the channel's secret (the key, zero-padded) and hash (first byte of sha256(key))
  void makeChannel() {
    memset(&_channel, 0, sizeof(_channel));
    memcpy(_channel.secret, _s.key, sizeof(_s.key));
    mesh::Utils::sha256(_channel.hash, sizeof(_channel.hash), _s.key, sizeof(_s.key));
  }

  void keyToHex(char* hex) const {
    for (int i = 0; i < (int)sizeof(_s.key); i++) sprintf(&hex[i * 2], "%02x", _s.key[i]);
  }

  // Sets one setting from "<key> <value>". 'from_cli': trailing spaces are trimmed. Returns nullptr, or an error.
  const char* set(const char* config, bool from_cli) {
    while (*config == ' ') config++;
    const char* v = strchr(config, ' ');
    if (v == nullptr) return "use: set <setting> <value>";
    int key_len = v - config;
    while (*v == ' ') v++;
    char value[40];
    int v_len = strlen(v);
    if (from_cli) {
      while (v_len > 0 && v[v_len - 1] == ' ') v_len--;
    }
    if (v_len == 0 || v_len >= (int)sizeof(value)) return "bad value";
    memcpy(value, v, v_len);
    value[v_len] = 0;

    if (isKey(config, key_len, "reports.enabled")) {
      return setNumber(value, 0, 1, _s.enabled);
    } else if (isKey(config, key_len, "reports.channel.key")) {
      uint8_t key[sizeof(_s.key)];
      if (v_len != 32 || !isHex(value) || !mesh::Utils::fromHex(key, sizeof(key), value)) {
        return "bad key, 32 hex digits";
      }
      memcpy(_s.key, key, sizeof(_s.key));
      makeChannel();
      return nullptr;
    } else if (isKey(config, key_len, "reports.channel.region")) {
      if (v_len >= (int)sizeof(_s.region)) return "bad region, up to 30 characters";
      strcpy(_s.region, value);
      return nullptr;
    } else if (isKey(config, key_len, "reports.hops.max")) {
      return setNumber(value, 0, REPORTS_MAX_HOPS, _s.hops_max);
    } else if (isKey(config, key_len, "reports.cooldown")) {
      return setNumber16(value, 15, 1440, _s.cooldown_mins);
    } else if (isKey(config, key_len, "alerts.enabled")) {
      return setNumber(value, 0, 1, _s.alerts_enabled);
    } else if (isKey(config, key_len, "alerts.battery")) {
      return setNumberOrOff(value, 10, 50, _s.alert_battery);
    } else if (isKey(config, key_len, "alerts.noisefloor")) {
      return setNumberOrOff(value, 3, 40, _s.alert_noisefloor);
    } else if (isKey(config, key_len, "alerts.airtime")) {
      return setNumberOrOff(value, 1, 100, _s.alert_airtime);
    } else if (isKey(config, key_len, "alerts.cooldown")) {
      return setNumber16(value, 15, 1440, _s.alert_cooldown_mins);
    }
    return "unknown setting";
  }

  // Writes the value of setting 'key' at dest. Returns the length, or -1 if it's not a setting.
  int formatValue(const char* key, char* dest) const {
    if (strcmp(key, "reports.enabled") == 0) return sprintf(dest, "%d", _s.enabled);
    if (strcmp(key, "reports.channel.key") == 0) {
      keyToHex(dest);
      return 32;
    }
    if (strcmp(key, "reports.channel.region") == 0) return sprintf(dest, "%s", _s.region);
    if (strcmp(key, "reports.hops.max") == 0) return sprintf(dest, "%d", _s.hops_max);
    if (strcmp(key, "reports.cooldown") == 0) return sprintf(dest, "%d", _s.cooldown_mins);
    if (strcmp(key, "alerts.enabled") == 0) return sprintf(dest, "%d", _s.alerts_enabled);
    if (strcmp(key, "alerts.battery") == 0) return sprintf(dest, "%d", _s.alert_battery);
    if (strcmp(key, "alerts.noisefloor") == 0) return sprintf(dest, "%d", _s.alert_noisefloor);
    if (strcmp(key, "alerts.airtime") == 0) return sprintf(dest, "%d", _s.alert_airtime);
    if (strcmp(key, "alerts.cooldown") == 0) return sprintf(dest, "%d", _s.alert_cooldown_mins);
    return -1;
  }

  // Saves every setting to REPORTS_FILE, as 'set' lines. False if it failed.
  bool save() {
    if (_fs == nullptr) return false;
    File file = tableFileOpenWrite(_fs, REPORTS_FILE);
    if (!file) return false;
    bool ok = true;
    char line[80];
    for (const char* const* k = keys(); *k != nullptr && ok; k++) {
      int n = sprintf(line, "%s ", *k);
      formatValue(*k, &line[n]);
      ok = tableFileWriteLine(file, line);
    }
    file.close();
    return ok;
  }

  static bool isKey(const char* s, int len, const char* key) {
    return (int)strlen(key) == len && memcmp(s, key, len) == 0;
  }

  static bool isHex(const char* s) {
    for (; *s; s++) {
      if (!mesh::Utils::isHexChar(*s)) return false;
    }
    return true;
  }

  // decimal value min-max into 'out'. Returns nullptr, or an error.
  static const char* parseNumber(const char* value, int min, int max, int& out) {
    if (*value < '0' || *value > '9') return "bad value";
    long n = 0;
    for (const char* p = value; *p; p++) {
      if (*p < '0' || *p > '9') return "bad value";
      n = n * 10 + (*p - '0');
      if (n > 100000) return "bad value";
    }
    if (n < min || n > max) return "value out of range";
    out = (int)n;
    return nullptr;
  }
  static const char* setNumber(const char* value, int min, int max, uint8_t& out) {
    int n;
    const char* err = parseNumber(value, min, max, n);
    if (err == nullptr) out = n;
    return err;
  }
  static const char* setNumber16(const char* value, int min, int max, uint16_t& out) {
    int n;
    const char* err = parseNumber(value, min, max, n);
    if (err == nullptr) out = n;
    return err;
  }
  // 0 (off), or min-max
  static const char* setNumberOrOff(const char* value, int min, int max, uint8_t& out) {
    if (strcmp(value, "0") == 0) {
      out = 0;
      return nullptr;
    }
    return setNumber(value, min, max, out);
  }
};

#endif   // !STM32_PLATFORM
