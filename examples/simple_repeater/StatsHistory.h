#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

// Repeater stats history, RAM only (starts empty at every boot): one reading per 5-minute slot, for the last
// 24 hours. Every stat shares the slots. Not built for STM32 (STM32WL: 64 KB RAM).
//   packets:    decoded packets received and packets sent, and their bytes on air.
//   airtime:    RX and TX airtime utilisation, a whole percent (rounded to nearest). Taken from the Dispatcher's
//               running airtime totals (ms): RX is estimated from packets that decoded, so it's a lower bound on how
//               busy the channel is, TX is measured.
//   noisefloor: the median of the slot's RSSI readings (dBm), taken while the radio is listening. Packets are
//               short, so it follows the background noise. Readings shift if the RX gain or frequency changes.
//   firewall:   packets the firewall dropped.
//   rx errors:  packets the radio heard but couldn't read (eg. CRC failures), from its running total.
//   flood dups: flood-routed packets heard again after they were already seen, from the packet tables' running total.
//   send queue: the most packets waiting to be sent at once.
//   tx waits:   sends put off because the channel was busy (one per retry), sends forced after it stayed busy
//               too long, and holds: times sending was held back because the airtime budget (duty cycle) was
//               used up (one per hold, until the next send). From Dispatcher::checkSend().
//   looped:     packets dropped by loop detection.
//               Counts stop at their field's maximum (65535, or 255 for looped and the send queue) instead of
//               wrapping, so the maximum means "at least".

#define STATS_HISTORY_SLOTS        288      // 24 hours
#define STATS_HISTORY_SLOT_MILLIS  300000   // 5 minutes per slot

// noise floor: an RSSI reading every 5 s while the radio is listening, up to 60 per slot
#define STATS_HISTORY_NOISEFLOOR_SAMPLE_MILLIS  5000
#define STATS_HISTORY_NOISEFLOOR_SAMPLES        (STATS_HISTORY_SLOT_MILLIS / STATS_HISTORY_NOISEFLOOR_SAMPLE_MILLIS)
#define STATS_HISTORY_NOISEFLOOR_NONE           -128   // StatsHistorySlot::noisefloor_dbm: no reading in the slot

#define STATS_HISTORY_COUNT_MAX                 65535  // counts stop here
#define STATS_HISTORY_COUNT8_MAX                255    // 1-byte counts (looped, send queue) stop here

#define STATS_HISTORY_REPLY_SIZE                160    // CLI reply buffer, the end NUL included

#if !defined(STM32_PLATFORM)

// One 5-minute slot of history. Fields largest first, so there's no padding.
struct StatsHistorySlot {
  uint16_t rx_packets;          // decoded packets received
  uint16_t tx_packets;          // packets sent
  uint16_t rx_bytes;            // their bytes on air
  uint16_t tx_bytes;
  uint16_t fw_drops;            // packets the firewall dropped
  uint16_t rx_errors;           // packets heard but not readable
  uint16_t flood_dups;          // floods heard again
  uint16_t tx_deferred;         // sends put off, channel busy (one per retry)
  uint16_t tx_forced;           // sends forced, channel busy too long
  uint16_t tx_budget_holds;     // times sending was held back, airtime budget used up
  uint8_t  airtime_rx_percent;  // RX airtime %
  uint8_t  airtime_tx_percent;  // TX airtime %
  int8_t   noisefloor_dbm;      // median RSSI (dBm), or STATS_HISTORY_NOISEFLOOR_NONE
  uint8_t  send_queue_peak;     // most packets waiting to be sent
  uint8_t  looped;              // packets dropped by loop detection
};
static_assert(sizeof(StatsHistorySlot) == 26, "stats history slot must stay 26 bytes (25 + 1 padding)");

// Running totals from the Dispatcher, radio and packet tables, read when each slot ends (MyMesh::loop())
struct StatsHistoryRunningTotals {
  uint32_t airtime_rx_ms;       // getReceiveAirTime()
  uint32_t airtime_tx_ms;       // getTotalAirTime()
  uint32_t rx_errors;           // radio_driver.getPacketsRecvErrors(), reset by 'clear stats'
  uint32_t flood_dups;          // SimpleMeshTables::getNumFloodDups(), reset by 'clear stats'
};

class StatsHistory {
  // slots: a ring
  StatsHistorySlot _slots[STATS_HISTORY_SLOTS];
  int _newest;                                          // slot written last
  int _count;                                           // slots holding data, up to STATS_HISTORY_SLOTS
  uint64_t _next_slot_millis;                           // uptime when the slot being measured ends, 0 = not started

  // the slot being measured
  StatsHistoryRunningTotals _at_start;                  // the running totals when it started
  uint32_t _rx_packets_now, _tx_packets_now;            // its packets so far
  uint32_t _rx_bytes_now, _tx_bytes_now;                // and their bytes
  uint32_t _fw_drops_now;                               // its firewall drops so far
  uint8_t _send_queue_peak_now;                         // its send queue peak so far
  uint32_t _tx_deferred_now, _tx_forced_now;            // its tx waits so far
  uint32_t _tx_budget_holds_now;
  bool _tx_budget_held;                                 // sending is held back now (counted once, until a send)
  uint32_t _looped_now;                                 // its looped packets so far
  int8_t _noisefloor_samples[STATS_HISTORY_NOISEFLOOR_SAMPLES];   // its noise floor readings so far
  int _noisefloor_sample_count;
  uint64_t _next_noisefloor_sample_millis;              // uptime when the next noise floor reading is due

public:
  StatsHistory(): _slots(), _newest(STATS_HISTORY_SLOTS - 1), _count(0), _next_slot_millis(0), _at_start(),
                  _rx_packets_now(0), _tx_packets_now(0), _rx_bytes_now(0), _tx_bytes_now(0), _fw_drops_now(0),
                  _send_queue_peak_now(0), _tx_deferred_now(0), _tx_forced_now(0), _tx_budget_holds_now(0),
                  _tx_budget_held(false), _looped_now(0), _noisefloor_sample_count(0),
                  _next_noisefloor_sample_millis(0) { }

  // From MyMesh::loop(): when a slot's 5 minutes are up, stores its readings and starts the next slot. The first
  // call only starts the first slot.
  void update(uint64_t uptime_millis, const StatsHistoryRunningTotals& totals) {
    if (_next_slot_millis == 0) {   // first call: start measuring
      _next_slot_millis = uptime_millis + STATS_HISTORY_SLOT_MILLIS;
      _at_start = totals;
      return;
    }
    if (uptime_millis < _next_slot_millis) return;

    // the slot is over: store it in the next ring position (the oldest, once full)
    _newest = (_newest + 1) % STATS_HISTORY_SLOTS;
    if (_count < STATS_HISTORY_SLOTS) _count++;
    StatsHistorySlot& slot = _slots[_newest];

    // packets: the slot's counts
    slot.rx_packets = capped(_rx_packets_now, STATS_HISTORY_COUNT_MAX);
    slot.tx_packets = capped(_tx_packets_now, STATS_HISTORY_COUNT_MAX);
    slot.rx_bytes = capped(_rx_bytes_now, STATS_HISTORY_COUNT_MAX);
    slot.tx_bytes = capped(_tx_bytes_now, STATS_HISTORY_COUNT_MAX);
    _rx_packets_now = _tx_packets_now = _rx_bytes_now = _tx_bytes_now = 0;

    // airtime: the totals' growth over the slot (unsigned subtraction: right even if a total wraps)
    slot.airtime_rx_percent = slotPercent(totals.airtime_rx_ms - _at_start.airtime_rx_ms);
    slot.airtime_tx_percent = slotPercent(totals.airtime_tx_ms - _at_start.airtime_tx_ms);

    // noise floor: the median of the slot's readings
    slot.noisefloor_dbm = noisefloorMedian();
    _noisefloor_sample_count = 0;

    // firewall drops, rx errors, flood dups, send queue peak
    slot.fw_drops = capped(_fw_drops_now, STATS_HISTORY_COUNT_MAX);
    slot.rx_errors = capped(growth(totals.rx_errors, _at_start.rx_errors), STATS_HISTORY_COUNT_MAX);
    slot.flood_dups = capped(growth(totals.flood_dups, _at_start.flood_dups), STATS_HISTORY_COUNT_MAX);
    slot.send_queue_peak = _send_queue_peak_now;
    _fw_drops_now = 0;
    _send_queue_peak_now = 0;

    // tx waits and looped packets: the slot's counts
    slot.tx_deferred = capped(_tx_deferred_now, STATS_HISTORY_COUNT_MAX);
    slot.tx_forced = capped(_tx_forced_now, STATS_HISTORY_COUNT_MAX);
    slot.tx_budget_holds = capped(_tx_budget_holds_now, STATS_HISTORY_COUNT_MAX);
    slot.looped = capped(_looped_now, STATS_HISTORY_COUNT8_MAX);
    _tx_deferred_now = _tx_forced_now = _tx_budget_holds_now = _looped_now = 0;

    _at_start = totals;
    _next_slot_millis += STATS_HISTORY_SLOT_MILLIS;   // exactly one slot on, so slots don't drift
  }

  // From MyMesh::logRx() / logTx(): counts a decoded packet received / a packet sent, 'bytes' long, in the slot
  // being measured (from the first slot on)
  void countRx(int bytes) {
    if (_next_slot_millis == 0) return;
    _rx_packets_now++;
    _rx_bytes_now += bytes;
  }
  void countTx(int bytes) {
    _tx_budget_held = false;   // a send got through: the next budget hold is a new one
    if (_next_slot_millis == 0) return;
    _tx_packets_now++;
    _tx_bytes_now += bytes;
  }

  // From MyMesh::allowPacketForward(): counts a packet the firewall dropped
  void countFirewallDrop() {
    if (_next_slot_millis != 0) _fw_drops_now++;
  }

  // From MyMesh::loop(): the packets waiting to be sent now, for the slot's peak
  void noteSendQueue(int waiting) {
    if (_next_slot_millis == 0 || waiting <= _send_queue_peak_now) return;
    _send_queue_peak_now = capped(waiting, STATS_HISTORY_COUNT8_MAX);
  }

  // From MyMesh::logTxDeferred() / logTxForced() / logTxBudgetHold() / allowPacketForward(): counts a send put off
  // (channel busy), a send forced (busy too long), a budget hold (once, until the next send), or a packet dropped
  // by loop detection, in the slot being measured
  void countTxDeferred() {
    if (_next_slot_millis != 0) _tx_deferred_now++;
  }
  void countTxForced() {
    if (_next_slot_millis != 0) _tx_forced_now++;
  }
  void countTxBudgetHold() {
    if (_tx_budget_held) return;   // the same hold: Dispatcher::checkSend() reports it on every pass
    _tx_budget_held = true;
    if (_next_slot_millis != 0) _tx_budget_holds_now++;
  }
  void countLooped() {
    if (_next_slot_millis != 0) _looped_now++;
  }

  // From MyMesh::loop(): true when the next noise floor reading is due (every
  // STATS_HISTORY_NOISEFLOOR_SAMPLE_MILLIS)
  bool isNoisefloorSampleDue(uint64_t uptime_millis) {
    if (uptime_millis < _next_noisefloor_sample_millis) return false;
    _next_noisefloor_sample_millis += STATS_HISTORY_NOISEFLOOR_SAMPLE_MILLIS;
    if (_next_noisefloor_sample_millis <= uptime_millis) {   // fell behind: carry on from now, no catching up
      _next_noisefloor_sample_millis = uptime_millis + STATS_HISTORY_NOISEFLOOR_SAMPLE_MILLIS;
    }
    return true;
  }

  // Adds a noise floor reading (dBm) for the slot being measured, rounded and clamped to -127..0. NaN (no
  // reading), a reading before the first slot starts, or one past STATS_HISTORY_NOISEFLOOR_SAMPLES is dropped.
  void addNoisefloorSample(float rssi) {
    if (isnan(rssi) || _next_slot_millis == 0) return;
    if (_noisefloor_sample_count >= STATS_HISTORY_NOISEFLOOR_SAMPLES) return;
    if (rssi < -127) rssi = -127;
    if (rssi > 0) rssi = 0;
    _noisefloor_samples[_noisefloor_sample_count++] = (int8_t)floorf(rssi + 0.5f);
  }

  // the slot 'age' slots back (0 = the last 5 minutes), or nullptr if there's no such slot
  const StatsHistorySlot* getSlot(int age) const {
    if (age < 0 || age >= _count) return nullptr;
    return &_slots[(_newest - age + STATS_HISTORY_SLOTS) % STATS_HISTORY_SLOTS];
  }

  // CLI 'stats': airtime and noise floor for the last 5 min / 15 min / 60 min / 24 h (averages of the slots there
  // are), the packets and bytes in and out and the firewall drops over 24 h (totals), and how far back the history
  // goes (last, so it's what gets cut off if the reply would go over STATS_HISTORY_REPLY_SIZE).
  void formatSummary(char* reply) const {
    if (noStatsYet(reply)) return;
    StatsHistoryTotals t[4];
    sumSlots(0, 1, t[0]);
    sumSlots(0, 3, t[1]);
    sumSlots(0, 12, t[2]);
    sumSlots(0, STATS_HISTORY_SLOTS, t[3]);

    char air_rx[32], air_tx[32], nf[32];
    formatSummaryValues(air_rx, t, SUMMARY_AIRTIME_RX);
    formatSummaryValues(air_tx, t, SUMMARY_AIRTIME_TX);
    formatSummaryValues(nf, t, SUMMARY_NOISEFLOOR);
    snprintf(reply, STATS_HISTORY_REPLY_SIZE,
             "air_rx: %s\nair_tx: %s\nnf: %s\nin_24hr: %lup/%lub\nout_24hr: %lup/%lub\nfw_24hr: %lu\nhist: %dm",
             air_rx, air_tx, nf, (unsigned long)t[3].rx_packets, (unsigned long)t[3].rx_bytes,
             (unsigned long)t[3].tx_packets, (unsigned long)t[3].tx_bytes, (unsigned long)t[3].fw_drops, _count * 5);
  }

  // CLI 'stats <minutes>': every stat of the one slot that ended 'minutes_ago' ago (a multiple of 5: 5 = the
  // newest, 10 = the one before).
  void formatSlot(int minutes_ago, char* reply) const {
    if (noStatsYet(reply)) return;
    int age = minutes_ago / 5 - 1;
    if (age >= _count) {
      sprintf(reply, "Err - only %dm of stats so far", _count * 5);
      return;
    }
    StatsHistoryTotals t;
    sumSlots(age, 1, t);
    formatTotals(t, reply);
  }

  // CLI 'stats +<minutes>': every stat over the last 'minutes' (a multiple of 5, or the slots there are): totals,
  // averages for airtime and noise floor, the highest send queue.
  void formatPeriod(int minutes, char* reply) const {
    if (noStatsYet(reply)) return;
    StatsHistoryTotals t;
    sumSlots(0, minutes / 5, t);
    formatTotals(t, reply);
  }

private:
  // a group of slots added up, for the CLI
  struct StatsHistoryTotals {
    int slots;                                             // slots added up
    uint32_t rx_packets, tx_packets, rx_bytes, tx_bytes;
    uint32_t airtime_rx_sum, airtime_tx_sum;               // percentages added up
    int32_t noisefloor_sum;                                // readings added up
    int noisefloor_slots;                                  // slots with a reading
    uint32_t fw_drops, rx_errors, flood_dups;
    int send_queue_peak;                                   // the highest
    uint32_t tx_deferred, tx_forced, tx_budget_holds, looped;
  };

  // which stat formatSummaryValues() writes
  enum SummaryStat { SUMMARY_AIRTIME_RX, SUMMARY_AIRTIME_TX, SUMMARY_NOISEFLOOR };

  // 'no stats yet' in 'reply' and true, if no slot has been stored yet
  bool noStatsYet(char* reply) const {
    if (_count > 0) return false;
    strcpy(reply, "no stats yet, first reading 5 minutes after boot");
    return true;
  }

  // Adds up 'n' slots, starting 'first_age' slots back (0 = the newest), as far as there are slots.
  void sumSlots(int first_age, int n, StatsHistoryTotals& t) const {
    memset(&t, 0, sizeof(t));
    for (int age = first_age; age < first_age + n; age++) {
      const StatsHistorySlot* s = getSlot(age);
      if (s == nullptr) break;
      t.slots++;
      t.rx_packets += s->rx_packets;
      t.tx_packets += s->tx_packets;
      t.rx_bytes += s->rx_bytes;
      t.tx_bytes += s->tx_bytes;
      t.airtime_rx_sum += s->airtime_rx_percent;
      t.airtime_tx_sum += s->airtime_tx_percent;
      if (s->noisefloor_dbm != STATS_HISTORY_NOISEFLOOR_NONE) {
        t.noisefloor_sum += s->noisefloor_dbm;
        t.noisefloor_slots++;
      }
      t.fw_drops += s->fw_drops;
      t.rx_errors += s->rx_errors;
      t.flood_dups += s->flood_dups;
      if (s->send_queue_peak > t.send_queue_peak) t.send_queue_peak = s->send_queue_peak;
      t.tx_deferred += s->tx_deferred;
      t.tx_forced += s->tx_forced;
      t.tx_budget_holds += s->tx_budget_holds;
      t.looped += s->looped;
    }
  }

  // Writes one stat's 4 summary values (5 min / 15 min / 60 min / 24 h, from 't'), '/' separated. Returns the
  // length.
  static int formatSummaryValues(char* dest, const StatsHistoryTotals* t, SummaryStat stat) {
    int n = 0;
    for (int i = 0; i < 4; i++) {
      if (i > 0) dest[n++] = '/';
      if (stat == SUMMARY_AIRTIME_RX) {
        n += sprintf(&dest[n], "%d%%", average(t[i].airtime_rx_sum, t[i].slots));
      } else if (stat == SUMMARY_AIRTIME_TX) {
        n += sprintf(&dest[n], "%d%%", average(t[i].airtime_tx_sum, t[i].slots));
      } else {
        n += formatNoisefloor(&dest[n], t[i]);
      }
    }
    return n;
  }

  // Writes every stat of 't', related ones on one line ('stats <n>' / 'stats +<n>'). At most
  // STATS_HISTORY_REPLY_SIZE (cut off there).
  static void formatTotals(const StatsHistoryTotals& t, char* reply) {
    char nf[8];
    formatNoisefloor(nf, t);
    snprintf(reply, STATS_HISTORY_REPLY_SIZE,
             "rx: %lup/%lub\ntx: %lup/%lub\narr/art: %d%%/%d%%\nnf: %s\nfw/err/dup: %lu/%lu/%lu\nsq: %d"
             "\ndfr/frc/hld: %lu/%lu/%lu\nlp: %lu",
             (unsigned long)t.rx_packets, (unsigned long)t.rx_bytes, (unsigned long)t.tx_packets,
             (unsigned long)t.tx_bytes, average(t.airtime_rx_sum, t.slots), average(t.airtime_tx_sum, t.slots), nf,
             (unsigned long)t.fw_drops, (unsigned long)t.rx_errors, (unsigned long)t.flood_dups, t.send_queue_peak,
             (unsigned long)t.tx_deferred, (unsigned long)t.tx_forced, (unsigned long)t.tx_budget_holds,
             (unsigned long)t.looped);
  }

  // Writes the average noise floor of 't' (dBm), or '-' if no slot had a reading. Returns the length.
  static int formatNoisefloor(char* dest, const StatsHistoryTotals& t) {
    if (t.noisefloor_slots == 0) return sprintf(dest, "-");
    return sprintf(dest, "%d", average(t.noisefloor_sum, t.noisefloor_slots));
  }

  // 'sum' / 'n', rounded to nearest (negative sums too), or 0 if n is 0
  static int average(int32_t sum, int n) {
    if (n <= 0) return 0;
    if (sum < 0) return -(int)((-sum + n / 2) / n);
    return (int)((sum + n / 2) / n);
  }

  // median of the slot's noise floor readings (sorts them), or STATS_HISTORY_NOISEFLOOR_NONE if there are none
  int8_t noisefloorMedian() {
    if (_noisefloor_sample_count == 0) return STATS_HISTORY_NOISEFLOOR_NONE;
    for (int i = 1; i < _noisefloor_sample_count; i++) {   // insertion sort, at most STATS_HISTORY_NOISEFLOOR_SAMPLES
      int8_t v = _noisefloor_samples[i];
      int j = i - 1;
      while (j >= 0 && _noisefloor_samples[j] > v) {
        _noisefloor_samples[j + 1] = _noisefloor_samples[j];
        j--;
      }
      _noisefloor_samples[j + 1] = v;
    }
    return _noisefloor_samples[_noisefloor_sample_count / 2];
  }

  // how much a running total grew since 'at_start'. 'clear stats' resets some totals to 0: if it went down, the
  // count since the reset.
  static uint32_t growth(uint32_t now, uint32_t at_start) {
    if (now < at_start) return now;
    return now - at_start;
  }

  // a count for a slot: at most 'max'
  static uint32_t capped(uint32_t count, uint32_t max) {
    if (count > max) return max;
    return count;
  }

  // whole percent of a slot, rounded to nearest, at most 100. 'ms': airtime in the slot.
  static uint8_t slotPercent(uint32_t ms) {
    uint32_t percent = ((uint64_t)ms * 100 + STATS_HISTORY_SLOT_MILLIS / 2) / STATS_HISTORY_SLOT_MILLIS;
    if (percent > 100) percent = 100;
    return (uint8_t)percent;
  }
};

#endif   // !STM32_PLATFORM
