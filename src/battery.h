// Battery (BMS) data for Xiaomi M365 / Pro / Pro 2 scooters.
// Pure C++ (no Arduino deps) so it can be unit-tested on the host.
//
// Protocol notes (open-source BMS firmware + m365 reference library):
//   * Requests to the BMS use address 0x22, replies come from 0x25.
//   * Register numbers are WORD indexes into the BMS memory map
//     (register = byte offset / 2), read lengths are in bytes.
//   * The ESC (0x20 -> 0x23) has its own "distance left" register 0x25.
//
//   reg 0x10 (32 B): serial[14], version, design mAh, real mAh, nominal mV,
//                    cycles, charge count, max V (/100), max dis A (/100), max chg A (/100)
//   reg 0x20 ( 8 B): manufacture date, error bytes[6]
//   reg 0x30 (24 B): status, remaining mAh, percent, current (i16, A/100),
//                    voltage (V/100), temp1-20, temp2-20, balance bits, ..., health @ byte 22
//   reg 0x40 (20 B): cell voltages in mV, 2 bytes each
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

namespace bat {

constexpr uint8_t ADDR_BMS_TX = 0x22, ADDR_BMS_RX = 0x25;
constexpr uint8_t ADDR_ESC_TX = 0x20, ADDR_ESC_RX = 0x23;

constexpr uint8_t REG_INFO = 0x10;   constexpr uint8_t LEN_INFO = 32;
constexpr uint8_t REG_DATE = 0x20;   constexpr uint8_t LEN_DATE = 8;
constexpr uint8_t REG_LIVE = 0x30;   constexpr uint8_t LEN_LIVE = 24;
constexpr uint8_t REG_CELLS = 0x40;  constexpr uint8_t LEN_CELLS = 20;
constexpr uint8_t REG_ESC_RANGE = 0x25;  // ESC: remaining distance, u16, 1/100 km
constexpr uint8_t LEN_ESC_RANGE = 2;

constexpr uint16_t ST_CHARGING = 1 << 6;   // status bit 6
constexpr uint16_t ST_OVERVOLT = 1 << 9;   // status bit 9
constexpr uint16_t ST_OVERHEAT = 1 << 10;  // status bit 10

inline uint16_t le16(const uint8_t* d, size_t o) { return (uint16_t)(d[o] | (d[o + 1] << 8)); }

struct Info {
  bool ok = false;
  char serial[15] = {0};
  uint16_t version = 0, designMah = 0, realMah = 0, nominalMv = 0;
  uint16_t cycles = 0, charges = 0, maxV = 0, maxDis = 0, maxChg = 0;
};

struct DateErr {
  bool ok = false;
  uint16_t raw = 0;
  uint8_t err[6] = {0};
  int year() const { return 2000 + (raw >> 9); }
  int month() const { return (raw >> 5) & 0x0F; }
  int day() const { return raw & 0x1F; }
  bool anyError() const { for (int i = 0; i < 6; i++) if (err[i]) return true; return false; }
};

struct Live {
  bool ok = false;
  uint16_t status = 0, capMah = 0, pct = 0, balance = 0, health = 0;
  float amps = 0;   // + = discharging (riding), - = charging / regen
  float volts = 0;
  int t1 = 0, t2 = 0;  // deg C
  int tmax() const { return t1 > t2 ? t1 : t2; }
  bool charging() const { return status & ST_CHARGING; }
};

struct Cells {
  bool ok = false;
  uint8_t n = 0;
  uint16_t mv[15] = {0};
  uint16_t minMv = 0, maxMv = 0;
  uint8_t minIdx = 0, maxIdx = 0;
  int deltaMv() const { return (int)maxMv - (int)minMv; }
};

struct State {
  Info info;
  DateErr date;
  Live live;
  Cells cells;
  float rangeKm = -1;        // scooter's own remaining-distance estimate (ESC reg 0x25)
  float escTemp = -100;      // controller / frame temperature, deg C
  uint32_t liveMs = 0, cellsMs = 0, rangeMs = 0;

  // ride tracking (baseline = first live sample after connect)
  bool haveBase = false;
  uint16_t baseMah = 0;
  float baseKm = 0;
  float peakAmps = 0, peakWatts = 0, regenPeakAmps = 0;
  int maxTemp = -100;
  float minVolts = 0, maxVolts = 0;
  float whOut = 0, whRegen = 0;
  int minCellMv = 0;         // lowest single cell seen this ride

  // ---------------- parsers ----------------
  bool parseInfo(const uint8_t* d, size_t n) {
    if (n < LEN_INFO) return false;
    Info i;
    for (int k = 0; k < 14; k++) i.serial[k] = (d[k] >= 32 && d[k] < 127) ? (char)d[k] : '.';
    i.serial[14] = 0;
    for (int k = 13; k >= 0 && (i.serial[k] == ' ' || i.serial[k] == '.'); k--) i.serial[k] = 0;
    i.version = le16(d, 14);
    i.designMah = le16(d, 16);
    i.realMah = le16(d, 18);
    i.nominalMv = le16(d, 20);
    i.cycles = le16(d, 22);
    i.charges = le16(d, 24);
    i.maxV = le16(d, 26);
    i.maxDis = le16(d, 28);
    i.maxChg = le16(d, 30);
    i.ok = true;
    info = i;
    return true;
  }

  bool parseDate(const uint8_t* d, size_t n) {
    if (n < LEN_DATE) return false;
    DateErr e;
    e.raw = le16(d, 0);
    memcpy(e.err, d + 2, 6);
    e.ok = true;
    date = e;
    return true;
  }

  // rideKm = distance travelled so far this ride (used for the baseline only)
  bool parseLive(const uint8_t* d, size_t n, uint32_t nowMs, float rideKm) {
    if (n < LEN_LIVE) return false;
    Live l;
    l.status = le16(d, 0);
    l.capMah = le16(d, 2);
    l.pct = le16(d, 4);
    l.amps = (int16_t)le16(d, 6) / 100.0f;
    l.volts = le16(d, 8) / 100.0f;
    l.t1 = (int)d[10] - 20;
    l.t2 = (int)d[11] - 20;
    l.balance = le16(d, 12);
    l.health = le16(d, 22);
    if (l.pct > 100 || l.volts < 5.0f || l.volts > 80.0f) return false;  // garbage frame
    if (l.t1 < -40 || l.t1 > 120 || l.t2 < -40 || l.t2 > 120) return false;
    l.ok = true;

    float dtS = liveMs ? (nowMs - liveMs) / 1000.0f : 0;
    if (dtS > 3.0f) dtS = 0;  // gap (reconnect etc.) - don't integrate across it
    float watts = l.volts * l.amps;
    if (l.amps > 0.05f) whOut += watts * dtS / 3600.0f;
    else if (l.amps < -0.05f && !l.charging()) whRegen += -watts * dtS / 3600.0f;

    if (!haveBase) { haveBase = true; baseMah = l.capMah; baseKm = rideKm; minVolts = maxVolts = l.volts; maxTemp = l.tmax(); }
    if (l.amps > peakAmps) peakAmps = l.amps;
    if (watts > peakWatts) peakWatts = watts;
    if (!l.charging() && -l.amps > regenPeakAmps) regenPeakAmps = -l.amps;
    if (l.tmax() > maxTemp) maxTemp = l.tmax();
    if (l.volts < minVolts) minVolts = l.volts;
    if (l.volts > maxVolts) maxVolts = l.volts;

    live = l;
    liveMs = nowMs;
    return true;
  }

  bool parseCells(const uint8_t* d, size_t n, uint32_t nowMs) {
    Cells c;
    size_t cnt = n / 2;
    if (cnt > 15) cnt = 15;
    for (size_t k = 0; k < cnt; k++) {
      uint16_t v = le16(d, k * 2);
      if (v < 1500 || v > 5000) break;  // unused slots read 0
      c.mv[c.n++] = v;
    }
    if (c.n < 3) return false;
    c.minMv = c.maxMv = c.mv[0];
    for (uint8_t k = 1; k < c.n; k++) {
      if (c.mv[k] < c.minMv) { c.minMv = c.mv[k]; c.minIdx = k; }
      if (c.mv[k] > c.maxMv) { c.maxMv = c.mv[k]; c.maxIdx = k; }
    }
    c.ok = true;
    cells = c;
    cellsMs = nowMs;
    if (minCellMv == 0 || c.minMv < minCellMv) minCellMv = c.minMv;
    return true;
  }

  bool parseRange(const uint8_t* d, size_t n, uint32_t nowMs) {
    if (n < 2) return false;
    uint16_t v = le16(d, 0);
    if (v == 0xFFFF) return false;
    rangeKm = v / 100.0f;
    rangeMs = nowMs;
    return true;
  }

  // ---------------- derived values ----------------
  bool liveFresh(uint32_t nowMs, uint32_t maxAgeMs = 5000) const { return live.ok && nowMs - liveMs < maxAgeMs; }
  bool rangeFresh(uint32_t nowMs, uint32_t maxAgeMs = 15000) const { return rangeKm >= 0 && nowMs - rangeMs < maxAgeMs; }

  float watts() const { return live.volts * live.amps; }
  float nominalV() const { return info.nominalMv ? info.nominalMv / 1000.0f : 36.0f; }
  float perCellV() const { return cells.ok && cells.n ? live.volts / cells.n : 0; }
  int usedMah() const { return haveBase && live.ok ? (int)baseMah - (int)live.capMah : 0; }

  // Own range estimate from this ride's consumption. Needs ~0.4 km and ~100 mAh of data.
  bool estimate(float rideKm, float& kmLeft, float& whPerKm) const {
    if (!haveBase || !live.ok) return false;
    float km = rideKm - baseKm;
    int used = usedMah();
    if (km < 0.4f || used < 100) return false;
    float mahPerKm = used / km;
    kmLeft = live.capMah / mahPerKm;
    if (kmLeft > 150.0f) kmLeft = 150.0f;
    whPerKm = mahPerKm * nominalV() / 1000.0f;
    return true;
  }

  // wear = how much of the design capacity is gone (0 = new)
  bool wearPct(int& w) const {
    if (!info.ok || !info.designMah || !info.realMah) return false;
    w = 100 - (int)((uint32_t)info.realMah * 100 / info.designMah);
    if (w < 0) w = 0;
    return true;
  }
};

// "1.1.5" from 0x0115
inline void versionStr(uint16_t v, char* out, size_t n) {
  snprintf(out, n, "%u.%u.%u", (unsigned)(v >> 8), (unsigned)((v >> 4) & 0xF), (unsigned)(v & 0xF));
}

}  // namespace bat
