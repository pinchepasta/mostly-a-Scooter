// Host-side check of src/battery.h.
// Builds a fake BMS memory image using the byte offsets of the open-source M365 BMS
// firmware (BotoX/xiaomi-m365-compatible-bms, struct M365BMS), then "reads" it the
// way the scooter would (register = word index = byte offset / 2) and parses it.
// Build/run:  g++ -std=c++17 -Wall -o tb host_battery_test.cpp && ./tb
#include <stdio.h>
#include <math.h>
#include "../src/battery.h"

static uint8_t mem[256];
static void w16(int off, uint16_t v) { mem[off] = v & 0xFF; mem[off + 1] = v >> 8; }
static const uint8_t* rd(uint8_t reg, size_t len) { return mem + reg * 2; (void)len; }

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)
#define NEAR(a, b, e) CHECK(fabsf((a) - (b)) < (e))

int main() {
  memset(mem, 0, sizeof(mem));
  memcpy(mem + 0x20, "N2GXX12345678 ", 14);   // serial        0x20-0x2D
  w16(0x2E, 0x0115);                          // version       1.1.5
  w16(0x30, 12800);                           // design mAh
  w16(0x32, 12150);                           // real mAh
  w16(0x34, 36000);                           // nominal mV
  w16(0x36, 42);                              // cycles
  w16(0x38, 18);                              // charges
  w16(0x3A, 4200);                            // max V /100
  w16(0x3C, 2000);                            // max discharge A /100
  w16(0x3E, 600);                             // max charge A /100
  w16(0x40, ((23) << 9) | (5 << 5) | 12);     // date 2023-05-12
  mem[0x42] = 0x07;                           // an error byte
  w16(0x60, 0x0001);                          // status
  w16(0x62, 11240);                           // capacity left mAh
  w16(0x64, 87);                              // percent
  w16(0x66, (uint16_t)(int16_t)231);          // current +2.31 A
  w16(0x68, 3942);                            // 39.42 V
  mem[0x6A] = 48; mem[0x6B] = 49;             // temps 28 / 29 C
  w16(0x6C, 0x0004);                          // balancing cell 3
  w16(0x76, 97);                              // health
  for (int i = 0; i < 10; i++) w16(0x80 + i * 2, 3940 + i);  // cells, 3940..3949 mV
  w16(0x80 + 4 * 2, 3921);                    // one low cell

  bat::State s;
  CHECK(s.parseInfo(rd(bat::REG_INFO, 32), 32));
  CHECK(strcmp(s.info.serial, "N2GXX12345678") == 0);
  CHECK(s.info.version == 0x115);
  char v[8]; bat::versionStr(s.info.version, v, sizeof v); CHECK(strcmp(v, "1.1.5") == 0);
  CHECK(s.info.designMah == 12800 && s.info.realMah == 12150 && s.info.nominalMv == 36000);
  CHECK(s.info.cycles == 42 && s.info.charges == 18);
  CHECK(s.info.maxV == 4200 && s.info.maxDis == 2000 && s.info.maxChg == 600);
  int wear; CHECK(s.wearPct(wear) && wear == 6);

  CHECK(s.parseDate(rd(bat::REG_DATE, 8), 8));
  CHECK(s.date.year() == 2023 && s.date.month() == 5 && s.date.day() == 12);
  CHECK(s.date.err[0] == 0x07 && s.date.anyError());

  CHECK(s.parseLive(rd(bat::REG_LIVE, 24), 24, 1000, 0.0f));
  CHECK(s.live.capMah == 11240 && s.live.pct == 87);
  NEAR(s.live.amps, 2.31f, 0.001f); NEAR(s.live.volts, 39.42f, 0.001f);
  CHECK(s.live.t1 == 28 && s.live.t2 == 29 && s.live.tmax() == 29);
  CHECK(s.live.balance == 4 && s.live.health == 97 && !s.live.charging());

  CHECK(s.parseCells(rd(bat::REG_CELLS, 20), 20, 1000));
  CHECK(s.cells.n == 10 && s.cells.minMv == 3921 && s.cells.minIdx == 4 && s.cells.deltaMv() == 28);
  NEAR(s.perCellV(), 3.942f, 0.001f);

  uint8_t r[2] = {0x6E, 0x08};  // 2158 -> 21.58 km
  CHECK(s.parseRange(r, 2, 1000)); NEAR(s.rangeKm, 21.58f, 0.001f);

  // garbage / short frames are rejected and leave state alone
  uint8_t bad[24] = {0}; CHECK(!s.parseLive(bad, 24, 1100, 0));
  CHECK(!s.parseLive(bad, 10, 1100, 0)); CHECK(!s.parseInfo(bad, 10)); CHECK(!s.parseCells(bad, 20, 1100));
  CHECK(s.live.capMah == 11240);

  // ride tracking: ride 1.0 km, battery drops 160 mAh, 3 s of 2.31 A then regen
  { float k0, w0; CHECK(!s.estimate(0.2f, k0, w0)); }  // not enough data yet
  w16(0x62, 11080);                                          // 160 mAh used
  CHECK(s.parseLive(rd(bat::REG_LIVE, 24), 24, 2000, 1.0f));  // 1 s after first sample
  float km, whkm;
  CHECK(s.estimate(1.0f, km, whkm));
  NEAR(km, 11080.0f / 160.0f, 0.01f);   // 160 mAh/km -> 69.25 km
  NEAR(whkm, 160 * 36.0f / 1000.0f, 0.01f);
  CHECK(s.usedMah() == 160);
  NEAR(s.whOut, 39.42f * 2.31f * 1.0f / 3600.0f, 0.0001f);

  w16(0x66, (uint16_t)(int16_t)-150);                       // regen -1.50 A
  CHECK(s.parseLive(rd(bat::REG_LIVE, 24), 24, 3000, 1.0f));
  NEAR(s.whRegen, 39.42f * 1.5f / 3600.0f, 0.0001f);
  w16(0x60, 0x0041);                                        // now charging flag set: not regen
  float before = s.whRegen;
  CHECK(s.parseLive(rd(bat::REG_LIVE, 24), 24, 4000, 1.0f));
  NEAR(s.whRegen, before, 0.00001f);
  NEAR(s.peakAmps, 2.31f, 0.001f);

  // a gap > 3 s must not be integrated
  float wo = s.whOut; w16(0x66, 231);
  CHECK(s.parseLive(rd(bat::REG_LIVE, 24), 24, 20000, 1.0f));
  NEAR(s.whOut, wo, 0.00001f);

  printf(fails ? "\n%d FAILED\n" : "all battery tests OK\n", fails);
  return fails != 0;
}
