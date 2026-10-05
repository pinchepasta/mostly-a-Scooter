// mostly-a-Scooter  -  M5Stack Cardputer ADV
// Dashboard for Xiaomi M365 / Pro / Pro 2 scooters + IMU ride logger.
// Uses Xiaomi's own registration (power-button confirm) + encrypted login,
// ported from the open-source macbury/m365 reference. Falls back to the
// plain protocol for old firmware that has no FE95 auth service.
//
// Keys:  Home:  S = scan & ride   W = WiFi export   B = BLE export   T = theme (13 themes, see THEMES[])
//        Scan:  ; / . = up/down   Enter = connect   A = show all
//               F = forget saved pairing of selected scooter   Q = back
//        Pair:  Q = cancel
//        Ride:  R = start/stop recording   I = battery info pages   T = theme   Q = disconnect & home
//               L = motor lock/unlock   H = tail light off/brake/always   G = headlight   V = HUD style   S = settings
//        Settings: ; / . = select row   , / / = change value   ENT = toggle   (hotkeys: L H G A V T B)   ESC / DEL / Q = back to HUD
//        ESC (or DEL) always goes back: Settings / Info -> ride HUD, Scan / Export -> home. On the ride HUD, Q disconnects.
//        Meters (Ride, key 2): g-force + tilt + speed + battery amps.  2 = open/close   Z = zero tilt   X = tilt axis   C = flip sign   ESC / Q / 1 = back
//        Info:  I or / = next page   , = previous page   R = record   Q = back to ride
//        Export: Q = back

#include <M5Cardputer.h>
#include <NimBLEDevice.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WebServer.h>
#include <SD.h>
#include <SPI.h>
#include <LittleFS.h>
#include <esp_random.h>
#include <vector>
#include <stdarg.h>

#ifdef SET_LOOP_TASK_STACK_SIZE
SET_LOOP_TASK_STACK_SIZE(16 * 1024);  // ECDH/mbedtls needs more than the 8 kB default
#endif

#define MI_FILL_RANDOM(b, n) esp_fill_random((b), (n))
#include "mi_crypto.h"
#include "battery.h"
#include "logo.h"

#define APP_NAME "mostly-a-Scooter"

// ---------------- Scooter protocol ----------------
static NimBLEUUID NUS_SVC("6e400001-b5a3-f393-e0a9-e50e24dcca9e");
static NimBLEUUID NUS_RX_WRITE("6e400002-b5a3-f393-e0a9-e50e24dcca9e");  // we write here
static NimBLEUUID NUS_TX_NOTIFY("6e400003-b5a3-f393-e0a9-e50e24dcca9e"); // scooter notifies here
// Xiaomi auth service (16-bit UUIDs): FE95 service, 0010 = UPNP, 0019 = AVDTP
constexpr uint16_t UUID_AUTH_SVC = 0xFE95, UUID_UPNP = 0x0010, UUID_AVDTP = 0x0019;

constexpr uint8_t REG_MOTOR_INFO = 0xB0;  // read 0x20 bytes from the motor controller (0x20)
constexpr bool BLE_BONDING = false;       // Xiaomi auth is app-level; set true only if a scooter wants BLE bonding

const uint8_t CMD_GET_INFO[4] = {0xa2, 0, 0, 0};
const uint8_t CMD_SET_KEY[4] = {0x15, 0, 0, 0};
const uint8_t CMD_AUTH[4] = {0x13, 0, 0, 0};
const uint8_t CMD_LOGIN[4] = {0x24, 0, 0, 0};
const uint8_t CMD_SEND_DATA[6] = {0, 0, 0, 0x03, 0x04, 0};
const uint8_t CMD_SEND_DID[6] = {0, 0, 0, 0, 0x02, 0};
const uint8_t CMD_SEND_KEY[6] = {0, 0, 0, 0x0b, 0x01, 0};
const uint8_t CMD_SEND_INFO[6] = {0, 0, 0, 0x0a, 0x02, 0};
const uint8_t RCV_RDY[4] = {0, 0, 1, 1};
const uint8_t RCV_OK[4] = {0, 0, 1, 0};
const uint8_t RCV_AUTH_OK[4] = {0x11, 0, 0, 0};
const uint8_t RCV_LOGIN_OK[4] = {0x21, 0, 0, 0};

// ---------------- Export settings ----------------
const char* AP_SSID = "mostly-a-Scooter";
const char* AP_PASS = "scooter123";
static NimBLEUUID EXP_SVC("6e4f0001-1c2d-4a57-9b11-0a6b5c0d0001");
static NimBLEUUID EXP_CMD("6e4f0002-1c2d-4a57-9b11-0a6b5c0d0001");   // write: LIST | GET <name>
static NimBLEUUID EXP_DATA("6e4f0003-1c2d-4a57-9b11-0a6b5c0d0001");  // notify: stream, ends with "\n#EOF\n"

// ---------------- Globals ----------------
enum State { ST_HOME, ST_SCAN, ST_RIDE, ST_SETTINGS, ST_EXPORT_WIFI, ST_EXPORT_BLE };
State state = ST_HOME;

M5Canvas cv(&M5Cardputer.Display);
fs::FS* fsys = nullptr;
const char* fsName = "none";
Preferences prefs;

struct Telemetry {
  float kmh = 0;
  int batt = -1;
  float totalKm = -1;
  float rideKm = 0;
  uint32_t lastRx = 0;
} tel;

bat::State bs;       // battery (BMS) data + ride statistics
int rdBrake = -1, rdTail = -1;  // brake level / tail-light mode as REPORTED by the scooter (-1 = unknown)
int infoPage = 0;    // 0 = ride dashboard, 1..INFO_PAGES = battery info pages
uint32_t rxMotorN = 0, rxBmsN = 0, rxBmsBad = 0;  // reply counters (diagnostics)
constexpr int INFO_PAGES = 4;

NimBLEClient* client = nullptr;
NimBLERemoteCharacteristic *rxChar = nullptr, *txChar = nullptr, *upnp = nullptr, *avdtp = nullptr;
volatile bool scooterConnected = false;
volatile bool sessionActive = false;  // encrypted session established
bool cryptoMode = false;
mi::Keychain keys;
NimBLEAddress scooterAddr;
bool haveScooter = false;
bool cancelled = false;

struct Dev { NimBLEAddress addr; String name; int rssi; bool paired; };
std::vector<Dev> devs;
int sel = 0;
bool showAll = false;

bool recording = false;
File logFile;
String logName;
uint32_t samples = 0, lastFlush = 0, lastImu = 0, lastPoll = 0, lastSpeedT = 0;

WebServer web(80);

// ---------------- Helpers ----------------
constexpr char KEY_BACK = 0x1B;  // returned for ESC (top-left key) and DEL/backspace
char getKey() {
  M5Cardputer.update();
  if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
    auto s = M5Cardputer.Keyboard.keysState();
    if (s.enter) return '\n';
    if (s.del) return KEY_BACK;
    for (char c : s.word) if (c == '`' || c == 0x1B) return KEY_BACK;  // ESC key prints '`'
    if (!s.word.empty()) return tolower(s.word.back());
  }
  return 0;
}

// ---- tiny debug log: shown on failure screens and mirrored to USB serial ----
char dbgLines[8][44];
void dbgf(const char* fmt, ...) {
  char b[44];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(b, sizeof(b), fmt, ap);
  va_end(ap);
  Serial.println(b);
  memmove(dbgLines[0], dbgLines[1], 7 * 44);
  strncpy(dbgLines[7], b, 43);
  dbgLines[7][43] = 0;
}
void dbgHex(const char* label, const uint8_t* d, size_t n) {
  Serial.printf("%s [%u] ", label, (unsigned)n);
  for (size_t i = 0; i < n; i++) Serial.printf("%02x", d[i]);
  Serial.println();
  char b[44];
  int p = snprintf(b, sizeof(b), "%s ", label);
  for (size_t i = 0; i < n && p < 41; i++) p += snprintf(b + p, sizeof(b) - p, "%02x", d[i]);
  memmove(dbgLines[0], dbgLines[1], 7 * 44);
  strncpy(dbgLines[7], b, 43);
  dbgLines[7][43] = 0;
}


// ---- GAP event tap: records WHY and WHEN the scooter link drops (shown on error screens) ----
volatile int gapDiscReason = 0;          // NimBLE return code of the last disconnect (0 = none)
volatile uint32_t gapConnAt = 0, gapDiscAt = 0;
volatile uint8_t gapEvN = 0;
volatile char gapEv[12];                 // C=connect M=mtu U/u=conn-param req/done E=encryption P=passkey R=re-pair D=disconnect

int gapTap(ble_gap_event* ev, void*) {
  char c = 0;
  switch (ev->type) {
    case BLE_GAP_EVENT_CONNECT:
      if (ev->connect.status != 0) break;
      gapConnAt = millis(); gapDiscAt = 0; gapDiscReason = 0; gapEvN = 0; c = 'C';
      break;
    case BLE_GAP_EVENT_DISCONNECT: gapDiscReason = ev->disconnect.reason; gapDiscAt = millis(); c = 'D'; break;
    case BLE_GAP_EVENT_CONN_UPDATE: c = 'u'; break;
    case BLE_GAP_EVENT_CONN_UPDATE_REQ: c = 'U'; break;
    case BLE_GAP_EVENT_L2CAP_UPDATE_REQ: c = 'L'; break;
    case BLE_GAP_EVENT_ENC_CHANGE: c = 'E'; break;
    case BLE_GAP_EVENT_PASSKEY_ACTION: c = 'P'; break;
    case BLE_GAP_EVENT_REPEAT_PAIRING: c = 'R'; break;
    case BLE_GAP_EVENT_MTU: c = 'M'; break;
    default: break;
  }
  if (c && gapEvN < sizeof(gapEv) - 1) { gapEv[gapEvN] = c; gapEvN = gapEvN + 1; }
  return 0;
}

const char* hciName(int c) {
  switch (c) {
    case 0x05: return "auth failure";
    case 0x06: return "key missing";
    case 0x08: return "link timeout";
    case 0x13: return "scooter hung up";
    case 0x14: return "scooter low res";
    case 0x15: return "scooter power off";
    case 0x16: return "we hung up";
    case 0x1A: return "unsupported";
    case 0x22: return "LL timeout";
    case 0x28: return "instant passed";
    case 0x3B: return "bad conn params";
    case 0x3D: return "MIC failure";
    case 0x3E: return "connect not est.";
    default: return "";
  }
}

// Call when a link is found dead (or a connect failed): puts the reason + timing on the debug log.
void logDrop() {
  delay(30);  // let the BLE host task publish the disconnect event
  if (client && client->isConnected()) { dbgf("link still up"); return; }
  int r = gapDiscReason;
  if (r >= 0x200 && r < 0x300) dbgf("drop hci 0x%02x %s", r - 0x200, hciName(r - 0x200));
  else if (r) dbgf("drop rc=%d", r);
  else dbgf("no disconnect event seen");
  char ev[14] = {0};
  for (int i = 0; i < gapEvN && i < 12; i++) ev[i] = gapEv[i];
  if (gapDiscAt && gapConnAt) dbgf("t+%lums ev %s", (unsigned long)(gapDiscAt - gapConnAt), ev);
  else dbgf("ev %s", ev);
}

// ---------------- Terminal theme ----------------
#define RGB(r, g, b) ((uint16_t)((((r) & 0xF8) << 8) | (((g) & 0xFC) << 3) | ((b) >> 3)))
// Active palette (set by applyTheme). Roles: FG = primary, DIM = labels/secondary,
// FAINT = grid/empty bars, AMBER = warning, RED = alert, CYAN = accent (charging/regen/cold/min).
uint16_t C_BG, C_SCAN, C_FG, C_DIM, C_FAINT, C_AMBER, C_RED, C_CYAN, C_LOG;
bool scanlines = true;
int themeIdx = 0;

struct Theme {
  const char* name;
  bool scan;
  uint16_t bg, scanc, fg, dim, faint, amber, red, cyan, log;
};
const Theme THEMES[] = {
    // crt: original phosphor green with CRT scanlines
    {"crt", true, RGB(0, 6, 0), RGB(0, 15, 0), RGB(57, 255, 20), RGB(0, 135, 40), RGB(0, 55, 18),
     RGB(255, 176, 0), RGB(255, 60, 60), RGB(0, 225, 205), RGB(0, 95, 28)},
    // neon: high-contrast neon green + hot pink on black, no scanlines
    {"neon", false, RGB(0, 0, 0), RGB(0, 0, 0), RGB(57, 255, 20), RGB(255, 40, 170), RGB(90, 15, 60),
     RGB(255, 235, 0), RGB(255, 70, 10), RGB(0, 240, 255), RGB(190, 30, 125)},
    // orange: bright orange + teal accents on black, no scanlines
    {"orange", false, RGB(0, 0, 0), RGB(0, 0, 0), RGB(255, 135, 0), RGB(0, 160, 152), RGB(0, 60, 57),
     RGB(255, 230, 0), RGB(255, 50, 70), RGB(90, 255, 235), RGB(0, 115, 110)},
    // RED: everything in shades of red (warnings = orange-red, alerts = light red), no scanlines
    {"RED", false, RGB(10, 0, 0), RGB(22, 0, 0), RGB(255, 30, 30), RGB(150, 0, 0), RGB(65, 0, 0),
     RGB(255, 95, 40), RGB(255, 150, 150), RGB(210, 50, 70), RGB(115, 0, 0)},
    // neon-blue: electric cyan-blue + violet on black
    {"neon-blue", false, RGB(0, 0, 0), RGB(0, 0, 0), RGB(0, 200, 255), RGB(140, 70, 255), RGB(35, 20, 90),
     RGB(255, 225, 0), RGB(255, 50, 90), RGB(120, 255, 255), RGB(95, 45, 200)},
    // neon-purple: synthwave violet + cyan on black
    {"neon-purple", false, RGB(0, 0, 0), RGB(0, 0, 0), RGB(190, 60, 255), RGB(0, 190, 230), RGB(20, 50, 70),
     RGB(255, 225, 0), RGB(255, 60, 100), RGB(255, 70, 200), RGB(0, 125, 150)},
    // neon-yellow: volt yellow + orange on black
    {"neon-yellow", false, RGB(0, 0, 0), RGB(0, 0, 0), RGB(235, 255, 0), RGB(255, 110, 0), RGB(80, 35, 0),
     RGB(255, 170, 0), RGB(255, 45, 70), RGB(0, 255, 200), RGB(190, 85, 0)},
    // neon-ice: icy mint + blue on black
    {"neon-ice", false, RGB(0, 0, 0), RGB(0, 0, 0), RGB(0, 255, 230), RGB(90, 160, 255), RGB(15, 45, 80),
     RGB(255, 230, 40), RGB(255, 60, 90), RGB(255, 255, 255), RGB(60, 115, 200)},
    // pink: hot pink on dark plum
    {"pink", false, RGB(14, 0, 10), RGB(14, 0, 10), RGB(255, 70, 170), RGB(175, 45, 115), RGB(65, 12, 45),
     RGB(255, 200, 60), RGB(255, 40, 40), RGB(120, 240, 255), RGB(130, 30, 85)},
    // rosa: soft pastel rose on deep wine
    {"rosa", false, RGB(24, 6, 14), RGB(24, 6, 14), RGB(255, 170, 200), RGB(190, 110, 140), RGB(75, 35, 52),
     RGB(255, 215, 130), RGB(255, 90, 100), RGB(170, 230, 255), RGB(140, 80, 105)},
};
const int THEME_COUNT = sizeof(THEMES) / sizeof(THEMES[0]);

void applyTheme(int i) {
  if (i < 0 || i >= THEME_COUNT) i = 0;
  const Theme& t = THEMES[i];
  themeIdx = i;
  scanlines = t.scan;
  C_BG = t.bg; C_SCAN = t.scanc; C_FG = t.fg; C_DIM = t.dim; C_FAINT = t.faint;
  C_AMBER = t.amber; C_RED = t.red; C_CYAN = t.cyan; C_LOG = t.log;
}
void loadTheme() {
  prefs.begin("ui", true);
  int i = prefs.getUChar("theme", 0);
  prefs.end();
  applyTheme(i);
}
void cycleTheme(int dir = 1) {
  applyTheme((themeIdx + dir + THEME_COUNT) % THEME_COUNT);
  prefs.begin("ui", false);
  prefs.putUChar("theme", themeIdx);
  prefs.end();
}

float spdHist[110];  // speed scope history
int spdCount = 0;
float lastAccG = 1.0f;

bool blink(uint32_t ms = 500) { return (millis() / ms) & 1; }

void T(int x, int y, const String& s, uint16_t col, int font = 2) {
  cv.setTextFont(font);
  cv.setTextSize(1);
  cv.setTextColor(col);
  cv.setCursor(x, y);
  cv.print(s);
}
void TR(int xr, int y, const String& s, uint16_t col, int font = 2) {
  cv.setTextFont(font);
  cv.setTextSize(1);
  T(xr - cv.textWidth(s), y, s, col, font);
}
void bg() {
  cv.fillSprite(C_BG);
  if (scanlines) for (int y = 0; y < cv.height(); y += 3) cv.drawFastHLine(0, y, cv.width(), C_SCAN);  // CRT scanlines
}
void header(const String& title, const String& right = "", uint16_t rcol = C_DIM, uint16_t tcol = C_FG) {
  T(4, 1, "# " + title, tcol, 2);
  if (right.length()) TR(236, 1, right, rcol, 2);
  cv.drawFastHLine(0, 17, cv.width(), C_DIM);
}
void footer(const String& keys) {
  cv.drawFastHLine(0, 124, cv.width(), C_FAINT);
  T(4, 126, keys, C_DIM, 0);
}
void segBar(int x, int y, int w, int h, int pct, uint16_t col) {
  const int n = 20, gap = 2;
  int sw = (w - (n - 1) * gap) / n;
  for (int i = 0; i < n; i++) cv.fillRect(x + i * (sw + gap), y, sw, h, (i * 100 / n < pct) ? col : C_FAINT);
}
void scope(int x, int y, int w, int h, const char* label) {
  cv.drawRect(x, y, w, h, C_FAINT);
  for (int g = 1; g < 4; g++)
    for (int px = x + 2; px < x + w - 2; px += 4) cv.drawPixel(px, y + g * h / 4, C_FAINT);
  float mx = 25;
  for (int i = 0; i < spdCount; i++) if (spdHist[i] > mx) mx = spdHist[i];
  int pw = w - 2;
  int start = spdCount > pw ? spdCount - pw : 0;
  int px0 = 0, py0 = 0;
  for (int i = start; i < spdCount; i++) {
    int px = x + 1 + (i - start);
    int py = y + h - 2 - (int)(spdHist[i] / mx * (h - 4));
    if (i > start) cv.drawLine(px0, py0, px, py, C_FG);
    px0 = px; py0 = py;
  }
  T(x + 3, y + 2, label, C_DIM, 0);
  char b[12];
  snprintf(b, sizeof(b), "%.0f", mx);
  TR(x + w - 3, y + 2, b, C_DIM, 0);
}

uint16_t mapCol(uint16_t c) {
  if (c == RED) return C_RED;
  if (c == YELLOW) return C_AMBER;
  return C_FG;
}

void msg(const String& a, const String& b = "", uint16_t col = WHITE) {
  bg();
  header(APP_NAME);
  String line = "> " + a;
  T(6, 36, line, mapCol(col), line.length() <= 13 ? 4 : 2);
  if (b.length()) T(6, 74, b, C_DIM, 2);
  T(6, 100, blink() ? "_" : " ", C_FG, 2);
  cv.pushSprite(0, 0);
}

// ---------------- Storage ----------------
bool initStorage() {
  SPI.begin(40, 39, 14, 12);
  if (SD.begin(12, SPI, 25000000)) { fsys = &SD; fsName = "SD"; }
  else if (LittleFS.begin(true)) { fsys = &LittleFS; fsName = "FLASH"; }
  if (!fsys) return false;
  if (!fsys->exists("/rides")) fsys->mkdir("/rides");
  return true;
}

String nextRideName() {
  for (int i = 1; i < 1000; i++) {
    char b[32];
    snprintf(b, sizeof(b), "/rides/ride_%03d.csv", i);
    if (!fsys->exists(b)) return String(b);
  }
  return "/rides/ride_999.csv";
}

void startRecording() {
  if (!fsys || recording) return;
  logName = nextRideName();
  logFile = fsys->open(logName, FILE_WRITE);
  if (!logFile) return;
  logFile.println("ms,ax_g,ay_g,az_g,gx_dps,gy_dps,gz_dps,kmh,batt_pct,pack_v,pack_a,bat_t1,bat_t2");
  samples = 0;
  recording = true;
}

void stopRecording() {
  if (!recording) return;
  logFile.close();
  recording = false;
}

// ---------------- Token storage (per scooter) ----------------
String tokenKey(const NimBLEAddress& a) {
  String k = a.toString().c_str();
  k.replace(":", "");
  return k;
}
bool loadToken(const NimBLEAddress& a, uint8_t t[12]) {
  prefs.begin("scooter", true);
  size_t n = prefs.getBytes(tokenKey(a).c_str(), t, 12);
  prefs.end();
  return n == 12;
}
void saveToken(const NimBLEAddress& a, const uint8_t t[12]) {
  prefs.begin("scooter", false);
  prefs.putBytes(tokenKey(a).c_str(), t, 12);
  prefs.end();
}
void forgetToken(const NimBLEAddress& a) {
  prefs.begin("scooter", false);
  prefs.remove(tokenKey(a).c_str());
  prefs.end();
}

// ---------------- Notification plumbing ----------------
enum { SRC_UPNP = 1, SRC_AVDTP = 2 };
struct Notif { uint8_t src; uint8_t len; uint8_t d[64]; };
QueueHandle_t authQ = nullptr, frameQ = nullptr;

void pushQ(QueueHandle_t q, uint8_t src, const uint8_t* d, size_t n) {
  Notif m;
  m.src = src;
  m.len = n > sizeof(m.d) ? sizeof(m.d) : n;
  memcpy(m.d, d, m.len);
  xQueueSend(q, &m, 0);
}

// UART (NUS) reassembly: plain frames are 55 AA, encrypted ones 55 AB.
static uint8_t rb[96];
static size_t rl = 0;
void onUart(uint8_t* d, size_t n) {
  if (!scooterConnected) return;
  if (rl + n > sizeof(rb)) rl = 0;
  memcpy(rb + rl, d, n);
  rl += n;
  while (rl >= 3) {
    uint8_t h2 = sessionActive ? 0xAB : 0xAA;
    if (!(rb[0] == 0x55 && rb[1] == h2)) { memmove(rb, rb + 1, --rl); continue; }
    size_t tot = rb[2] + (sessionActive ? 16 : 6);
    if (tot > sizeof(((Notif*)0)->d)) { rl = 0; return; }
    if (rl < tot) return;
    pushQ(frameQ, 0, rb, tot);
    memmove(rb, rb + tot, rl - tot);
    rl -= tot;
  }
}

void onMotorInfo(const uint8_t* d, size_t dl) {
  if (dl < 22) return;
  tel.lastRx = millis();
  tel.batt = d[8] | (d[9] << 8);
  float v = fabsf((int16_t)(d[10] | (d[11] << 8)) / 1000.0f);
  uint32_t now = millis();
  if (lastSpeedT) tel.rideKm += v * (now - lastSpeedT) / 3600000.0f;
  lastSpeedT = now;
  tel.kmh = v;
  uint32_t totalM = d[14] | (d[15] << 8) | (d[16] << 16) | ((uint32_t)d[17] << 24);
  tel.totalKm = totalM / 1000.0f;
  if (dl >= 24) {  // frame / controller temperature, 0.1 deg C
    float t = (int16_t)(d[22] | (d[23] << 8)) / 10.0f;
    if (t > -40 && t < 150) bs.escTemp = t;
  }
}

// Route a decoded reply [addr, reg, data...] to the right parser.
void onReply(uint8_t addr, uint8_t reg, const uint8_t* d, size_t n) {
  uint32_t now = millis();
  if (addr == bat::ADDR_ESC_RX) {
    rxMotorN++;
    if (reg == REG_MOTOR_INFO) onMotorInfo(d, n);
    else if (reg == bat::REG_ESC_RANGE) bs.parseRange(d, n, now);
    else if (reg == 0x7B && n >= 6) {  // supplementary: brake(u16) cruise(u16) tail light(u16)
      rdBrake = d[0] | (d[1] << 8);
      rdTail = d[4] | (d[5] << 8);
    }
  } else if (addr == bat::ADDR_BMS_RX) {
    rxBmsN++;
    bool ok = false;
    if (reg == bat::REG_LIVE) ok = bs.parseLive(d, n, now, tel.rideKm);
    else if (reg == bat::REG_CELLS) ok = bs.parseCells(d, n, now);
    else if (reg == bat::REG_INFO) ok = bs.parseInfo(d, n);
    else if (reg == bat::REG_DATE) ok = bs.parseDate(d, n);
    else return;
    if (!ok) { rxBmsBad++; dbgf("bms reg %02x rejected n=%u", reg, (unsigned)n); }
  }
}

void processFrames() {
  Notif m;
  while (xQueueReceive(frameQ, &m, 0) == pdTRUE) {
    if (sessionActive) {
      uint8_t dec[80];
      int n = mi::decrypt_uart(keys.dev, m.d, m.len, dec);
      // dec = [addr, cmd, reg, data..., rand4]
      if (n >= 7) onReply(dec[0], dec[2], dec + 3, n - 7);
    } else {
      uint16_t s = 0;
      for (size_t i = 2; i < (size_t)m.len - 2; i++) s += m.d[i];
      s ^= 0xFFFF;
      if (s != (uint16_t)(m.d[m.len - 2] | (m.d[m.len - 1] << 8))) continue;
      if (m.len >= 8 && m.d[2] >= 2) onReply(m.d[3], m.d[5], m.d + 6, m.d[2] - 2);
    }
  }
}

// Read `len` bytes starting at register `reg` of device `addr` (0x20 = ESC, 0x22 = BMS).
void sendRead(uint8_t addr, uint8_t reg, uint8_t len) {
  if (!scooterConnected || !rxChar) return;
  uint8_t out[48];
  size_t n;
  if (sessionActive) {
    const uint8_t req[5] = {3, addr, 0x01, reg, len};
    n = mi::encrypt_uart(keys.app, req, 5, 0, nullptr, out);
  } else {
    uint8_t f[9] = {0x55, 0xAA, 0x03, addr, 0x01, reg, len, 0, 0};
    uint16_t s = 0;
    for (int i = 2; i < 7; i++) s += f[i];
    s ^= 0xFFFF;
    f[7] = s & 0xFF; f[8] = s >> 8;
    memcpy(out, f, 9);
    n = 9;
  }
  for (size_t o = 0; o < n; o += 20) rxChar->writeValue(out + o, min((size_t)20, n - o), false);
}

void sendMotorInfoReq() { sendRead(bat::ADDR_ESC_TX, REG_MOTOR_INFO, 0x20); }

// ---------------- Scooter control (writes) ----------------
// Xiaomi M365 / Pro / Pro 2 ESC registers (write = command 0x03 to device 0x20).
constexpr uint8_t REG_LOCK = 0x70;        // write 0x0001 = lock motor
constexpr uint8_t REG_UNLOCK = 0x71;      // write 0x0001 = unlock motor
constexpr uint8_t REG_BRAKE_KERS = 0x7B;  // motor brake / energy recovery: 0 weak, 1 medium, 2 strong
constexpr uint8_t REG_TAIL = 0x7D;        // TAIL light mode: 0 off, 1 on while braking, 2 always on
// HEADLIGHT. Unlike the tail light (ESC register 0x7D) the Xiaomi headlight is part of the dashboard
// assembly and no public protocol document lists a register for it. Fill these in once you know
// what your scooter accepts (target board, register, on/off words). HEAD_REG = 0 means "not set":
// the G key / settings row then just says so and nothing is written to the scooter.
constexpr uint8_t HEAD_ADDR = bat::ADDR_ESC_TX;  // board that owns the headlight register
constexpr uint8_t HEAD_REG = 0x00;               // register to write (0 = not configured)
constexpr uint16_t HEAD_ON = 1, HEAD_OFF = 0;    // values for on / off
const char* BRAKE_NAMES[3] = {"weak", "medium", "strong"};
const char* TAIL_NAMES[3] = {"off", "brake", "always"};

bool scooterLocked = false;  // last state we commanded (a power-cycled scooter comes back unlocked)
bool headOn = false;         // last headlight state we commanded
int tailMode = 1;            // tail light mode (follows what the scooter reports once it answers)
int brakeLevel = 1;          // motor brake level, saved in prefs
int alarmMode = 1;           // 0 off, 1 wheel movement, 2 wheel movement + shake (IMU), saved in prefs
String ctlNote;              // one-line result of the last command, shown on screen
uint32_t ctlNoteAt = 0;
uint32_t suppReadAt = 0;     // when to ask the scooter for its brake / tail-light state (0 = not scheduled)
uint32_t lockedAt = 0, alarmUntil = 0, lastBeepAt = 0;
float shakeEma = 0, prevG = 1.0f;
constexpr float ALARM_KMH = 0.5f;     // wheel speed that counts as "moved" while locked
constexpr float ALARM_SHAKE = 0.06f;  // IMU jitter (g) that counts as "moved" in shake mode - tune if needed
const char* ALARM_NAMES[3] = {"off", "wheel", "wheel+shake"};

void setNote(const String& s) { ctlNote = s; ctlNoteAt = millis(); }
void askScooterState(uint32_t inMs = 400) { suppReadAt = millis() + inMs; }

// Write a 16-bit value to an ESC register.
bool sendWrite16To(uint8_t addr, uint8_t reg, uint16_t val) {
  if (!scooterConnected || !rxChar) { setNote("no link"); return false; }
  uint8_t out[48];
  size_t n;
  if (sessionActive) {
    const uint8_t req[6] = {4, addr, 0x03, reg, (uint8_t)(val & 0xFF), (uint8_t)(val >> 8)};
    n = mi::encrypt_uart(keys.app, req, 6, 0, nullptr, out);
    if (!n) { setNote("encrypt failed"); return false; }
  } else {
    uint8_t f[10] = {0x55, 0xAA, 0x04, addr, 0x03, reg, (uint8_t)(val & 0xFF), (uint8_t)(val >> 8), 0, 0};
    uint16_t sum = 0;
    for (int i = 2; i < 8; i++) sum += f[i];
    sum ^= 0xFFFF;
    f[8] = sum & 0xFF; f[9] = sum >> 8;
    memcpy(out, f, 10);
    n = 10;
  }
  for (size_t o = 0; o < n; o += 20) rxChar->writeValue(out + o, min((size_t)20, n - o), false);
  return true;
}

bool sendWrite16(uint8_t reg, uint16_t val) { return sendWrite16To(bat::ADDR_ESC_TX, reg, val); }

// Motor lock. Refused while rolling so the scooter can't be locked mid-ride.
void setLock(bool lock) {
  if (lock && tel.kmh > 1.0f) { setNote("stop first (moving)"); return; }
  if (sendWrite16(lock ? REG_LOCK : REG_UNLOCK, 1)) {
    scooterLocked = lock;
    lockedAt = millis();
    alarmUntil = 0;
    shakeEma = 0;
    setNote(lock ? "motor LOCKED" : "motor unlocked");
  }
}

void setTail(int mode) {
  mode = ((mode % 3) + 3) % 3;
  if (sendWrite16(REG_TAIL, mode)) {
    tailMode = mode;
    setNote(String("tail light: ") + TAIL_NAMES[mode]);
    askScooterState();
  }
}

void setHead(bool on) {
  if (HEAD_REG == 0) { setNote("headlight: set HEAD_REG"); return; }
  if (sendWrite16To(HEAD_ADDR, HEAD_REG, on ? HEAD_ON : HEAD_OFF)) {
    headOn = on;
    setNote(on ? "headlight ON" : "headlight OFF");
  }
}

void setBrake(int level, bool save = true) {
  level = constrain(level, 0, 2);
  if (sendWrite16(REG_BRAKE_KERS, level)) {
    brakeLevel = level;
    setNote(String("brake: ") + BRAKE_NAMES[level]);
    askScooterState();
    if (save) {
      prefs.begin("ui", false);
      prefs.putUChar("brake", brakeLevel);
      prefs.end();
    }
  }
}

void loadScooterSettings() {
  prefs.begin("ui", true);
  brakeLevel = constrain((int)prefs.getUChar("brake", 1), 0, 2);
  alarmMode = constrain((int)prefs.getUChar("alarm", 1), 0, 2);
  prefs.end();
}

// Called once after a fresh connect: push the saved brake level, reset local lock/light state.
void applySavedScooterSettings() {
  scooterLocked = false;
  headOn = false;
  rdBrake = rdTail = -1;
  alarmUntil = 0;
  delay(150);
  setBrake(brakeLevel, false);
  askScooterState(600);
}

void cycleAlarm(int dir = 1) {
  alarmMode = (alarmMode + dir + 3) % 3;
  alarmUntil = 0;
  prefs.begin("ui", false);
  prefs.putUChar("alarm", alarmMode);
  prefs.end();
  setNote(String("alarm: ") + ALARM_NAMES[alarmMode]);
}

// Ask the scooter for brake / tail-light state when due, so the screen shows the real values.
void suppTick() {
  if (suppReadAt && (int32_t)(millis() - suppReadAt) >= 0) {
    suppReadAt = 0;
    sendRead(bat::ADDR_ESC_TX, REG_BRAKE_KERS, 6);
  }
  if (rdTail >= 0 && rdTail <= 2) tailMode = rdTail;  // trust the scooter
}

// Locked + moved => loud two-tone beep (and on-screen banner) for 4 s after the last movement.
void alarmTick() {
  if (!scooterLocked || alarmMode == 0 || !scooterConnected) { alarmUntil = 0; return; }
  if (millis() - lockedAt < 2500) return;  // let the lock settle / hand off the scooter
  bool moved = tel.kmh >= ALARM_KMH || (alarmMode == 2 && shakeEma > ALARM_SHAKE);
  if (moved) alarmUntil = millis() + 4000;
  if (millis() < alarmUntil && millis() - lastBeepAt > 330) {
    lastBeepAt = millis();
    static bool hi = false;
    hi = !hi;
    M5Cardputer.Speaker.tone(hi ? 3200 : 2300, 280);
  }
}
bool alarmActive() { return millis() < alarmUntil; }
void drawAlarmBanner() {
  if (!alarmActive()) return;
  bool on = blink(200);
  cv.fillRect(0, 19, cv.width(), 42, on ? C_RED : C_BG);
  cv.drawRect(0, 19, cv.width(), 42, C_RED);
  T(20, 30, "! MOVED WHILE LOCKED !", on ? C_BG : C_RED, 2);
}

// ---------------- Pairing UI ----------------
const char* pairStatus = "";
uint32_t cdStart = 0, cdTotal = 0;  // countdown for long waits

void drawPairPrompt() {
  bg();
  uint32_t el = millis() - cdStart;
  uint32_t left = (cdTotal && el < cdTotal) ? (cdTotal - el) / 1000 : 0;
  header("pairing", cdTotal ? String(left) + "s" : String(scooterConnected ? "LINK" : "..."), C_AMBER, C_AMBER);
  T(6, 22, String("> ") + pairStatus, C_CYAN, 2);
  if (cdTotal) {
    uint16_t c = blink(400) ? C_AMBER : C_DIM;
    T(8, 44, "PRESS POWER", c, 4);
    T(8, 70, "BUTTON NOW", c, 4);
    int w = el >= cdTotal ? 0 : (int)((uint64_t)(cdTotal - el) * 228 / cdTotal);
    cv.drawRect(4, 102, 232, 10, C_DIM);
    cv.fillRect(6, 104, w, 6, C_AMBER);
  } else {
    T(6, 42, "press POWER on the scooter", C_DIM, 2);
    T(6, 58, "when it beeps / blinks", C_DIM, 2);
    for (int i = 4; i < 8; i++) T(6, 80 + (i - 4) * 10, dbgLines[i], C_LOG, 0);
  }
  footer("[Q] cancel");
  cv.pushSprite(0, 0);
}

void setPairStatus(const char* s, uint32_t countdownMs = 0) {
  pairStatus = s;
  cdTotal = countdownMs;
  cdStart = millis();
  drawPairPrompt();
}

// ---------------- Xiaomi auth helpers ----------------
bool is(const Notif& m, const uint8_t* c, size_t n = 4) { return m.len == n && !memcmp(m.d, c, n); }

void drainAuth() { Notif m; while (xQueueReceive(authQ, &m, 0) == pdTRUE) {} }

bool waitNotif(Notif& m, uint8_t src, uint32_t ms) {
  uint32_t t0 = millis(), lastDraw = 0;
  while (millis() - t0 < ms) {
    if (xQueueReceive(authQ, &m, pdMS_TO_TICKS(20)) == pdTRUE) {
      dbgHex(m.src == SRC_UPNP ? "rx UPNP" : "rx AVDTP", m.d, m.len);
      if (src == 0 || m.src == src) return true;
    }
    { char kk = getKey(); if (kk == 'q' || kk == KEY_BACK) { cancelled = true; dbgf("cancelled by user"); return false; } }
    if (!scooterConnected) { dbgf("link dropped while waiting"); logDrop(); return false; }
    if (cdTotal && millis() - lastDraw > 250) { lastDraw = millis(); drawPairPrompt(); }
  }
  dbgf("timeout %lus (src %d)", (unsigned long)(ms / 1000), src);
  return false;
}

void writeCmd(NimBLERemoteCharacteristic* c, const uint8_t* b, size_t n) {
  dbgHex(c == upnp ? "tx UPNP" : "tx AVDTP", b, n);
  if (!c->writeValue(b, n, false)) dbgf("WRITE FAILED");
}

void writeParcel(NimBLERemoteCharacteristic* c, const uint8_t* d, size_t n) {
  uint8_t buf[20], idx = 1;
  for (size_t o = 0; o < n; o += 18, idx++) {
    size_t cl = min((size_t)18, n - o);
    buf[0] = idx; buf[1] = 0;
    memcpy(buf + 2, d + o, cl);
    c->writeValue(buf, cl + 2, false);
    delay(5);
  }
}

bool readParcel(uint8_t* out, size_t maxLen, size_t& outLen, uint32_t toMs = 5000) {
  Notif m;
  if (!waitNotif(m, SRC_AVDTP, toMs) || m.len < 6) return false;
  uint16_t total = m.d[4] | (m.d[5] << 8), cur = 0;
  writeCmd(avdtp, RCV_RDY, 4);
  outLen = 0;
  while (cur < total) {
    if (!waitNotif(m, SRC_AVDTP, toMs) || m.len < 3) return false;
    cur = m.d[0] | (m.d[1] << 8);
    size_t c = m.len - 2;
    if (outLen + c > maxLen) return false;
    memcpy(out + outLen, m.d + 2, c);
    outLen += c;
  }
  writeCmd(avdtp, RCV_OK, 4);
  return true;
}

enum RegResult { REG_OK, REG_RETRY, REG_FAIL };

// Registration: key exchange + DID, then the scooter waits for the POWER button.
RegResult doRegister(uint8_t token[12]) {
  drainAuth();
  Notif m;
  setPairStatus("Exchanging keys...");
  mi::KeyPair kp;
  uint8_t pub[64];
  if (!mi::gen_keypair(kp, pub)) return REG_FAIL;

  uint8_t info[64];
  size_t il = 0;
  dbgf("step: GET_INFO");
  writeCmd(upnp, CMD_GET_INFO, 4);
  if (!readParcel(info, sizeof(info), il)) return cancelled ? REG_FAIL : REG_RETRY;

  writeCmd(upnp, CMD_SET_KEY, 4);
  writeCmd(avdtp, CMD_SEND_DATA, 6);
  dbgf("step: SET_KEY/SEND_DATA");
  if (!waitNotif(m, 0, 2000)) return cancelled ? REG_FAIL : REG_RETRY;
  if (!is(m, RCV_RDY)) { dbgf("expected RDY"); return REG_RETRY; }
  writeParcel(avdtp, pub, 64);
  if (!waitNotif(m, 0, 3000) || !is(m, RCV_OK)) { dbgf("pubkey not acked"); return cancelled ? REG_FAIL : REG_RETRY; }

  dbgf("step: read scooter key");
  uint8_t rk[80];
  size_t rkl = 0;
  if (!readParcel(rk, sizeof(rk), rkl) || rkl < 64) return cancelled ? REG_FAIL : REG_RETRY;

  uint8_t did[72];
  size_t dl = 0;
  if (il > 60 || !mi::calc_did(kp, rk, info, il, did, &dl, token)) return REG_FAIL;
  dbgf("step: send DID");
  writeCmd(avdtp, CMD_SEND_DID, 6);
  for (;;) {
    if (!waitNotif(m, 0, 3000)) return cancelled ? REG_FAIL : REG_RETRY;
    if (is(m, RCV_RDY)) writeParcel(avdtp, did, dl);
    else if (is(m, RCV_OK)) break;
    else return REG_RETRY;
  }

  setPairStatus("PRESS POWER BUTTON NOW", 30000);
  dbgf("step: AUTH (button)");
  writeCmd(upnp, CMD_AUTH, 4);
  if (!waitNotif(m, 0, 30000)) return cancelled ? REG_FAIL : REG_RETRY;
  if (!is(m, RCV_AUTH_OK)) { dbgf("AUTH rejected by scooter"); return REG_RETRY; }
  return REG_OK;
}

bool loginTokenRejected = false;

bool doLogin(const uint8_t token[12], mi::Keychain& kc) {
  drainAuth();
  loginTokenRejected = false;
  Notif m;
  uint8_t myr[16];
  MI_FILL_RANDOM(myr, 16);
  dbgf("step: LOGIN");
  writeCmd(upnp, CMD_LOGIN, 4);
  writeCmd(avdtp, CMD_SEND_KEY, 6);
  if (!waitNotif(m, SRC_AVDTP, 3000) || !is(m, RCV_RDY)) return false;
  writeParcel(avdtp, myr, 16);
  if (!waitNotif(m, SRC_AVDTP, 3000) || !is(m, RCV_OK)) return false;

  uint8_t rr[32], ri[64];
  size_t n1 = 0, n2 = 0;
  if (!readParcel(rr, sizeof(rr), n1) || n1 != 16) return false;
  if (!readParcel(ri, sizeof(ri), n2) || n2 != 32) return false;

  uint8_t info[32], expct[32];
  if (!mi::calc_login(myr, rr, token, info, expct, kc)) return false;
  if (memcmp(ri, expct, 32) != 0) { loginTokenRejected = true; dbgf("login: token mismatch"); return false; }

  writeCmd(avdtp, CMD_SEND_INFO, 6);
  if (!waitNotif(m, SRC_AVDTP, 3000) || !is(m, RCV_RDY)) return false;
  writeParcel(avdtp, info, 32);
  if (!waitNotif(m, SRC_AVDTP, 3000) || !is(m, RCV_OK)) return false;
  if (!waitNotif(m, SRC_UPNP, 5000)) return false;
  return is(m, RCV_LOGIN_OK);
}

// ---------------- BLE client (scooter) ----------------
uint32_t promptPasskey() {
  String s;
  while (true) {
    bg();
    header("passkey", "", C_DIM, C_AMBER);
    T(6, 26, "scooter wants a pairing code", C_DIM, 2);
    T(6, 56, "> " + s + (blink() ? "_" : " "), C_FG, 4);
    footer("digits  [DEL] erase  [ENT] ok");
    cv.pushSprite(0, 0);
    M5Cardputer.update();
    if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
      auto st = M5Cardputer.Keyboard.keysState();
      for (char c : st.word) if (isdigit(c) && s.length() < 6) s += c;
      if (st.del && s.length()) s.remove(s.length() - 1);
      if (st.enter) return s.toInt();
    }
    delay(20);
  }
}

class ClientCb : public NimBLEClientCallbacks {
  void onConnect(NimBLEClient*) override {}
  void onDisconnect(NimBLEClient*) override { scooterConnected = false; sessionActive = false; }
  uint32_t onPassKeyRequest() override { return promptPasskey(); }
  bool onConfirmPIN(uint32_t pin) override {
    msg("Confirm code", String(pin), YELLOW);
    for (uint32_t t = millis(); millis() - t < 15000;) {
      char k = getKey();
      if (k == '\n') return true;
      if (k == 'q' || k == KEY_BACK) return false;
      delay(20);
    }
    return false;
  }
} clientCb;

// UUIDs are compared as normalized lowercase 128-bit strings, so 16-bit and 128-bit forms both match.
static std::string normUuid(const NimBLEUUID& u) {
  std::string s = u.toString();
  for (auto& c : s) c = tolower(c);
  if (s.rfind("0x", 0) == 0) {
    s = s.substr(2);
    while (s.size() < 8) s = "0" + s;
    s += "-0000-1000-8000-00805f9b34fb";
  }
  return s;
}
static bool uuidIs(const NimBLEUUID& u, const char* full) {
  std::string t = full;
  for (auto& c : t) c = tolower(c);
  return normUuid(u) == t;
}
static bool uuidIs16(const NimBLEUUID& u, uint16_t id) {
  char b[40];
  snprintf(b, sizeof(b), "0000%04x-0000-1000-8000-00805f9b34fb", id);
  return uuidIs(u, b);
}

NimBLERemoteCharacteristic* findChar16(NimBLERemoteService* svc, uint16_t id) {
  for (auto* c : *svc->getCharacteristics(true)) if (uuidIs16(c->getUUID(), id)) return c;
  return nullptr;
}

// Connect GATT, resolve characteristics and subscribe.
// Uses full service/characteristic discovery (no per-UUID lookups, which some
// old scooter BLE stacks answer badly) and logs what the scooter exposes.
bool linkUp(const NimBLEAddress& a) {
  scooterConnected = false;
  sessionActive = false;
  rxChar = txChar = upnp = avdtp = nullptr;
  if (client) {
    if (client->isConnected()) client->disconnect();
    NimBLEDevice::deleteClient(client);
    client = nullptr;
  }
  rl = 0;
  drainAuth();
  client = NimBLEDevice::createClient();
  client->setClientCallbacks(&clientCb, false);
  client->setConnectTimeout(10);
  // MOD: longer supervision timeout (4 s) so a scooter that goes quiet for a moment
  // right after connect does not get dropped with HCI 0x08 "link timeout".
  client->setConnectionParams(24, 40, 0, 400);
  dbgf("connecting %s", a.toString().c_str());
  if (!client->connect(a)) { dbgf("GATT connect failed"); logDrop(); return false; }
  scooterConnected = true;
  if (BLE_BONDING) client->secureConnection();
  delay(50);

  NimBLERemoteService *uart = nullptr, *auth = nullptr;
  auto* svcs = client->getServices(true);
  String list;
  for (auto* sv : *svcs) {
    list += normUuid(sv->getUUID()).substr(0, 8).c_str();
    list += " ";
    if (uuidIs(sv->getUUID(), "6e400001-b5a3-f393-e0a9-e50e24dcca9e")) uart = sv;
    else if (uuidIs16(sv->getUUID(), UUID_AUTH_SVC)) auth = sv;
  }
  dbgf("svc %s", list.c_str());
  if (!uart) { dbgf("no UART service"); return false; }

  // Xiaomi auth service first: get to the notification subscriptions as fast as possible after
  // connecting (the scooter may hang up on a central that dawdles).
  cryptoMode = auth != nullptr;
  if (auth) {
    upnp = findChar16(auth, UUID_UPNP);
    avdtp = findChar16(auth, UUID_AVDTP);
    if (!upnp || !avdtp) { dbgf("UPNP/AVDTP chars missing"); logDrop(); return false; }
    if (!avdtp->subscribe(true, [](NimBLERemoteCharacteristic*, uint8_t* d, size_t n, bool) { pushQ(authQ, SRC_AVDTP, d, n); })) { dbgf("subscribe AVDTP failed"); logDrop(); return false; }
    if (!upnp->subscribe(true, [](NimBLERemoteCharacteristic*, uint8_t* d, size_t n, bool) { pushQ(authQ, SRC_UPNP, d, n); })) { dbgf("subscribe UPNP failed"); logDrop(); return false; }
    dbgf("auth subscribed t+%lums", (unsigned long)(millis() - gapConnAt));
  }

  // Discovery can come back empty right after connect. Retry, then fall back
  // to by-UUID lookup, and log whether the link is still alive.
  for (int attempt = 0; attempt < 3 && !(rxChar && txChar); attempt++) {
    if (!client->isConnected()) { logDrop(); return false; }
    if (attempt) delay(500);
    rxChar = txChar = nullptr;
    String cl;
    for (auto* c : *uart->getCharacteristics(true)) {
      std::string id = normUuid(c->getUUID());
      cl += id.substr(0, 8).c_str();
      cl += c->canNotify() ? "n" : "";
      cl += (c->canWrite() || c->canWriteNoResponse()) ? "w" : "";
      cl += " ";
      if (id == "6e400002-b5a3-f393-e0a9-e50e24dcca9e") rxChar = c;
      else if (id == "6e400003-b5a3-f393-e0a9-e50e24dcca9e") txChar = c;
    }
    dbgf("uart[%d] %s", attempt, cl.c_str());
  }
  if (!rxChar || !txChar) {  // by-UUID discovery
    rxChar = uart->getCharacteristic(NUS_RX_WRITE);
    txChar = uart->getCharacteristic(NUS_TX_NOTIFY);
    dbgf("by-uuid rx=%d tx=%d", rxChar != nullptr, txChar != nullptr);
  }
  if (!rxChar || !txChar) {  // fallback: pick by properties
    for (auto* c : *uart->getCharacteristics(false)) {
      if (!rxChar && c != txChar && (c->canWriteNoResponse() || c->canWrite())) rxChar = c;
      if (!txChar && c != rxChar && c->canNotify()) txChar = c;
    }
    if (rxChar && txChar) dbgf("uart chars picked by props");
  }
  if (!rxChar || !txChar) { dbgf("UART chars missing"); logDrop(); return false; }

  if (!txChar->subscribe(true, [](NimBLERemoteCharacteristic*, uint8_t* d, size_t n, bool) { onUart(d, n); })) { dbgf("subscribe UART failed"); logDrop(); return false; }
  dbgf("link up, %s mode", cryptoMode ? "secure" : "plain");
  delay(300);
  return true;
}

// MOD: after the POWER button press the scooter resets its BLE stack and needs a few
// seconds before it advertises again. Instead of one blind reconnect, wait, check that it
// is advertising, and retry with growing back-off.
bool linkUpRetry(const NimBLEAddress& a, int tries = 6) {
  if (WiFi.getMode() != WIFI_OFF) WiFi.mode(WIFI_OFF);  // keep the radio free for BLE
  for (int i = 0; i < tries; i++) {
    char st[32];
    snprintf(st, sizeof(st), "Reconnecting %d/%d", i + 1, tries);
    setPairStatus(st);
    delay(1500 + i * 1000);
    // short scan: is the scooter advertising again?
    NimBLEScan* sc = NimBLEDevice::getScan();
    sc->setActiveScan(true);
    NimBLEScanResults r = sc->start(2, false);
    bool seen = false;
    for (int k = 0; k < r.getCount(); k++) if (r.getDevice(k).getAddress() == a) { seen = true; break; }
    sc->clearResults();
    dbgf("retry %d seen=%d", i + 1, seen);
    if (!seen && i < tries - 1) continue;   // not advertising yet, wait longer
    if (linkUp(a)) return true;
    if (cancelled) return false;
  }
  return false;
}

void failMsg(const char* a, const char* b = "") {
  if (client && client->isConnected()) client->disconnect();
  scooterConnected = false;
  sessionActive = false;
  dbgf("FAIL: %s", a);
  bg();
  header("error", "", C_RED, C_RED);
  T(6, 20, String("! ") + a + (*b ? String(" - ") + b : String("")), C_RED, 2);
  for (int i = 0; i < 6; i++) T(4, 40 + i * 12, dbgLines[2 + i], C_DIM, 0);
  footer("any key = continue");
  cv.pushSprite(0, 0);
  for (uint32_t t = millis(); millis() - t < 60000;) { if (getKey()) break; delay(20); }
}

bool connectScooter(const NimBLEAddress& a) {
  cancelled = false;
  cdTotal = 0;
  msg("Connecting...", a.toString().c_str());
  if (!linkUp(a) && !linkUpRetry(a, 2)) { failMsg("Connect failed"); return false; }

  if (cryptoMode) {
    uint8_t token[12];
    bool loggedIn = false;
    if (loadToken(a, token)) {
      setPairStatus("Logging in...");
      loggedIn = doLogin(token, keys);
      if (cancelled) { failMsg("Cancelled"); return false; }
    }
    if (!loggedIn) {
      bool reg = false;
      for (int attempt = 0; attempt < 3 && !reg; attempt++) {
        setPairStatus(attempt ? "Retrying - press POWER" : "Starting registration...");
        RegResult r = doRegister(token);
        if (r == REG_OK) { reg = true; break; }
        if (cancelled) { failMsg("Cancelled"); return false; }
        setPairStatus("Press POWER, reconnecting");
        if (!linkUpRetry(a)) { failMsg("Reconnect failed"); return false; }
      }
      if (!reg) { failMsg("Pairing failed", "Scooter did not confirm"); return false; }
      saveToken(a, token);
      setPairStatus("Paired! Logging in...");
      if (!linkUpRetry(a)) { failMsg("Reconnect failed"); return false; }
      if (!doLogin(token, keys)) {
        if (loginTokenRejected) forgetToken(a);
        failMsg("Login failed", "Try again");
        return false;
      }
    }
    sessionActive = true;
  }

  scooterAddr = a;
  haveScooter = true;
  lastSpeedT = 0;
  cdTotal = 0;
  msg(cryptoMode ? "Logged in" : "Connected (plain)", "Starting dashboard", GREEN);
  delay(600);
  return true;
}

void scanScooters() {
  msg("Scanning...", "5 s");
  devs.clear();
  NimBLEScan* sc = NimBLEDevice::getScan();
  sc->setActiveScan(true);
  NimBLEScanResults r = sc->start(5, false);
  for (int i = 0; i < r.getCount(); i++) {
    NimBLEAdvertisedDevice d = r.getDevice(i);
    String n = d.getName().c_str();
    bool match = n.indexOf("Scooter") >= 0 || d.isAdvertisingService(NUS_SVC);
    if (!showAll && !match) continue;
    if (n.length() == 0) n = "(unnamed)";
    uint8_t tk[12];
    devs.push_back({d.getAddress(), n, d.getRSSI(), loadToken(d.getAddress(), tk)});
  }
  sc->clearResults();
  sel = 0;
}

// ---------------- Export: WiFi ----------------
bool safeName(const String& n) {
  return n.length() && n.indexOf('/') < 0 && n.indexOf("..") < 0;
}

void handleRoot() {
  String h = "<html><head><meta name=viewport content='width=device-width'><title>" APP_NAME "</title></head><body>"
             "<h2>" APP_NAME " rides</h2><ul>";
  File dir = fsys->open("/rides");
  File f;
  while ((f = dir.openNextFile())) {
    String n = f.name();
    h += "<li><a href='/f?n=" + n + "'>" + n + "</a> (" + String((unsigned)f.size() / 1024) +
         " kB) &nbsp; <a href='/del?n=" + n + "'>delete</a></li>";
  }
  h += "</ul></body></html>";
  web.send(200, "text/html", h);
}

void handleGet() {
  String n = web.arg("n");
  if (!safeName(n)) { web.send(400, "text/plain", "bad name"); return; }
  File f = fsys->open("/rides/" + n);
  if (!f) { web.send(404, "text/plain", "not found"); return; }
  web.sendHeader("Content-Disposition", "attachment; filename=" + n);
  web.streamFile(f, "text/csv");
  f.close();
}

void handleDel() {
  String n = web.arg("n");
  if (safeName(n)) fsys->remove("/rides/" + n);
  web.sendHeader("Location", "/");
  web.send(303);
}

void startWifiExport() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  web.on("/", handleRoot);
  web.on("/f", handleGet);
  web.on("/del", handleDel);
  web.begin();
}

void stopWifiExport() {
  web.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
}

// ---------------- Export: BLE ----------------
NimBLEServer* expServer = nullptr;
NimBLECharacteristic* expData = nullptr;
String expReq, txBuf;
volatile bool expPending = false;
size_t txPos = 0;
File xf;
bool sendEof = false;

class CmdCb : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic* c) override {
    expReq = String(c->getValue().c_str());
    expPending = true;
  }
};
CmdCb cmdCb;

void startBleExport() {
  NimBLEDevice::setMTU(185);
  if (!expServer) {
    expServer = NimBLEDevice::createServer();
    NimBLEService* s = expServer->createService(EXP_SVC);
    NimBLECharacteristic* cmd = s->createCharacteristic(EXP_CMD, NIMBLE_PROPERTY::WRITE);
    cmd->setCallbacks(&cmdCb);
    expData = s->createCharacteristic(EXP_DATA, NIMBLE_PROPERTY::NOTIFY);
    s->start();
  }
  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(EXP_SVC);
  adv->setName(APP_NAME);
  adv->start();
}

void stopBleExport() {
  NimBLEDevice::getAdvertising()->stop();
  if (xf) xf.close();
  txBuf = "";
  txPos = 0;
  sendEof = false;
}

void pumpBleExport() {
  if (expPending) {
    expPending = false;
    if (xf) xf.close();
    txBuf = "";
    txPos = 0;
    if (expReq.startsWith("LIST")) {
      File dir = fsys->open("/rides");
      File f;
      while ((f = dir.openNextFile())) txBuf += String(f.name()) + "," + String((unsigned)f.size()) + "\n";
      sendEof = true;
    } else if (expReq.startsWith("GET ")) {
      String n = expReq.substring(4);
      n.trim();
      if (safeName(n)) xf = fsys->open("/rides/" + n);
      sendEof = true;
    }
  }
  if (!expData || expServer->getConnectedCount() == 0) return;
  size_t chunk = NimBLEDevice::getMTU() - 3;
  if (chunk < 20) chunk = 20;
  if (chunk > 180) chunk = 180;
  uint8_t buf[180];
  size_t n = 0;
  if (txPos < txBuf.length()) {
    n = min(chunk, txBuf.length() - txPos);
    memcpy(buf, txBuf.c_str() + txPos, n);
    txPos += n;
  } else if (xf && xf.available()) {
    n = xf.read(buf, chunk);
  } else if (sendEof) {
    const char* e = "\n#EOF\n";
    memcpy(buf, e, 6);
    n = 6;
    sendEof = false;
    if (xf) xf.close();
  }
  if (n) {
    expData->setValue(buf, n);
    expData->notify();
    delay(8);
  }
}

// ---------------- UI ----------------
void drawHome() {
  bg();
  T(6, 4, APP_NAME, C_FG, 4);
  T(6, 34, "// xiaomi telemetry + imu recorder", C_DIM, 0);
  cv.drawFastHLine(4, 46, 232, C_DIM);
  T(10, 52, "[S]", C_FG, 2);  T(46, 52, "scan & ride", C_FG, 2);
  T(10, 70, "[W]", C_FG, 2);  T(46, 70, "export :: wifi", C_FG, 2);
  T(10, 88, "[B]", C_FG, 2);  T(46, 88, "export :: ble", C_FG, 2);
  cv.drawFastHLine(0, 108, 240, C_FAINT);
  T(4, 111, String("root@scooter:~$ ") + (blink() ? "_" : " "), C_FG, 2);
  T(4, 127, String("storage:") + fsName, C_DIM, 0);
  TR(236, 127, "v2.0", C_DIM, 0);
  TR(236, 114, String("[T] theme: ") + THEMES[themeIdx].name, C_DIM, 0);
  cv.pushSprite(0, 0);
}

void drawScan() {
  bg();
  header("scan", String((int)devs.size()) + (showAll ? " all" : " found"));
  if (devs.empty()) {
    T(6, 30, "> no scooters in range", C_AMBER, 2);
    T(6, 48, "  [S] rescan   [A] show all", C_DIM, 2);
  }
  int top = sel > 5 ? sel - 5 : 0;
  for (int i = top; i < (int)devs.size() && i < top + 6; i++) {
    int y = 20 + (i - top) * 16;
    bool on = i == sel;
    if (on) cv.fillRect(0, y, 240, 16, C_FG);
    uint16_t c = on ? C_BG : C_FG;
    String n = devs[i].name;
    if (n.length() > 14) n = n.substring(0, 14);
    T(4, y, (on ? "> " : "  ") + n, c, 2);
    char r[16];
    snprintf(r, sizeof(r), "%ddBm", devs[i].rssi);
    TR(236, y, r, on ? C_BG : C_DIM, 2);
    if (devs[i].paired) T(150, y, "[KEY]", on ? C_BG : C_AMBER, 0);
  }
  footer(";/. move  ENT connect  A all  F forget  Q back");
  cv.pushSprite(0, 0);
}

// Battery temperature colour: cold (<0) cyan, normal green, warm amber, hot red.
uint16_t tempColor(int c) { return c < 0 ? C_CYAN : (c <= 45 ? C_FG : (c <= 55 ? C_AMBER : C_RED)); }

void drawRideTerminal() {
  bg();
  const char* st = scooterConnected ? (sessionActive ? "SECURE" : "LINK") : "NO LINK";
  uint16_t sc = scooterConnected ? (sessionActive ? C_FG : C_AMBER) : C_RED;
  header("ride", String(st), sc);

  // speed (seven-segment) + scope
  char sp[12];
  snprintf(sp, sizeof(sp), "%.1f", tel.kmh);
  T(4, 18, sp, scooterConnected ? C_FG : C_DIM, 7);
  T(6, 66, "km/h", C_DIM, 2);
  scope(126, 19, 110, 46, "spd");

  // battery
  int b = constrain(tel.batt, 0, 100);
  uint16_t bc = b > 50 ? C_FG : (b > 20 ? C_AMBER : C_RED);
  T(4, 83, "BAT", C_DIM, 2);
  segBar(40, 87, 150, 9, tel.batt >= 0 ? b : 0, bc);
  TR(236, 83, tel.batt >= 0 ? String(b) + "%" : String("--"), bc, 2);

  // scooter range + battery temperature
  char buf[24];
  uint32_t now = millis();
  float estKm, estWk;
  if (bs.rangeFresh(now)) {
    snprintf(buf, sizeof(buf), "rng %.1fkm", bs.rangeKm);
    T(4, 100, buf, bs.rangeKm < 5 ? C_RED : (bs.rangeKm < 10 ? C_AMBER : C_FG), 2);
  } else if (bs.estimate(tel.rideKm, estKm, estWk)) {
    snprintf(buf, sizeof(buf), "rng ~%.1fkm", estKm);
    T(4, 100, buf, C_DIM, 2);
  } else {
    T(4, 100, "rng --", C_DIM, 2);
  }
  if (bs.liveFresh(now)) {
    int t = bs.live.tmax();
    snprintf(buf, sizeof(buf), "bat %dC", t);
    TR(236, 100, buf, tempColor(t), 2);
  } else {
    TR(236, 100, "bat --", C_DIM, 2);
  }

  // footer: ride distance + rec / keys
  cv.drawFastHLine(0, 117, cv.width(), C_FAINT);
  snprintf(buf, sizeof(buf), "ride %.2fkm", tel.rideKm);
  bool noteOn = ctlNote.length() && millis() - ctlNoteAt < 2500;
  if (noteOn) T(4, 118, ctlNote, C_CYAN, 2);  // last lock / light / brake result
  else T(4, 118, buf, C_DIM, 2);
  if (recording) {
    snprintf(buf, sizeof(buf), "%s REC %lu", blink(400) ? "*" : " ", (unsigned long)samples);
    TR(236, 118, buf, C_RED, 2);
  } else {
    TR(236, 122, "L H G V S R I Q", C_DIM, 0);
  }
  // status badges (lock / lights) + last command result
  if (scooterLocked) T(56, 66, "LOCKED", C_RED, 2);
  else {
    if (headOn) T(56, 66, "HEAD", C_AMBER, 2);
    if (tailMode == 2) T(100, 66, "TAIL", C_AMBER, 2);
  }
  drawAlarmBanner();
  cv.pushSprite(0, 0);
}

// ---- HUD-BEGIN ----------------------------------------------------------------------------
// ---------------- HUD styles ----------------
// Four ride HUDs, picked in Settings (or V on the ride screen) and saved. They all use the active
// colour theme, so style x theme gives 4 x 13 looks.
//   terminal : the original phosphor-terminal dashboard
//   cyber    : futuristic segmented gauge with a red-line zone, tech side panel, corner brackets
//   minimal  : one huge number, a hairline battery bar, everything else out of the way
//   elegant  : thin ring gauge, serif type, hairline frame and ornaments
// Set HUD_GFX_FONTS to 0 to fall back to the built-in bitmap fonts instead of the serif ones.
#ifndef HUD_GFX_FONTS
#define HUD_GFX_FONTS 1
#endif
enum { HUD_TERMINAL, HUD_CYBER, HUD_MINIMAL, HUD_ELEGANT, HUD_COUNT };
const char* HUD_NAMES[HUD_COUNT] = {"terminal", "cyber", "minimal", "elegant"};
int hudStyle = HUD_TERMINAL;
constexpr float HUD_MAX_KMH = 30.0f;  // full scale of the gauges

void loadHud() {
  prefs.begin("ui", true);
  hudStyle = constrain((int)prefs.getUChar("hud", HUD_TERMINAL), 0, HUD_COUNT - 1);
  prefs.end();
}
void cycleHud(int dir = 1) {
  hudStyle = (hudStyle + dir + HUD_COUNT) % HUD_COUNT;
  prefs.begin("ui", false);
  prefs.putUChar("hud", hudStyle);
  prefs.end();
  setNote(String("hud: ") + HUD_NAMES[hudStyle]);
}

// Text in whichever font is currently selected. align: 0 left, 1 centre, 2 right. yc = vertical centre.
void TA(int x, int yc, const String& s, uint16_t col, int align = 0) {
  cv.setTextSize(1);
  cv.setTextColor(col);
  int w = cv.textWidth(s);
  int x0 = align == 1 ? x - w / 2 : (align == 2 ? x - w : x);
  cv.setCursor(x0, yc - cv.fontHeight() / 2);
  cv.print(s);
}
void fSerifBig()   { cv.setFont(HUD_GFX_FONTS ? (const lgfx::IFont*)&fonts::FreeSerif24pt7b : (const lgfx::IFont*)&fonts::Font7); }
void fSerifMid()   { cv.setFont(HUD_GFX_FONTS ? (const lgfx::IFont*)&fonts::FreeSerif12pt7b : (const lgfx::IFont*)&fonts::Font4); }
void fSerifText()  { cv.setFont(HUD_GFX_FONTS ? (const lgfx::IFont*)&fonts::FreeSerif9pt7b : (const lgfx::IFont*)&fonts::Font2); }
void fSerifSmall() { cv.setFont(HUD_GFX_FONTS ? (const lgfx::IFont*)&fonts::FreeSerifItalic9pt7b : (const lgfx::IFont*)&fonts::Font2); }

// Filled ring segment. Angles in degrees, 0 = 3 o'clock, increasing clockwise (screen coordinates).
void polar(int cx, int cy, float r, float a, int& x, int& y) {
  float t = a * 0.0174533f;
  x = cx + (int)lroundf(r * cosf(t));
  y = cy + (int)lroundf(r * sinf(t));
}
void arcBand(int cx, int cy, float r0, float r1, float a0, float a1, uint16_t col) {
  if (a1 <= a0) return;
  for (float a = a0; a < a1; a += 4.0f) {
    float b = a + 4.5f;  // slight overlap hides rounding seams
    if (b > a1) b = a1;
    int x0, y0, x1, y1, x2, y2, x3, y3;
    polar(cx, cy, r0, a, x0, y0); polar(cx, cy, r1, a, x1, y1);
    polar(cx, cy, r1, b, x2, y2); polar(cx, cy, r0, b, x3, y3);
    cv.fillTriangle(x0, y0, x1, y1, x2, y2, col);
    cv.fillTriangle(x0, y0, x2, y2, x3, y3, col);
  }
}
void diamond(int x, int y, int r, uint16_t col) {
  cv.fillTriangle(x - r, y, x, y - r, x + r, y, col);
  cv.fillTriangle(x - r, y, x, y + r, x + r, y, col);
}
void bracket(int x, int y, int dx, int dy, int len, uint16_t col) {  // L-shaped corner mark
  cv.drawFastHLine(dx > 0 ? x : x - len + 1, y, len, col);
  cv.drawFastVLine(x, dy > 0 ? y : y - len + 1, len, col);
}

// Everything the HUDs show, gathered once per frame.
struct HudData {
  float kmh;
  bool conn;
  const char* st;
  uint16_t stc;
  int batt;  // 0..100, -1 unknown
  uint16_t bc;
  bool rngOk, rngEst;
  float rngKm;
  uint16_t rngc;
  bool tempOk;
  int tempC;
  uint16_t tempc;
  bool noteOn;
};
HudData hudGather() {
  HudData h;
  uint32_t now = millis();
  h.kmh = tel.kmh;
  h.conn = scooterConnected;
  h.st = scooterConnected ? (sessionActive ? "SECURE" : "LINK") : "NO LINK";
  h.stc = scooterConnected ? (sessionActive ? C_FG : C_AMBER) : C_RED;
  h.batt = tel.batt >= 0 ? constrain(tel.batt, 0, 100) : -1;
  h.bc = h.batt < 0 ? C_DIM : (h.batt > 50 ? C_FG : (h.batt > 20 ? C_AMBER : C_RED));
  float estKm, estWk;
  h.rngOk = h.rngEst = false;
  h.rngKm = 0;
  h.rngc = C_DIM;
  if (bs.rangeFresh(now)) {
    h.rngOk = true;
    h.rngKm = bs.rangeKm;
    h.rngc = bs.rangeKm < 5 ? C_RED : (bs.rangeKm < 10 ? C_AMBER : C_FG);
  } else if (bs.estimate(tel.rideKm, estKm, estWk)) {
    h.rngOk = h.rngEst = true;
    h.rngKm = estKm;
  }
  h.tempOk = bs.liveFresh(now);
  h.tempC = h.tempOk ? bs.live.tmax() : 0;
  h.tempc = h.tempOk ? tempColor(h.tempC) : C_DIM;
  h.noteOn = ctlNote.length() && millis() - ctlNoteAt < 2500;
  return h;
}
String fmtRange(const HudData& h) {
  if (!h.rngOk) return "--";
  char b[16];
  snprintf(b, sizeof(b), "%s%.1f", h.rngEst ? "~" : "", h.rngKm);
  return b;
}
String fmtTrip() {
  char b[16];
  snprintf(b, sizeof(b), "%.2f", tel.rideKm);
  return b;
}
float speedFrac(float kmh) { return constrain(kmh / HUD_MAX_KMH, 0.0f, 1.0f); }

// ---- cyber: segmented gauge + tech panel ----
void tag(int x, int y, int w, const char* t, bool on, uint16_t col) {  // small status tag, dim when off
  if (on) cv.fillRect(x, y, w, 11, col);
  else cv.drawRect(x, y, w, 11, C_FAINT);
  cv.setTextFont(0);
  TA(x + w / 2, y + 6, t, on ? C_BG : C_FAINT, 1);
}
void drawHudCyber() {
  const HudData h = hudGather();
  bg();
  const int cx = 76, cy = 70;
  // gauge: 30 segments over 270 deg, green -> amber -> red zone
  const int n = 30;
  int lit = (int)ceilf(speedFrac(h.kmh) * n);
  for (int i = 0; i < n; i++) {
    float a0 = 135.0f + i * 9.0f;
    float f = (i + 1) / (float)n;
    uint16_t col = f < 0.70f ? C_FG : (f < 0.87f ? C_AMBER : C_RED);
    arcBand(cx, cy, 53, 60, a0, a0 + 7.4f, i < lit ? col : C_FAINT);
  }
  arcBand(cx, cy, 48.5f, 49.5f, 135, 405, C_FAINT);  // inner hairline ring
  for (int k = 0; k <= 6; k++) {                       // ticks every 5 km/h
    int x0, y0, x1, y1;
    float a = 135.0f + 270.0f * k / 6.0f;
    polar(cx, cy, 62, a, x0, y0);
    polar(cx, cy, (k == 0 || k == 6) ? 68 : 66, a, x1, y1);
    cv.drawLine(x0, y0, x1, y1, (k == 0 || k == 6) ? C_DIM : C_FAINT);
  }
  // speed
  int ki = (int)h.kmh;
  cv.setTextFont(7);
  String ks = String(ki);
  int kw = cv.textWidth(ks);
  TA(cx, cy - 6, ks, h.conn ? C_FG : C_DIM, 1);
  cv.setTextFont(2);
  TA(cx + kw / 2 + 2, cy + 12, String(".") + String((int)(h.kmh * 10) % 10), C_DIM, 0);
  TA(cx, cy + 44, "KM/H", C_DIM, 1);

  // side panel
  cv.drawFastVLine(144, 12, 100, C_FAINT);
  cv.fillRect(142, 10, 5, 2, C_DIM);
  cv.fillRect(142, 112, 5, 2, C_DIM);
  cv.setTextFont(2);
  TA(236, 9, h.st, h.stc, 2);
  if (recording) {
    char b[20];
    snprintf(b, sizeof(b), "%s REC %lu", blink(400) ? "*" : " ", (unsigned long)samples);
    TA(4, 9, b, C_RED, 0);
  }
  cv.setTextFont(0);
  TA(150, 22, "BAT", C_DIM, 0);
  cv.setTextFont(4);
  TA(236, 35, h.batt >= 0 ? String(h.batt) + "%" : String("--"), h.bc, 2);
  int litb = h.batt < 0 ? 0 : (h.batt + 9) / 10;
  for (int i = 0; i < 10; i++) cv.fillRect(150 + i * 9, 50, 6, 7, i < litb ? h.bc : C_FAINT);

  const int ry[3] = {67, 83, 99};
  const char* rl[3] = {"RANGE", "TEMP", "TRIP"};
  String rv[3] = {h.rngOk ? fmtRange(h) + "km" : String("--"), h.tempOk ? String(h.tempC) + "C" : String("--"),
                  fmtTrip() + "km"};
  uint16_t rc[3] = {h.rngc, h.tempc, C_FG};
  for (int i = 0; i < 3; i++) {
    cv.setTextFont(0);
    TA(150, ry[i], rl[i], C_DIM, 0);
    cv.setTextFont(2);
    TA(236, ry[i], rv[i], rc[i], 2);
    cv.drawFastHLine(150, ry[i] + 8, 86, C_FAINT);
  }
  tag(150, 108, 26, "HEAD", headOn, C_AMBER);
  tag(180, 108, 26, "TAIL", tailMode == 2, C_AMBER);
  tag(210, 108, 26, "LOCK", scooterLocked, C_RED);

  // bottom line: command result, else key hints
  if (h.noteOn) {
    cv.fillRect(0, 118, 240, 17, C_BG);
    cv.setTextFont(2);
    TA(120, 126, ctlNote, C_CYAN, 1);
  } else {
    cv.setTextFont(0);
    TA(8, 127, "L lock H tail G head V hud S set", C_DIM, 0);
  }
  bracket(0, 0, 1, 1, 10, C_DIM);   bracket(239, 0, -1, 1, 10, C_DIM);
  bracket(0, 134, 1, -1, 10, C_DIM); bracket(239, 134, -1, -1, 10, C_DIM);
  drawAlarmBanner();
  cv.pushSprite(0, 0);
}

// ---- minimal: one number ----
void drawHudMinimal() {
  const HudData h = hudGather();
  cv.fillSprite(C_BG);  // no scanlines, whatever the theme says
  cv.setTextFont(8);
  TA(120, 50, String((int)lroundf(h.kmh)), h.conn ? C_FG : C_DIM, 1);
  cv.setTextFont(2);
  TA(120, 98, "km/h", C_DIM, 1);

  cv.fillCircle(9, 9, 2, h.stc);                                          // link dot
  if (recording && blink(500)) cv.fillCircle(20, 9, 2, C_RED);            // rec dot
  cv.setTextFont(0);
  int xr = 232;  // active flags, right-aligned, only when on
  auto flag = [&](const char* t, uint16_t c) { TA(xr, 9, t, c, 2); xr -= cv.textWidth(t) + 8; };
  if (scooterLocked) flag("LOCK", C_RED);
  if (tailMode == 2) flag("TAIL", C_AMBER);
  if (headOn) flag("HEAD", C_AMBER);

  cv.setTextFont(2);
  if (h.noteOn) {
    TA(120, 114, ctlNote, C_CYAN, 1);
  } else {
    TA(8, 114, h.batt >= 0 ? String(h.batt) + "%" : String("--"), C_DIM, 0);
    TA(120, 114, fmtTrip() + " km", C_DIM, 1);
    TA(232, 114, h.rngOk ? fmtRange(h) + " km" : String("--"), C_DIM, 2);
  }
  cv.fillRect(8, 127, 224, 2, C_FAINT);  // hairline battery bar
  if (h.batt > 0) cv.fillRect(8, 127, 224 * h.batt / 100, 2, h.bc);
  drawAlarmBanner();
  cv.pushSprite(0, 0);
}

// ---- elegant: ring gauge, serif type ----
void drawHudElegant() {
  const HudData h = hudGather();
  cv.fillSprite(C_BG);
  cv.drawRoundRect(2, 2, 236, 131, 10, C_DIM);   // double hairline frame
  cv.drawRoundRect(5, 5, 230, 125, 8, C_FAINT);

  const int cx = 58, cy = 66;
  const float a1 = 135.0f + 270.0f * speedFrac(h.kmh);
  arcBand(cx, cy, 43, 44.5f, 135, 405, C_FAINT);  // track
  for (int k = 0; k <= 6; k++) {                  // dots every 5 km/h
    int x, y;
    polar(cx, cy, 50, 135.0f + 270.0f * k / 6.0f, x, y);
    cv.fillCircle(x, y, (k == 0 || k == 6) ? 2 : 1, C_DIM);
  }
  if (h.kmh > 0.2f) {
    arcBand(cx, cy, 42, 45.5f, 135, a1, C_FG);
    int x, y;
    polar(cx, cy, 43.75f, a1, x, y);
    cv.fillCircle(x, y, 4, C_FG);
    cv.fillCircle(x, y, 2, C_BG);
  }
  fSerifBig();
  TA(cx, cy - 6, String((int)h.kmh), h.conn ? C_FG : C_DIM, 1);
  fSerifSmall();
  TA(cx, cy + 24, "km/h", C_DIM, 1);

  // ornamented divider
  const int dx = 114, rx0 = 124, rx1 = 230;
  cv.drawFastVLine(dx, 14, 46, C_FAINT);
  cv.drawFastVLine(dx, 74, 46, C_FAINT);
  diamond(dx, 67, 4, C_FG);

  // readouts: battery with a hairline meter, then range / temp / trip
  fSerifSmall();
  TA(rx0, 20, "Battery", C_DIM, 0);
  fSerifText();
  TA(rx1, 20, h.batt >= 0 ? String(h.batt) + "%" : String("--"), h.bc, 2);
  cv.fillRoundRect(rx0, 33, rx1 - rx0, 3, 1, C_FAINT);
  if (h.batt > 0) cv.fillRoundRect(rx0, 33, max(3, (rx1 - rx0) * h.batt / 100), 3, 1, h.bc);

  const int ry[3] = {55, 77, 99};
  const char* rl[3] = {"Range", "Temp", "Trip"};
  String rv[3] = {h.rngOk ? fmtRange(h) + "km" : String("--"), h.tempOk ? String(h.tempC) + "C" : String("--"),
                  fmtTrip() + "km"};
  uint16_t rc[3] = {h.rngc, h.tempc, C_FG};
  for (int i = 0; i < 3; i++) {
    cv.drawFastHLine(rx0, ry[i] - 11, rx1 - rx0, C_FAINT);
    fSerifSmall();
    TA(rx0, ry[i], rl[i], C_DIM, 0);
    fSerifText();
    TA(rx1, ry[i], rv[i], rc[i], 2);
  }

  // bottom: link state (left), active flags (right), command result replaces both for a moment
  fSerifSmall();
  if (recording && blink(500)) TA(14, 14, "rec", C_RED, 0);
  if (h.noteOn) {
    cv.fillRect(10, 110, 220, 16, C_BG);
    TA(120, 118, ctlNote, C_CYAN, 1);
  } else {
    String st = h.st;
    st.toLowerCase();
    TA(cx, 118, st, h.stc, 1);
    String f;
    if (headOn) f += "head";
    if (tailMode == 2) f += String(f.length() ? ", " : "") + "tail";
    if (scooterLocked) f = "locked";
    if (f.length()) TA(226, 118, f, scooterLocked ? C_RED : C_AMBER, 2);
  }
  drawAlarmBanner();
  cv.pushSprite(0, 0);
}

void drawRide() {
  switch (hudStyle) {
    case HUD_CYBER:   drawHudCyber(); break;
    case HUD_MINIMAL: drawHudMinimal(); break;
    case HUD_ELEGANT: drawHudElegant(); break;
    default:          drawRideTerminal(); break;
  }
}
// ---- HUD-END ------------------------------------------------------------------------------

// ---- STATS-BEGIN --------------------------------------------------------------------------
// ---------------- Meters page (key 2) ----------------
// Big, glanceable page: g-force gauge, IMU tilt gauge, live speed and live battery current.
//   2 = open / close   Z = zero the tilt (and clear the g peak)   X = tilt axis   C = flip tilt sign
//   ESC / Q / 1 = back to the ride HUD. Follows the colour theme (T) like every other screen.
// Battery current comes from the BMS (the scooter does not report phase/motor current): + = drawing,
// - = regen/charging. While this page is open the poll loop alternates motor info and BMS live data.
bool statPage = false;
constexpr float STAT_G_SPAN   = 0.5f;    // g-gauge spans 1.0 g +/- this (full deflection)
constexpr float STAT_TILT_MAX = 30.0f;   // tilt gauge spans +/- this many degrees
constexpr float STAT_AMP_MIN  = -10.0f;  // current bar: regen end
constexpr float STAT_AMP_MAX  = 30.0f;   // current bar: full throttle end
float gSm = 1.0f, gPeakDev = 0;          // smoothed |accel| in g, largest deviation from 1 g since last clear
float tAx = 0, tAy = 0, tAz = 1;         // smoothed accelerometer vector used for tilt
int tiltAxis = 0;                        // rotation axis: 0 = X, 1 = Y, 2 = Z (device axes)
int tiltInv = 0;                         // 1 = flip sign
float tiltZero = 0;                      // raw angle (deg) that counts as level

void loadStats() {
  prefs.begin("ui", true);
  tiltAxis = constrain((int)prefs.getUChar("tAx", 0), 0, 2);
  tiltInv = prefs.getUChar("tInv", 0) ? 1 : 0;
  tiltZero = prefs.getFloat("tZero", 0);
  prefs.end();
}
void saveStats() {
  prefs.begin("ui", false);
  prefs.putUChar("tAx", tiltAxis);
  prefs.putUChar("tInv", tiltInv);
  prefs.putFloat("tZero", tiltZero);
  prefs.end();
}

// Called from imuTick() at ~50 Hz with the raw accelerometer reading (g) and its magnitude.
void statImuUpdate(float ax, float ay, float az, float g) {
  gSm += 0.3f * (g - gSm);
  float dev = gSm - 1.0f;
  if (fabsf(dev) > fabsf(gPeakDev)) gPeakDev = dev;
  tAx += 0.06f * (ax - tAx);  // ~0.3 s smoothing: rides out bumps without lagging the lean
  tAy += 0.06f * (ay - tAy);
  tAz += 0.06f * (az - tAz);
}
float tiltRawDeg() {
  float a;
  switch (tiltAxis) {
    case 0:  a = atan2f(tAy, tAz); break;
    case 1:  a = atan2f(tAx, tAz); break;
    default: a = atan2f(tAx, tAy); break;
  }
  return a * 57.29578f;
}
float tiltDeg() {
  float d = tiltRawDeg() - tiltZero;
  while (d > 180.0f) d -= 360.0f;
  while (d < -180.0f) d += 360.0f;
  return tiltInv ? -d : d;
}
void statZero()  { tiltZero = tiltRawDeg(); gPeakDev = 0; saveStats(); setNote("tilt zeroed"); }
void statAxis()  { tiltAxis = (tiltAxis + 1) % 3; saveStats(); setNote(String("tilt axis ") + "XYZ"[tiltAxis]); }
void statFlip()  { tiltInv ^= 1; saveStats(); setNote(tiltInv ? "tilt sign: -" : "tilt sign: +"); }

// Centre-zero half-ring gauge. f = -1..+1 (0 = top centre). Fills from the centre towards the value.
void statGauge(int cx, int cy, float f, uint16_t col, float pk, bool showPk) {
  const float r0 = 40, r1 = 48;
  f = constrain(f, -1.0f, 1.0f);
  arcBand(cx, cy, r0, r1, 180, 360, C_FAINT);                       // track
  float a = 270.0f + 90.0f * f;
  if (f > 0.01f) arcBand(cx, cy, r0, r1, 270, a, col);
  else if (f < -0.01f) arcBand(cx, cy, r0, r1, a, 270, col);
  for (int k = 0; k <= 4; k++) {                                    // ticks: ends, quarters, centre
    int x0, y0, x1, y1;
    float ta = 180.0f + 45.0f * k;
    polar(cx, cy, r1 + 1, ta, x0, y0);
    polar(cx, cy, k == 2 ? r1 + 6 : r1 + 4, ta, x1, y1);
    cv.drawLine(x0, y0, x1, y1, k == 2 ? C_FG : C_DIM);
  }
  if (showPk) {                                                      // peak marker
    int x0, y0, x1, y1;
    float pa = 270.0f + 90.0f * constrain(pk, -1.0f, 1.0f);
    polar(cx, cy, r0 - 5, pa, x0, y0);
    polar(cx, cy, r0 - 1, pa, x1, y1);
    cv.drawLine(x0, y0, x1, y1, C_AMBER);
  }
  int kx, ky;                                                        // knob at the current value
  polar(cx, cy, (r0 + r1) / 2, a, kx, ky);
  cv.fillCircle(kx, ky, 6, col);
  cv.fillCircle(kx, ky, 2, C_BG);
}

void drawStats() {
  const uint32_t now = millis();
  bg();
  const char* st = scooterConnected ? (sessionActive ? "SECURE" : "LINK") : "NO LINK";
  uint16_t sc = scooterConnected ? (sessionActive ? C_FG : C_AMBER) : C_RED;
  header("meters", String(st), sc);
  if (recording && blink(400)) T(112, 1, "REC", C_RED, 2);

  const int cy = 72, cxL = 60, cxR = 180;
  char b[24];

  // ---- g-force ----
  float dev = gSm - 1.0f;
  float adev = fabsf(dev);
  uint16_t gc = adev < 0.25f ? C_FG : (adev < 0.5f ? C_AMBER : C_RED);
  statGauge(cxL, cy, dev / STAT_G_SPAN, gc, gPeakDev / STAT_G_SPAN, fabsf(gPeakDev) > 0.03f);
  snprintf(b, sizeof(b), "%.2f", gSm);
  cv.setTextFont(4);
  TA(cxL, 59, b, gc, 1);

  // ---- tilt ----
  float tilt = tiltDeg();
  if (fabsf(tilt) < 0.05f) tilt = 0;
  float at = fabsf(tilt);
  uint16_t tc = at < 10.0f ? C_FG : (at < 20.0f ? C_AMBER : C_RED);
  statGauge(cxR, cy, tilt / STAT_TILT_MAX, tc, 0, false);
  snprintf(b, sizeof(b), "%.1f", tilt);
  cv.setTextFont(4);
  TA(cxR, 59, b, tc, 1);

  // label row (a command result like "tilt zeroed" replaces it for a moment)
  cv.setTextFont(2);
  if (ctlNote.length() && now - ctlNoteAt < 2500) {
    TA(120, 84, ctlNote, C_CYAN, 1);
  } else {
    TA(cxL, 84, "G-FORCE (g)", C_DIM, 1);
    snprintf(b, sizeof(b), "TILT %c%c (deg)", "XYZ"[tiltAxis], tiltInv ? '-' : '+');
    TA(cxR, 84, b, C_DIM, 1);
  }
  cv.drawFastVLine(120, 22, 62, C_FAINT);
  cv.drawFastHLine(0, 95, cv.width(), C_FAINT);
  cv.drawFastVLine(120, 96, 38, C_FAINT);

  // ---- speed ----
  const int vy = 99;
  snprintf(b, sizeof(b), "%.1f", tel.kmh);
  uint16_t spc = scooterConnected ? C_FG : C_DIM;
  cv.setTextFont(4);
  cv.setTextSize(1);
  int w = cv.textWidth(b);
  T(4, vy, b, spc, 4);
  T(4 + w + 4, vy + 10, "km/h", C_DIM, 2);
  cv.fillRect(4, 128, 112, 5, C_FAINT);
  cv.fillRect(4, 128, (int)(112 * speedFrac(tel.kmh)), 5, spc);

  // ---- battery current ----
  const bool ok = bs.liveFresh(now, 2500);
  const float amps = ok ? bs.live.amps : 0;
  uint16_t ac = !ok ? C_DIM : (amps < -0.3f ? C_CYAN : (amps < 15.0f ? C_FG : (amps < 25.0f ? C_AMBER : C_RED)));
  if (ok) snprintf(b, sizeof(b), "%.1f", amps); else snprintf(b, sizeof(b), "--");
  cv.setTextFont(4);
  cv.setTextSize(1);
  w = cv.textWidth(b);
  T(126, vy, b, ac, 4);
  T(126 + w + 4, vy + 10, "A", C_DIM, 2);
  const int bx = 126, bw = 110;
  const int zx = bx + (int)(bw * (-STAT_AMP_MIN) / (STAT_AMP_MAX - STAT_AMP_MIN));
  cv.fillRect(bx, 128, bw, 5, C_FAINT);
  if (ok) {
    int vx = bx + (int)(bw * (constrain(amps, STAT_AMP_MIN, STAT_AMP_MAX) - STAT_AMP_MIN) / (STAT_AMP_MAX - STAT_AMP_MIN));
    if (vx >= zx) cv.fillRect(zx, 128, vx - zx + 1, 5, ac);
    else cv.fillRect(vx, 128, zx - vx, 5, ac);
  }
  cv.drawFastVLine(zx, 126, 9, C_DIM);  // zero marker

  drawAlarmBanner();
  cv.pushSprite(0, 0);
}
// ---- STATS-END ----------------------------------------------------------------------------

// Settings: a selectable list. ; / . move the highlight, , and / change the value, ENT toggles.
enum { SR_LOCK, SR_TAIL, SR_HEAD, SR_BRAKE, SR_ALARM, SR_HUD, SR_THEME, SR_BEEP, SR_COUNT };
constexpr int SET_ROWS = 6;  // rows visible at once; the list scrolls
int setSel = 0;

void settingsAct(int row, int dir) {  // dir: +1 next / toggle, -1 previous
  switch (row) {
    case SR_LOCK:  setLock(!scooterLocked); break;
    case SR_TAIL:  setTail(tailMode + dir); break;
    case SR_HEAD:  setHead(!headOn); break;
    case SR_BRAKE: setBrake(brakeLevel + dir); break;
    case SR_ALARM: cycleAlarm(dir); break;
    case SR_HUD:   cycleHud(dir); break;
    case SR_THEME: cycleTheme(dir); break;
    case SR_BEEP:  M5Cardputer.Speaker.tone(3200, 400); break;
  }
}

void drawSettings() {
  bg();
  header("settings", scooterConnected ? (sessionActive ? "SECURE" : "LINK") : "NO LINK",
         scooterConnected ? C_FG : C_RED);
  static const char* labels[SR_COUNT] = {"[L] motor lock", "[H] tail light", "[G] headlight", "    motor brake",
                                         "[A] alarm", "[V] hud style", "[T] theme", "[B] beep test"};
  int top = constrain(setSel - 2, 0, SR_COUNT - SET_ROWS);  // scroll window follows the selection
  for (int i = top; i < top + SET_ROWS; i++) {
    int y = 20 + (i - top) * 17;
    bool on = i == setSel;
    if (on) cv.fillRect(0, y - 1, 237, 17, C_FG);
    uint16_t lc = on ? C_BG : C_FG;
    String val;
    uint16_t vc = C_DIM;
    bool adj = true;  // shows < > arrows
    switch (i) {
      case SR_LOCK:  val = scooterLocked ? "LOCKED" : "off"; vc = scooterLocked ? C_RED : C_DIM; adj = false; break;
      case SR_TAIL:  val = TAIL_NAMES[tailMode]; vc = tailMode == 2 ? C_AMBER : C_DIM; break;
      case SR_HEAD:
        val = HEAD_REG == 0 ? "not set" : (headOn ? "ON" : "off");
        vc = headOn ? C_AMBER : C_DIM;
        adj = false;
        break;
      case SR_BRAKE: val = BRAKE_NAMES[brakeLevel]; vc = C_CYAN; break;
      case SR_ALARM: val = ALARM_NAMES[alarmMode]; vc = alarmMode ? C_CYAN : C_DIM; break;
      case SR_HUD:   val = HUD_NAMES[hudStyle]; vc = C_CYAN; break;
      case SR_THEME: val = THEMES[themeIdx].name; vc = C_CYAN; break;
      case SR_BEEP:  val = "play"; adj = false; break;
    }
    if (on) vc = C_BG;  // readable on the highlight bar
    if (on && adj) val = "< " + val + " >";
    T(4, y, labels[i], lc, 2);
    TR(234, y, val, vc, 2);
  }
  // scrollbar
  cv.fillRect(238, 20, 2, SET_ROWS * 17, C_FAINT);
  cv.fillRect(238, 20 + top * SET_ROWS * 17 / SR_COUNT, 2, SET_ROWS * SET_ROWS * 17 / SR_COUNT, C_FG);
  drawAlarmBanner();
  if (ctlNote.length() && millis() - ctlNoteAt < 3000) {
    cv.drawFastHLine(0, 124, cv.width(), C_FAINT);
    T(4, 126, "> " + ctlNote, C_AMBER, 0);
  } else {
    footer(";/. select  ,// change  ENT toggle  ESC back");
  }
  cv.pushSprite(0, 0);
}

// ---------------- Battery info pages ----------------
int infoY = 21;
void infoRow(const char* k, const String& v, uint16_t col = C_FG) {
  T(6, infoY, k, C_DIM, 2);
  T(70, infoY, v, col, 2);
  infoY += 17;
}

// page 1 = live, 2 = cells, 3 = pack (identity/health), 4 = this ride
void drawBattInfo(int page) {
  bg();
  uint32_t now = millis();
  bool fresh = bs.liveFresh(now);
  const bat::Live& L = bs.live;
  static const char* titles[] = {"", "battery :: live", "battery :: cells", "battery :: pack", "battery :: ride"};

  String st;
  uint16_t sc;
  if (!scooterConnected) { st = "NO LINK"; sc = C_RED; }
  else if (!fresh) { st = "no data"; sc = C_AMBER; }
  else if (L.charging()) { st = "CHG"; sc = C_CYAN; }
  else if (L.amps > 0.05f) { st = "DIS"; sc = C_FG; }
  else if (L.amps < -0.05f) { st = "REGEN"; sc = C_CYAN; }
  else { st = "IDLE"; sc = C_DIM; }
  header(titles[page], st, sc);
  infoY = 21;
  auto col = [&](uint16_t c) { return fresh ? c : (uint16_t)C_DIM; };
  char b[48];

  if (page == 1) {
    if (!L.ok) {
      infoRow("status", scooterConnected ? "waiting for BMS..." : "not connected", C_AMBER);
      snprintf(b, sizeof(b), "motor %lu  bms %lu", (unsigned long)rxMotorN, (unsigned long)rxBmsN);
      infoRow("replies", b, C_DIM);
      snprintf(b, sizeof(b), "%lu rejected", (unsigned long)rxBmsBad);
      infoRow("bad", b, rxBmsBad ? C_AMBER : C_DIM);
    } else {
      snprintf(b, sizeof(b), "%u%%  %umAh", (unsigned)L.pct, (unsigned)L.capMah);
      infoRow("charge", b, col(L.pct > 50 ? C_FG : (L.pct > 20 ? C_AMBER : C_RED)));
      if (bs.cells.ok) snprintf(b, sizeof(b), "%.2fV  %.2fV/cell", L.volts, bs.perCellV());
      else snprintf(b, sizeof(b), "%.2fV", L.volts);
      infoRow("volts", b, col(C_FG));
      snprintf(b, sizeof(b), "%+.2fA  %.0fW", L.amps, bs.watts());
      infoRow("current", b, col(L.amps < -0.05f ? C_CYAN : C_FG));
      snprintf(b, sizeof(b), "%d/%dC", L.t1, L.t2);
      if (bs.escTemp > -100) {
        char e[20];
        snprintf(e, sizeof(e), "  esc %.0fC", bs.escTemp);
        strncat(b, e, sizeof(b) - strlen(b) - 1);
      }
      infoRow("temp", b, col(tempColor(L.tmax())));
      float km, wk;
      bool eok = bs.estimate(tel.rideKm, km, wk);
      if (bs.rangeFresh(now)) snprintf(b, sizeof(b), "%.1fkm", bs.rangeKm);
      else snprintf(b, sizeof(b), "--");
      if (eok) {
        char e[24];
        snprintf(e, sizeof(e), "  est %.1fkm", km);
        strncat(b, e, sizeof(b) - strlen(b) - 1);
      }
      infoRow("range", b, C_FG);
      if (eok) snprintf(b, sizeof(b), "%.1fWh/km  %dmAh", wk, bs.usedMah());
      else if (bs.haveBase) snprintf(b, sizeof(b), "%dmAh (est needs 0.4km)", bs.usedMah());
      else snprintf(b, sizeof(b), "--");
      infoRow("use", b, eok ? C_FG : C_DIM);
    }
  } else if (page == 2) {
    const bat::Cells& C = bs.cells;
    bool cf = scooterConnected && now - bs.cellsMs < 15000;
    if (!C.ok) {
      infoRow("cells", scooterConnected ? "waiting for BMS..." : "not connected", C_AMBER);
    } else {
      int n = C.n, rows = (n + 1) / 2;
      bool big = rows > 5;
      int pitch = big ? 11 : 17, font = big ? 0 : 2;
      for (int i = 0; i < n; i++) {
        int x = 6 + (i / rows) * 120, y = 21 + (i % rows) * pitch;
        uint16_t cc = i == C.minIdx ? C_CYAN : (i == C.maxIdx ? C_AMBER : C_FG);
        bool bal = (L.balance >> i) & 1;
        snprintf(b, sizeof(b), "%2d %.3fV%s", i + 1, C.mv[i] / 1000.0f, bal ? "*" : "");
        T(x, y, b, cf ? cc : C_DIM, font);
      }
      snprintf(b, sizeof(b), "d%dmV  lo %.3f  hi %.3f", C.deltaMv(), C.minMv / 1000.0f, C.maxMv / 1000.0f);
      T(6, 107, b, C_DIM, 2);
    }
  } else if (page == 3) {
    const bat::Info& I = bs.info;
    if (!I.ok) {
      infoRow("pack", scooterConnected ? "reading BMS info..." : "not connected", C_AMBER);
    } else {
      infoRow("serial", I.serial[0] ? I.serial : "--");
      char v[8];
      bat::versionStr(I.version, v, sizeof(v));
      if (bs.date.ok && bs.date.raw) snprintf(b, sizeof(b), "fw %s  %04d-%02d-%02d", v, bs.date.year(), bs.date.month(), bs.date.day());
      else snprintf(b, sizeof(b), "fw %s", v);
      infoRow("bms", b);
      snprintf(b, sizeof(b), "%u / %u mAh", (unsigned)I.realMah, (unsigned)I.designMah);
      infoRow("capacity", b);
      int wear = 0;
      bool hw = bs.wearPct(wear);
      if (hw && L.ok) snprintf(b, sizeof(b), "bms %u%%  wear %d%%", (unsigned)L.health, wear);
      else if (hw) snprintf(b, sizeof(b), "wear %d%%", wear);
      else snprintf(b, sizeof(b), "--");
      infoRow("health", b, hw && wear > 40 ? C_RED : (hw && wear > 20 ? C_AMBER : C_FG));
      snprintf(b, sizeof(b), "%u cycles  %u chg", (unsigned)I.cycles, (unsigned)I.charges);
      infoRow("cycles", b);
      snprintf(b, sizeof(b), "max %.1fV %.0fA/%.0fA", I.maxV / 100.0f, I.maxDis / 100.0f, I.maxChg / 100.0f);
      infoRow("limits", b, C_DIM);
    }
  } else {
    if (!L.ok) {
      infoRow("status", scooterConnected ? "waiting for BMS..." : "not connected", C_AMBER);
    } else {
      String fl;
      if (L.status & bat::ST_CHARGING) fl += "CHG ";
      if (L.status & bat::ST_OVERVOLT) fl += "OVERV ";
      if (L.status & bat::ST_OVERHEAT) fl += "HOT ";
      if (bs.date.ok && bs.date.anyError()) {
        fl += "E:";
        for (int i = 0; i < 6; i++) { snprintf(b, sizeof(b), "%02X", bs.date.err[i]); fl += b; }
      }
      bool bad = (L.status & (bat::ST_OVERVOLT | bat::ST_OVERHEAT)) || (bs.date.ok && bs.date.anyError());
      snprintf(b, sizeof(b), "0x%04X %s", (unsigned)L.status, fl.length() ? fl.c_str() : "ok");
      infoRow("status", b, bad ? C_RED : col(C_FG));
      snprintf(b, sizeof(b), "%.1fA  %.0fW", bs.peakAmps, bs.peakWatts);
      infoRow("peak", b);
      snprintf(b, sizeof(b), "now %dC  max %dC", L.tmax(), bs.maxTemp);
      infoRow("temp", b, tempColor(bs.maxTemp));
      if (bs.minCellMv) snprintf(b, sizeof(b), "min %.2fV  cell %.3fV", bs.minVolts, bs.minCellMv / 1000.0f);
      else snprintf(b, sizeof(b), "min %.2fV", bs.minVolts);
      infoRow("volts", b);
      snprintf(b, sizeof(b), "out %.*fWh  regen %.1fWh", bs.whOut < 100 ? 1 : 0, bs.whOut, bs.whRegen);
      infoRow("energy", b);
      if (tel.totalKm >= 0) snprintf(b, sizeof(b), "ride %.2fkm  odo %.0fkm", tel.rideKm, tel.totalKm);
      else snprintf(b, sizeof(b), "ride %.2fkm  odo --", tel.rideKm);
      infoRow("trip", b);
    }
  }

  snprintf(b, sizeof(b), "[I]next [,]prev %s [Q]back  p%d/%d", recording ? "[R]stop" : "[R]ec", page, INFO_PAGES);
  footer(b);
  cv.pushSprite(0, 0);
}

void drawExport(bool wifi) {
  bg();
  header(wifi ? "export :: wifi" : "export :: ble", fsName, C_DIM);
  int y = 24;
  auto row = [&](const char* k, const String& v) {
    T(6, y, String("> ") + k, C_DIM, 2);
    T(62, y, v, C_FG, 2);
    y += 18;
  };
  if (wifi) {
    row("ssid", AP_SSID);
    row("pass", AP_PASS);
    row("url", "http://" + WiFi.softAPIP().toString());
    T(6, y + 4, "open the url, tap a ride to download", C_DIM, 0);
  } else {
    row("adv", APP_NAME);
    row("cmd", "LIST | GET <file>");
    row("write", "...0002");
    row("notify", "...0003  (ends #EOF)");
  }
  T(6, 108, String("clients: ") + (wifi ? String(WiFi.softAPgetStationNum()) : String(expServer ? expServer->getConnectedCount() : 0)), C_DIM, 2);
  footer("[Q] back");
  cv.pushSprite(0, 0);
}

// ---------------- Ride loop pieces ----------------
void imuTick() {
  if (millis() - lastImu < 20) return;  // ~50 Hz
  lastImu = millis();
  if (!M5.Imu.update()) return;
  auto d = M5.Imu.getImuData();
  lastAccG = sqrtf(d.accel.x * d.accel.x + d.accel.y * d.accel.y + d.accel.z * d.accel.z);
  shakeEma = 0.9f * shakeEma + 0.1f * fabsf(lastAccG - prevG);  // jitter, used by the lock alarm
  prevG = lastAccG;
  statImuUpdate(d.accel.x, d.accel.y, d.accel.z, lastAccG);
  if (!recording) return;
  logFile.printf("%lu,%.4f,%.4f,%.4f,%.2f,%.2f,%.2f,%.2f,%d", (unsigned long)millis(),
                 d.accel.x, d.accel.y, d.accel.z, d.gyro.x, d.gyro.y, d.gyro.z, tel.kmh, tel.batt);
  if (bs.liveFresh(millis())) logFile.printf(",%.2f,%.2f,%d,%d\n", bs.live.volts, bs.live.amps, bs.live.t1, bs.live.t2);
  else logFile.print(",,,,\n");
  samples++;
  if (millis() - lastFlush > 1000) { logFile.flush(); lastFlush = millis(); }
}

// Poll schedule (every 150 ms): motor info most of the time, BMS live data every 8th tick,
// and one "slow" read per 8 ticks cycling through cells / scooter range / pack info / date.
void pollTick_() {
  if (!scooterConnected || millis() - lastPoll < (statPage ? 120u : 150u)) return;
  lastPoll = millis();
  static uint8_t seq = 0, slow = 0;
  seq++;
  if (statPage) {  // meters page: alternate BMS live data (amps) and motor info (speed), skip the slow reads
    if (seq & 1) sendRead(bat::ADDR_BMS_TX, bat::REG_LIVE, bat::LEN_LIVE);
    else sendMotorInfoReq();
    return;
  }
  uint8_t slot = seq & 7;
  if (slot == 1) { sendRead(bat::ADDR_BMS_TX, bat::REG_LIVE, bat::LEN_LIVE); return; }
  if (slot == 3) {
    for (int tries = 0; tries < 4; tries++) {
      uint8_t k = (slow++) & 3;
      if (k == 0) { sendRead(bat::ADDR_BMS_TX, bat::REG_CELLS, bat::LEN_CELLS); return; }
      if (k == 1) { sendRead(bat::ADDR_ESC_TX, bat::REG_ESC_RANGE, bat::LEN_ESC_RANGE); return; }
      if (k == 2 && !bs.info.ok) { sendRead(bat::ADDR_BMS_TX, bat::REG_INFO, bat::LEN_INFO); return; }
      if (k == 3 && !bs.date.ok) { sendRead(bat::ADDR_BMS_TX, bat::REG_DATE, bat::LEN_DATE); return; }
    }
    return;
  }
  sendMotorInfoReq();
}

void goHome() {
  infoPage = 0;
  statPage = false;
  if (state == ST_RIDE) {
    stopRecording();
    if (client && scooterConnected) client->disconnect();
  } else if (state == ST_EXPORT_WIFI) stopWifiExport();
  else if (state == ST_EXPORT_BLE) stopBleExport();
  state = ST_HOME;
  drawHome();
}

// ---------------- Arduino ----------------
// ---- HUD-SPLASH-BEGIN ----
// Startup splash: logo on black, fades in, holds, fades out. Any key skips it.
void showSplash() {
  static uint16_t buf[LOGO_W * LOGO_H];
  const int x = (cv.width() - LOGO_W) / 2, y = (cv.height() - LOGO_H) / 2;
  auto frame = [&](int k, int n) {  // k/n brightness
    for (int i = 0; i < LOGO_W * LOGO_H; i++) {
      uint16_t c = LOGO_565[i];
      uint32_t r = ((c >> 11) & 31) * k / n, g = ((c >> 5) & 63) * k / n, b = (c & 31) * k / n;
      buf[i] = (r << 11) | (g << 5) | b;
    }
    cv.fillSprite(0x0000);
    cv.pushImage(x, y, LOGO_W, LOGO_H, (const lgfx::rgb565_t*)buf);
    cv.pushSprite(0, 0);
  };
  auto wait = [&](uint32_t ms) {  // returns true if a key was pressed
    uint32_t t0 = millis();
    while (millis() - t0 < ms) {
      M5Cardputer.update();
      if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) return true;
      delay(10);
    }
    return false;
  };
  for (int k = 1; k <= 10; k++) { frame(k, 10); delay(40); }
  bool skip = wait(1500);
  if (!skip) for (int k = 9; k >= 0; k--) { frame(k, 10); delay(30); }
  cv.fillSprite(0x0000);
  cv.pushSprite(0, 0);
}
// ---- HUD-SPLASH-END ----

void setup() {
  auto cfg = M5.config();
  Serial.begin(115200);
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Display.setRotation(1);
  cv.createSprite(M5Cardputer.Display.width(), M5Cardputer.Display.height());
  loadTheme();
  loadHud();
  loadStats();
  loadScooterSettings();
  showSplash();
  M5Cardputer.Speaker.setVolume(220);

  authQ = xQueueCreate(16, sizeof(Notif));
  frameQ = xQueueCreate(8, sizeof(Notif));
  bool storOk = initStorage();
  NimBLEDevice::init(APP_NAME);
  NimBLEDevice::setCustomGapHandler(gapTap);
  {  // fake-but-honest boot log
    String lines[5] = {String("[ OK ] ") + APP_NAME + " v2.0",
                       String(storOk ? "[ OK ] storage :: " : "[FAIL] storage :: ") + fsName,
                       "[ OK ] ble stack",
                       String(M5.Imu.isEnabled() ? "[ OK ] imu :: online" : "[FAIL] imu :: not found"),
                       "[ OK ] ready"};
    for (int n = 1; n <= 5; n++) {
      bg();
      for (int i = 0; i < n; i++) {
        bool bad = lines[i].startsWith("[FAIL]");
        T(4, 6 + i * 20, lines[i], bad ? C_RED : C_FG, 2);
      }
      cv.pushSprite(0, 0);
      delay(180);
    }
    delay(250);
  }
  NimBLEDevice::setSecurityAuth(BLE_BONDING, BLE_BONDING, BLE_BONDING);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_KEYBOARD_DISPLAY);
  drawHome();
}

uint32_t lastDraw = 0;

void loop() {
  char k = getKey();

  switch (state) {
    case ST_HOME:
      { static uint32_t lh = 0; if (millis() - lh > 250) { lh = millis(); drawHome(); } }
      if (k == 's') { showAll = false; scanScooters(); state = ST_SCAN; drawScan(); }
      else if (k == 't') { cycleTheme(); drawHome(); }
      else if (k == 'w' && fsys) { startWifiExport(); state = ST_EXPORT_WIFI; drawExport(true); }
      else if (k == 'b' && fsys) { startBleExport(); state = ST_EXPORT_BLE; drawExport(false); }
      break;

    case ST_SCAN:
      if (k == ';' && sel > 0) sel--;
      else if (k == '.' && sel + 1 < (int)devs.size()) sel++;
      else if (k == 'a') { showAll = !showAll; scanScooters(); }
      else if (k == 's') scanScooters();
      else if (k == 'f' && !devs.empty()) { forgetToken(devs[sel].addr); msg("Pairing forgotten", devs[sel].name, YELLOW); delay(1000); }
      else if (k == 'q' || k == KEY_BACK) { goHome(); break; }
      else if (k == '\n' && !devs.empty()) {
        if (connectScooter(devs[sel].addr)) {
          tel = Telemetry();
          bs = bat::State();
          infoPage = 0;
          statPage = false;
          gPeakDev = 0;
          rxMotorN = rxBmsN = rxBmsBad = 0;
          spdCount = 0;
          applySavedScooterSettings();
          state = ST_RIDE;
          break;
        }
      }
      drawScan();
      break;

    case ST_RIDE:
      if (k == '2') {  // meters page: g-force, tilt, speed, amps
        statPage = !statPage;
        infoPage = 0;
        if (statPage) setNote("9 zero  Z zero  X axis  C flip");
      }
      else if (statPage && k == '1') statPage = false;
      else if (statPage && (k == '9' || k == 'z' || k == 'Z')) statZero();
      else if (statPage && k == 'x') statAxis();
      else if (statPage && k == 'c') statFlip();
      else if (k == 'r') { recording ? stopRecording() : startRecording(); }
      else if (k == 't') cycleTheme();
      else if (k == 'l' && !infoPage) setLock(!scooterLocked);
      else if (k == 'h' && !infoPage) setTail(tailMode + 1);
      else if (k == 'g' && !infoPage) setHead(!headOn);
      else if (k == 'v' && !infoPage && !statPage) cycleHud();
      else if (k == 's') { infoPage = 0; statPage = false; setSel = 0; state = ST_SETTINGS; drawSettings(); break; }
      else if (k == 'i') { statPage = false; infoPage = (infoPage + 1) % (INFO_PAGES + 1); }
      else if (k == '/' && infoPage) infoPage = infoPage % INFO_PAGES + 1;
      else if (k == ',' && infoPage) infoPage = infoPage == 1 ? INFO_PAGES : infoPage - 1;
      else if (k == KEY_BACK) { infoPage = 0; statPage = false; }  // ESC: back to the main HUD (never disconnects)
      else if (k == 'q') {
        if (statPage) statPage = false;
        else if (infoPage) infoPage = 0;
        else { goHome(); break; }
      }
      processFrames();
      imuTick();
      pollTick_();
      suppTick();
      alarmTick();
      {
        static uint32_t lastHist = 0;
        if (millis() - lastHist > 250) {
          lastHist = millis();
          if (spdCount == (int)(sizeof(spdHist) / sizeof(spdHist[0]))) {
            memmove(spdHist, spdHist + 1, (spdCount - 1) * sizeof(float));
            spdCount--;
          }
          spdHist[spdCount++] = tel.kmh;
        }
      }
      if (!scooterConnected && haveScooter) {  // auto-reconnect (logs in with the saved token)
        static uint32_t lastTry = 0;
        if (millis() - lastTry > 4000) { lastTry = millis(); connectScooter(scooterAddr); }
      }
      if (millis() - lastDraw > 100) { lastDraw = millis(); if (infoPage) drawBattInfo(infoPage); else if (statPage) drawStats(); else drawRide(); }
      break;

    case ST_SETTINGS:
      if (k == ';') setSel = (setSel + SR_COUNT - 1) % SR_COUNT;
      else if (k == '.') setSel = (setSel + 1) % SR_COUNT;
      else if (k == ',') settingsAct(setSel, -1);
      else if (k == '/' || k == '\n') settingsAct(setSel, +1);
      else if (k == 'l') { setSel = SR_LOCK;  settingsAct(setSel, +1); }
      else if (k == 'h') { setSel = SR_TAIL;  settingsAct(setSel, +1); }
      else if (k == 'g') { setSel = SR_HEAD;  settingsAct(setSel, +1); }
      else if (k == 'a') { setSel = SR_ALARM; settingsAct(setSel, +1); }
      else if (k == 'v') { setSel = SR_HUD;   settingsAct(setSel, +1); }
      else if (k == 't') { setSel = SR_THEME; settingsAct(setSel, +1); }
      else if (k == 'b') { setSel = SR_BEEP;  settingsAct(setSel, +1); }
      else if (k == 'q' || k == KEY_BACK) { state = ST_RIDE; break; }  // back to the main HUD
      // keep telemetry flowing so the link and ride stats stay alive while in settings
      processFrames();
      imuTick();
      pollTick_();
      { static uint32_t ls = 0; if (millis() - ls > 3000) { ls = millis(); askScooterState(0); } }
      suppTick();
      alarmTick();
      if (millis() - lastDraw > 100) { lastDraw = millis(); drawSettings(); }
      break;

    case ST_EXPORT_WIFI:
      web.handleClient();
      { static uint32_t le = 0; if (millis() - le > 1000) { le = millis(); drawExport(true); } }
      if (k == 'q' || k == KEY_BACK) goHome();
      break;

    case ST_EXPORT_BLE:
      pumpBleExport();
      { static uint32_t le = 0; if (millis() - le > 1000) { le = millis(); drawExport(false); } }
      if (k == 'q' || k == KEY_BACK) goHome();
      break;
  }
  delay(1);
}
