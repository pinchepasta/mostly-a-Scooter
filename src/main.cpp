// mostly-a-Scooter  -  M5Stack Cardputer ADV
// Dashboard for Xiaomi M365 / Pro / Pro 2 scooters + IMU ride logger.
// Uses Xiaomi's own registration (power-button confirm) + encrypted login,
// ported from the open-source macbury/m365 reference. Falls back to the
// plain protocol for old firmware that has no FE95 auth service.
//
// Keys:  Home:  S = scan & ride   W = WiFi export   B = BLE export
//        Scan:  ; / . = up/down   Enter = connect   A = show all
//               F = forget saved pairing of selected scooter   Q = back
//        Pair:  Q = cancel
//        Ride:  R = start/stop recording   Q = disconnect & home
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

#define MI_FILL_RANDOM(b, n) esp_fill_random((b), (n))
#include "mi_crypto.h"

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
enum State { ST_HOME, ST_SCAN, ST_RIDE, ST_EXPORT_WIFI, ST_EXPORT_BLE };
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

NimBLEClient* client = nullptr;
NimBLERemoteCharacteristic *rxChar = nullptr, *txChar = nullptr, *upnp = nullptr, *avdtp = nullptr;
volatile bool scooterConnected = false;
volatile bool sessionActive = false;  // encrypted session established
bool cryptoMode = false;
mi::Keychain keys;
NimBLEAddress scooterAddr;
bool haveScooter = false;
bool cancelled = false;

struct Dev { NimBLEAddress addr; String name; int rssi; };
std::vector<Dev> devs;
int sel = 0;
bool showAll = false;

bool recording = false;
File logFile;
String logName;
uint32_t samples = 0, lastFlush = 0, lastImu = 0, lastPoll = 0, lastSpeedT = 0;

WebServer web(80);

// ---------------- Helpers ----------------
char getKey() {
  M5Cardputer.update();
  if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
    auto s = M5Cardputer.Keyboard.keysState();
    if (s.enter) return '\n';
    if (!s.word.empty()) return tolower(s.word.back());
  }
  return 0;
}

void msg(const String& a, const String& b = "", uint16_t col = WHITE) {
  cv.fillSprite(BLACK);
  cv.setTextColor(col);
  cv.setTextSize(2);
  cv.setCursor(4, 30);
  cv.println(a);
  cv.setTextSize(1);
  cv.setCursor(4, 70);
  cv.println(b);
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
  logFile.println("ms,ax_g,ay_g,az_g,gx_dps,gy_dps,gz_dps,kmh,batt_pct");
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
}

void processFrames() {
  Notif m;
  while (xQueueReceive(frameQ, &m, 0) == pdTRUE) {
    if (sessionActive) {
      uint8_t dec[80];
      int n = mi::decrypt_uart(keys.dev, m.d, m.len, dec);
      // dec = [addr, cmd, reg, data..., rand4]
      if (n >= 7 && dec[0] == 0x23 && dec[2] == REG_MOTOR_INFO) onMotorInfo(dec + 3, n - 7);
    } else {
      uint16_t s = 0;
      for (size_t i = 2; i < (size_t)m.len - 2; i++) s += m.d[i];
      s ^= 0xFFFF;
      if (s != (uint16_t)(m.d[m.len - 2] | (m.d[m.len - 1] << 8))) continue;
      if (m.d[3] == 0x23 && m.d[5] == REG_MOTOR_INFO) onMotorInfo(m.d + 6, m.d[2] - 2);
    }
  }
}

void sendMotorInfoReq() {
  if (!scooterConnected || !rxChar) return;
  uint8_t out[48];
  size_t n;
  if (sessionActive) {
    const uint8_t req[5] = {3, 0x20, 0x01, REG_MOTOR_INFO, 0x20};
    n = mi::encrypt_uart(keys.app, req, 5, 0, nullptr, out);
  } else {
    uint8_t f[9] = {0x55, 0xAA, 0x03, 0x20, 0x01, REG_MOTOR_INFO, 0x20, 0, 0};
    uint16_t s = 0;
    for (int i = 2; i < 7; i++) s += f[i];
    s ^= 0xFFFF;
    f[7] = s & 0xFF; f[8] = s >> 8;
    memcpy(out, f, 9);
    n = 9;
  }
  for (size_t o = 0; o < n; o += 20) rxChar->writeValue(out + o, min((size_t)20, n - o), false);
}

// ---------------- Pairing UI ----------------
const char* pairStatus = "";
uint32_t cdStart = 0, cdTotal = 0;  // countdown for long waits

void drawPairPrompt() {
  cv.fillSprite(BLACK);
  cv.setTextColor(YELLOW);
  cv.setTextSize(2);
  cv.setCursor(4, 4);
  cv.println("PAIRING");
  cv.setTextColor(WHITE);
  cv.setTextSize(1);
  cv.setCursor(4, 30);
  cv.println("Press the POWER button on the");
  cv.setCursor(4, 42);
  cv.println("scooter when it asks (beep/blink).");
  cv.setCursor(4, 70);
  cv.setTextColor(CYAN);
  cv.println(pairStatus);
  if (cdTotal) {
    uint32_t el = millis() - cdStart;
    uint32_t left = el >= cdTotal ? 0 : (cdTotal - el) / 1000;
    cv.setTextSize(3);
    cv.setTextColor(YELLOW);
    cv.setCursor(4, 88);
    cv.printf("%2lus", (unsigned long)left);
  }
  cv.setTextSize(1);
  cv.setTextColor(DARKGREY);
  cv.setCursor(150, 122);
  cv.print("Q = cancel");
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
    if (xQueueReceive(authQ, &m, pdMS_TO_TICKS(20)) == pdTRUE && m.src == src) return true;
    if (getKey() == 'q') { cancelled = true; return false; }
    if (!scooterConnected) return false;
    if (cdTotal && millis() - lastDraw > 250) { lastDraw = millis(); drawPairPrompt(); }
  }
  return false;
}

void writeCmd(NimBLERemoteCharacteristic* c, const uint8_t* b, size_t n) { c->writeValue(b, n, false); }

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
  writeCmd(upnp, CMD_GET_INFO, 4);
  if (!readParcel(info, sizeof(info), il)) return cancelled ? REG_FAIL : REG_RETRY;

  writeCmd(upnp, CMD_SET_KEY, 4);
  writeCmd(avdtp, CMD_SEND_DATA, 6);
  if (!waitNotif(m, SRC_AVDTP, 2000)) return cancelled ? REG_FAIL : REG_RETRY;
  if (!is(m, RCV_RDY)) return REG_RETRY;
  writeParcel(avdtp, pub, 64);
  if (!waitNotif(m, SRC_AVDTP, 3000) || !is(m, RCV_OK)) return cancelled ? REG_FAIL : REG_RETRY;

  uint8_t rk[80];
  size_t rkl = 0;
  if (!readParcel(rk, sizeof(rk), rkl) || rkl < 64) return cancelled ? REG_FAIL : REG_RETRY;

  uint8_t did[72];
  size_t dl = 0;
  if (il > 60 || !mi::calc_did(kp, rk, info, il, did, &dl, token)) return REG_FAIL;
  writeCmd(avdtp, CMD_SEND_DID, 6);
  for (;;) {
    if (!waitNotif(m, SRC_AVDTP, 3000)) return cancelled ? REG_FAIL : REG_RETRY;
    if (is(m, RCV_RDY)) writeParcel(avdtp, did, dl);
    else if (is(m, RCV_OK)) break;
    else return REG_RETRY;
  }

  setPairStatus("PRESS POWER BUTTON NOW", 30000);
  writeCmd(upnp, CMD_AUTH, 4);
  if (!waitNotif(m, SRC_UPNP, 30000)) return cancelled ? REG_FAIL : REG_RETRY;
  return is(m, RCV_AUTH_OK) ? REG_OK : REG_RETRY;
}

bool loginTokenRejected = false;

bool doLogin(const uint8_t token[12], mi::Keychain& kc) {
  drainAuth();
  loginTokenRejected = false;
  Notif m;
  uint8_t myr[16];
  MI_FILL_RANDOM(myr, 16);
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
  if (memcmp(ri, expct, 32) != 0) { loginTokenRejected = true; return false; }

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
    cv.fillSprite(BLACK);
    cv.setTextColor(YELLOW);
    cv.setTextSize(1);
    cv.setCursor(4, 10);
    cv.println("Scooter requests PAIRING CODE");
    cv.setTextSize(3);
    cv.setCursor(4, 50);
    cv.print(s + "_");
    cv.setTextSize(1);
    cv.setCursor(4, 115);
    cv.print("digits, DEL = erase, Enter = OK");
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
      if (k == 'q') return false;
      delay(20);
    }
    return false;
  }
} clientCb;

static bool uuidIs16(const NimBLEUUID& u, uint16_t id) {
  std::string s = u.toString();
  for (auto& c : s) c = tolower(c);
  char a[8], b[40];
  snprintf(a, sizeof(a), "0x%04x", id);
  snprintf(b, sizeof(b), "0000%04x-0000-1000-8000-00805f9b34fb", id);
  return s == a || s == b;
}

NimBLERemoteCharacteristic* findChar16(NimBLERemoteService* svc, uint16_t id) {
  for (auto* c : *svc->getCharacteristics(true)) if (uuidIs16(c->getUUID(), id)) return c;
  return nullptr;
}

// Connect GATT, resolve characteristics and subscribe.
bool linkUp(const NimBLEAddress& a) {
  scooterConnected = false;
  sessionActive = false;
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
  if (!client->connect(a)) return false;
  scooterConnected = true;
  if (BLE_BONDING) client->secureConnection();

  NimBLERemoteService* uart = client->getService(NUS_SVC);
  if (!uart) return false;
  rxChar = uart->getCharacteristic(NUS_RX_WRITE);
  txChar = uart->getCharacteristic(NUS_TX_NOTIFY);
  if (!rxChar || !txChar) return false;

  NimBLERemoteService* auth = nullptr;
  for (auto* s : *client->getServices(true)) if (uuidIs16(s->getUUID(), UUID_AUTH_SVC)) { auth = s; break; }
  cryptoMode = auth != nullptr;
  if (auth) {
    upnp = findChar16(auth, UUID_UPNP);
    avdtp = findChar16(auth, UUID_AVDTP);
    if (!upnp || !avdtp) return false;
    if (!upnp->subscribe(true, [](NimBLERemoteCharacteristic*, uint8_t* d, size_t n, bool) { pushQ(authQ, SRC_UPNP, d, n); })) return false;
    if (!avdtp->subscribe(true, [](NimBLERemoteCharacteristic*, uint8_t* d, size_t n, bool) { pushQ(authQ, SRC_AVDTP, d, n); })) return false;
  }
  return txChar->subscribe(true, [](NimBLERemoteCharacteristic*, uint8_t* d, size_t n, bool) { onUart(d, n); });
}

void failMsg(const char* a, const char* b = "") {
  msg(a, b, RED);
  if (client && client->isConnected()) client->disconnect();
  scooterConnected = false;
  sessionActive = false;
  delay(1800);
}

bool connectScooter(const NimBLEAddress& a) {
  cancelled = false;
  cdTotal = 0;
  msg("Connecting...", a.toString().c_str());
  if (!linkUp(a)) { failMsg("Connect failed"); return false; }

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
        delay(1500);
        if (!linkUp(a)) { failMsg("Reconnect failed"); return false; }
      }
      if (!reg) { failMsg("Pairing failed", "Scooter did not confirm"); return false; }
      saveToken(a, token);
      setPairStatus("Paired! Logging in...");
      delay(800);
      if (!linkUp(a)) { failMsg("Reconnect failed"); return false; }
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
    devs.push_back({d.getAddress(), n, d.getRSSI()});
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
  cv.fillSprite(BLACK);
  cv.setTextColor(GREEN);
  cv.setTextSize(2);
  cv.setCursor(4, 4);
  cv.println(APP_NAME);
  cv.setTextColor(WHITE);
  cv.setTextSize(1);
  cv.setCursor(4, 40);
  cv.println("S  scan & ride");
  cv.println("    W  export via WiFi");
  cv.println("    B  export via BLE");
  cv.setCursor(4, 110);
  cv.setTextColor(DARKGREY);
  cv.printf("storage: %s", fsName);
  cv.pushSprite(0, 0);
}

void drawScan() {
  cv.fillSprite(BLACK);
  cv.setTextSize(1);
  cv.setTextColor(CYAN);
  cv.setCursor(2, 2);
  cv.printf("Scooters (%s) ;/. Ent A=all F=forget", showAll ? "all" : "filt");
  for (int i = 0; i < (int)devs.size() && i < 9; i++) {
    cv.setTextColor(i == sel ? YELLOW : WHITE);
    cv.setCursor(2, 18 + i * 12);
    cv.printf("%c %s %d", i == sel ? '>' : ' ', devs[i].name.c_str(), devs[i].rssi);
  }
  if (devs.empty()) {
    cv.setTextColor(RED);
    cv.setCursor(2, 40);
    cv.print("none found - press S to rescan");
  }
  cv.pushSprite(0, 0);
}

void drawRide() {
  cv.fillSprite(BLACK);
  cv.setTextColor(scooterConnected ? WHITE : RED);
  cv.setTextSize(6);
  cv.setCursor(4, 6);
  cv.printf("%4.1f", tel.kmh);
  cv.setTextSize(2);
  cv.setCursor(175, 36);
  cv.print("km/h");

  int b = constrain(tel.batt, 0, 100);
  uint16_t bc = b > 50 ? GREEN : (b > 20 ? YELLOW : RED);
  cv.drawRect(4, 70, 120, 16, WHITE);
  if (tel.batt >= 0) cv.fillRect(5, 71, 118 * b / 100, 14, bc);
  cv.setTextSize(2);
  cv.setTextColor(WHITE);
  cv.setCursor(132, 70);
  if (tel.batt >= 0) cv.printf("%d%%", tel.batt); else cv.print("--");

  cv.setTextSize(1);
  cv.setCursor(4, 94);
  cv.printf("Ride %.2f km", tel.rideKm);
  cv.setCursor(4, 106);
  if (tel.totalKm >= 0) cv.printf("Total %.1f km", tel.totalKm); else cv.print("Total --");

  cv.setCursor(4, 122);
  cv.setTextColor(recording ? RED : DARKGREY);
  cv.printf(recording ? "REC %lu smp" : "R=record  Q=quit", (unsigned long)samples);
  cv.setCursor(150, 122);
  cv.setTextColor(scooterConnected ? GREEN : RED);
  cv.print(scooterConnected ? (sessionActive ? "secure" : "linked") : "no link");
  cv.pushSprite(0, 0);
}

void drawExport(bool wifi) {
  cv.fillSprite(BLACK);
  cv.setTextColor(CYAN);
  cv.setTextSize(2);
  cv.setCursor(4, 4);
  cv.print(wifi ? "WiFi export" : "BLE export");
  cv.setTextSize(1);
  cv.setTextColor(WHITE);
  cv.setCursor(4, 36);
  if (wifi) {
    cv.printf("SSID: %s\n    Pass: %s\n    Open http://%s\n", AP_SSID, AP_PASS,
              WiFi.softAPIP().toString().c_str());
  } else {
    cv.printf("Advertising as %s\n    Write LIST or GET <file>\n    to ...0002\n    Data via notify on ...0003\n",
              APP_NAME);
  }
  cv.setCursor(4, 120);
  cv.setTextColor(DARKGREY);
  cv.print("Q = back");
  cv.pushSprite(0, 0);
}

// ---------------- Ride loop pieces ----------------
void imuTick() {
  if (millis() - lastImu < 20) return;  // ~50 Hz
  lastImu = millis();
  if (!M5.Imu.update()) return;
  if (!recording) return;
  auto d = M5.Imu.getImuData();
  logFile.printf("%lu,%.4f,%.4f,%.4f,%.2f,%.2f,%.2f,%.2f,%d\n", (unsigned long)millis(),
                 d.accel.x, d.accel.y, d.accel.z, d.gyro.x, d.gyro.y, d.gyro.z, tel.kmh, tel.batt);
  samples++;
  if (millis() - lastFlush > 1000) { logFile.flush(); lastFlush = millis(); }
}

void pollTick_() {
  if (!scooterConnected || millis() - lastPoll < 250) return;
  lastPoll = millis();
  sendMotorInfoReq();
}

void goHome() {
  if (state == ST_RIDE) {
    stopRecording();
    if (client && scooterConnected) client->disconnect();
  } else if (state == ST_EXPORT_WIFI) stopWifiExport();
  else if (state == ST_EXPORT_BLE) stopBleExport();
  state = ST_HOME;
  drawHome();
}

// ---------------- Arduino ----------------
void setup() {
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Display.setRotation(1);
  cv.createSprite(M5Cardputer.Display.width(), M5Cardputer.Display.height());
  msg(APP_NAME, "starting...");

  authQ = xQueueCreate(16, sizeof(Notif));
  frameQ = xQueueCreate(8, sizeof(Notif));
  initStorage();
  NimBLEDevice::init(APP_NAME);
  NimBLEDevice::setMTU(185);
  NimBLEDevice::setSecurityAuth(BLE_BONDING, BLE_BONDING, BLE_BONDING);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_KEYBOARD_DISPLAY);
  drawHome();
}

uint32_t lastDraw = 0;

void loop() {
  char k = getKey();

  switch (state) {
    case ST_HOME:
      if (k == 's') { showAll = false; scanScooters(); state = ST_SCAN; drawScan(); }
      else if (k == 'w' && fsys) { startWifiExport(); state = ST_EXPORT_WIFI; drawExport(true); }
      else if (k == 'b' && fsys) { startBleExport(); state = ST_EXPORT_BLE; drawExport(false); }
      break;

    case ST_SCAN:
      if (k == ';' && sel > 0) sel--;
      else if (k == '.' && sel + 1 < (int)devs.size()) sel++;
      else if (k == 'a') { showAll = !showAll; scanScooters(); }
      else if (k == 's') scanScooters();
      else if (k == 'f' && !devs.empty()) { forgetToken(devs[sel].addr); msg("Pairing forgotten", devs[sel].name, YELLOW); delay(1000); }
      else if (k == 'q') { goHome(); break; }
      else if (k == '\n' && !devs.empty()) {
        if (connectScooter(devs[sel].addr)) {
          tel = Telemetry();
          state = ST_RIDE;
          break;
        }
      }
      drawScan();
      break;

    case ST_RIDE:
      if (k == 'r') { recording ? stopRecording() : startRecording(); }
      else if (k == 'q') { goHome(); break; }
      processFrames();
      imuTick();
      pollTick_();
      if (!scooterConnected && haveScooter) {  // auto-reconnect (logs in with the saved token)
        static uint32_t lastTry = 0;
        if (millis() - lastTry > 4000) { lastTry = millis(); connectScooter(scooterAddr); }
      }
      if (millis() - lastDraw > 100) { lastDraw = millis(); drawRide(); }
      break;

    case ST_EXPORT_WIFI:
      web.handleClient();
      if (k == 'q') goHome();
      break;

    case ST_EXPORT_BLE:
      pumpBleExport();
      if (k == 'q') goHome();
      break;
  }
  delay(1);
}
