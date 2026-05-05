#include <Arduino.h>
#include <cstring>
#include <DNSServer.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WiFi.h>
#include <mbedtls/sha256.h>
#include <esp_random.h>

#include <USB.h>
#include <USBHIDKeyboard.h>

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh_esp32.h>

#include <sys/select.h>
#include <netinet/in.h>
#include "lwip/etharp.h"
#include "lwip/netif.h"

namespace {

constexpr const char *kFirmwareVersion = "v1.6";
constexpr const char *kPreferencesNamespace = "sshwk";
constexpr const char *kPortalSsid = "SSHWK";
const IPAddress kPortalIp(10, 10, 10, 1);
const IPAddress kPortalGateway(10, 10, 10, 1);
const IPAddress kPortalSubnet(255, 255, 255, 0);
constexpr uint16_t kHttpPort = 80;
constexpr uint16_t kSshPort = 22;
constexpr uint32_t kWifiConnectTimeoutMs = 20000;
constexpr uint32_t kProvisioningConnectTimeoutMs = 15000;
constexpr uint32_t kReconnectIntervalMs = 10000;
constexpr uint32_t kFactoryResetHoldMs = 5000;
constexpr uint32_t kFactoryResetDebounceMs = 35;
constexpr int32_t kLowSignalThresholdDbm = -70;
constexpr uint8_t kFactoryResetPin = 0;
constexpr size_t kSshBufferSize = 64;
constexpr uint16_t kDnsPort = 53;
constexpr int kMaxAuthAttempts = 5;
constexpr int kScanCacheMax = 20;
constexpr int kBanThreshold = 20;
constexpr size_t kBanListSize = 16;
constexpr uint32_t kBanDurationMs = 24UL * 3600UL * 1000UL;

size_t getArduinoLoopTaskStackSize() {
  return 16384;
}

struct AppConfig {
  String wifiSsid;
  String wifiPassword;
  String sshUsername;
  String sshPasswordHash;
  String sshPasswordSalt;
  char ctrlLayoutKey = 'A';
  char ctrlDiscKey = 'D';

  bool isComplete() const {
    return !wifiSsid.isEmpty() && !sshUsername.isEmpty() &&
           !sshPasswordHash.isEmpty() && !sshPasswordSalt.isEmpty();
  }

  uint8_t ctrlLayoutByte() const { return static_cast<uint8_t>(ctrlLayoutKey - 'A' + 1); }
  uint8_t ctrlDiscByte() const { return static_cast<uint8_t>(ctrlDiscKey - 'A' + 1); }
};

class ConfigStore {
 public:
  bool load(AppConfig &config) {
    Preferences prefs;
    if (!prefs.begin(kPreferencesNamespace, true)) {
      return false;
    }

    config.wifiSsid = prefs.getString("wifi_ssid", "");
    config.wifiPassword = prefs.getString("wifi_pass", "");
    config.sshUsername = prefs.getString("ssh_user", "");
    config.sshPasswordHash = prefs.getString("ssh_hash", "");
    config.sshPasswordSalt = prefs.getString("ssh_salt", "");
    const String ctrlLayout = prefs.getString("ctrl_layout", "A");
    config.ctrlLayoutKey = ctrlLayout.isEmpty() ? 'A' : static_cast<char>(toupper(ctrlLayout[0]));
    const String ctrlDisc = prefs.getString("ctrl_disc", "D");
    config.ctrlDiscKey = ctrlDisc.isEmpty() ? 'D' : static_cast<char>(toupper(ctrlDisc[0]));
    prefs.end();
    return config.isComplete();
  }

  bool save(const AppConfig &config) {
    Preferences prefs;
    if (!prefs.begin(kPreferencesNamespace, false)) {
      return false;
    }

    const bool wifiSsidOk = prefs.putString("wifi_ssid", config.wifiSsid) > 0;
    const bool wifiPassOk =
        config.wifiPassword.isEmpty() || prefs.putString("wifi_pass", config.wifiPassword) > 0;
    const bool sshUserOk = prefs.putString("ssh_user", config.sshUsername) > 0;
    const bool sshHashOk = prefs.putString("ssh_hash", config.sshPasswordHash) > 0;
    const bool sshSaltOk = prefs.putString("ssh_salt", config.sshPasswordSalt) > 0;
    const bool ctrlLayoutOk = prefs.putString("ctrl_layout", String(config.ctrlLayoutKey)) > 0;
    const bool ctrlDiscOk = prefs.putString("ctrl_disc", String(config.ctrlDiscKey)) > 0;
    const bool ok = wifiSsidOk && wifiPassOk && sshUserOk && sshHashOk && sshSaltOk && ctrlLayoutOk && ctrlDiscOk;
    prefs.end();
    return ok;
  }

  void clear() {
    Preferences prefs;
    if (!prefs.begin(kPreferencesNamespace, false)) {
      return;
    }
    prefs.clear();
    prefs.end();
  }
};

String sha256HexSalted(const String &value, const String &salt) {
  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, reinterpret_cast<const unsigned char *>(salt.c_str()), salt.length());
  mbedtls_sha256_update_ret(&ctx, reinterpret_cast<const unsigned char *>(value.c_str()), value.length());
  mbedtls_sha256_finish_ret(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  char hex[65];
  for (size_t i = 0; i < sizeof(hash); ++i) {
    snprintf(hex + (i * 2), 3, "%02x", hash[i]);
  }
  hex[64] = '\0';
  return String(hex);
}

String generateSalt() {
  uint8_t bytes[16];
  esp_fill_random(bytes, sizeof(bytes));
  char hex[33];
  for (size_t i = 0; i < sizeof(bytes); ++i) {
    snprintf(hex + (i * 2), 3, "%02x", bytes[i]);
  }
  hex[32] = '\0';
  return String(hex);
}

struct MacEntry {
  uint8_t mac[6];
  int failures;
  uint32_t bannedAtMs;
  bool banned;
  bool valid;
};

MacEntry gBanList[kBanListSize];

bool isMacBanned(const uint8_t mac[6]) {
  const uint32_t now = millis();
  for (auto &e : gBanList) {
    if (!e.valid || memcmp(e.mac, mac, 6) != 0) continue;
    if (!e.banned) return false;
    if (now - e.bannedAtMs < kBanDurationMs) return true;
    e.banned = false;
    e.failures = 0;
    return false;
  }
  return false;
}

void recordAuthFailure(const uint8_t mac[6]) {
  MacEntry *slot = nullptr;
  for (auto &e : gBanList) {
    if (e.valid && memcmp(e.mac, mac, 6) == 0) { slot = &e; break; }
  }
  if (!slot) {
    for (auto &e : gBanList) {
      if (!e.valid) { slot = &e; break; }
    }
  }
  if (!slot) return;  // table full
  if (!slot->valid) {
    *slot = MacEntry{};
    memcpy(slot->mac, mac, 6);
    slot->valid = true;
  }
  ++slot->failures;
  if (!slot->banned && slot->failures >= kBanThreshold) {
    slot->banned = true;
    slot->bannedAtMs = millis();
    Serial.printf("[SSH] MAC %02X:%02X:%02X:%02X:%02X:%02X banned for 24h after %d failures.\n",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], slot->failures);
  }
}

// Resolves the remote client's MAC via ARP lookup on the session socket.
bool getClientMac(ssh_session session, uint8_t outMac[6]) {
  const int fd = ssh_get_fd(session);
  if (fd < 0) return false;
  struct sockaddr_in peer{};
  socklen_t len = sizeof(peer);
  if (getpeername(fd, reinterpret_cast<struct sockaddr *>(&peer), &len) != 0) return false;
  ip4_addr_t ip4;
  ip4.addr = peer.sin_addr.s_addr;
  struct eth_addr *eth = nullptr;
  const ip4_addr_t *found = nullptr;
  if (etharp_find_addr(netif_default, &ip4, &eth, &found) < 0 || eth == nullptr) return false;
  memcpy(outMac, eth->addr, 6);
  return true;
}

bool isValidSshUsername(const String &username) {
  if (username.isEmpty() || username.length() > 32) {
    return false;
  }

  for (size_t i = 0; i < username.length(); ++i) {
    const char c = username[i];
    const bool ok = isAlphaNumeric(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.';
    if (!ok) {
      return false;
    }
  }
  return true;
}

class StatusLed {
 public:
  enum class Mode {
    Booting,
    Provisioning,
    Scanning,
    Connecting,
    ConnectedGood,
    ConnectedWeak,
    SshActive,
    Resetting,
    Error,
  };

  void begin() {
    setMode(Mode::Booting);
  }

  void setMode(Mode mode) {
    mode_ = mode;
    apply(true);
  }

  void refreshForWifi() {
    if (mode_ == Mode::Provisioning || mode_ == Mode::Scanning || mode_ == Mode::Booting || mode_ == Mode::Connecting || mode_ == Mode::Error) {
      apply();
      return;
    }

    if (WiFi.status() != WL_CONNECTED) {
      setMode(Mode::Connecting);
      return;
    }

    if (mode_ != Mode::SshActive) {
      setMode(WiFi.RSSI() <= kLowSignalThresholdDbm ? Mode::ConnectedWeak : Mode::ConnectedGood);
    } else {
      apply();
    }
  }

  void tick() {
    apply();
  }

 private:
  void apply(bool force = false) {
    const uint32_t now = millis();
    if (!force && now - lastShowMs_ < 50) {
      return;
    }
    lastShowMs_ = now;

    uint8_t r = 0;
    uint8_t g = 0;
    uint8_t b = 0;

    switch (mode_) {
      case Mode::Booting:
        r = 0;
        g = 0;
        b = pulse(now, 48, 8);
        break;
      case Mode::Provisioning:
        r = pulse(now, 48, 12);
        g = pulse(now, 48, 12);
        b = pulse(now, 48, 12);
        break;
      case Mode::Scanning:
        if (((now / 180) % 2) == 0) {
          r = g = b = 48;
        }
        break;
      case Mode::Connecting:
        r = 0;
        g = pulse(now, 28, 4);
        b = pulse(now, 48, 8);
        break;
      case Mode::ConnectedGood:
        r = 0;
        g = 0;
        b = 48;
        break;
      case Mode::ConnectedWeak:
        r = 48;
        g = 32;
        b = 0;
        break;
      case Mode::SshActive:
        r = 0;
        g = 32;
        b = 48;
        break;
      case Mode::Resetting:
        if (((now / 150) % 2) == 0) {
          r = 56;
        } else {
          r = 0;
        }
        g = 0;
        b = 0;
        break;
      case Mode::Error:
        r = pulse(now, 56, 0);
        g = 0;
        b = 0;
        break;
    }

    neopixelWrite(RGB_BUILTIN, r, g, b);
  }

  uint8_t pulse(uint32_t now, uint8_t high, uint8_t low) const {
    const uint16_t phase = (now / 8) % 512;
    const uint16_t mirrored = phase < 256 ? phase : 511 - phase;
    return low + ((high - low) * mirrored) / 255;
  }

  Mode mode_ = Mode::Booting;
  uint32_t lastShowMs_ = 0;
};

StatusLed gStatusLed;

bool pollFactoryReset(ConfigStore &store) {
  static bool initialized = false;
  static bool lastRawState = HIGH;
  static bool stableState = HIGH;
  static uint32_t lastChangeMs = 0;
  static uint32_t pressedAtMs = 0;
  static bool resetTriggered = false;

  const bool rawState = digitalRead(kFactoryResetPin);
  const uint32_t now = millis();

  if (!initialized) {
    initialized = true;
    lastRawState = rawState;
    stableState = rawState;
    lastChangeMs = now;
    return false;
  }

  if (rawState != lastRawState) {
    lastRawState = rawState;
    lastChangeMs = now;
  }

  if (now - lastChangeMs < kFactoryResetDebounceMs) {
    return false;
  }

  if (rawState != stableState) {
    stableState = rawState;
    if (stableState == LOW) {
      pressedAtMs = now;
      resetTriggered = false;
    } else {
      pressedAtMs = 0;
      resetTriggered = false;
    }
  }

  if (stableState != LOW) {
    resetTriggered = false;
    return false;
  }

  if (!resetTriggered && pressedAtMs != 0 && now - pressedAtMs >= kFactoryResetHoldMs) {
    resetTriggered = true;
    Serial.printf("[RESET] Factory reset pin GPIO%u held for 5 seconds. Clearing saved configuration.\n", kFactoryResetPin);
    gStatusLed.setMode(StatusLed::Mode::Resetting);
    for (int i = 0; i < 12; ++i) {
      gStatusLed.tick();
      delay(125);
    }
    store.clear();
    ESP.restart();
    return true;
  }

  return false;
}

// ES-MX/LATAM keyboard layout table.
// modifier bits: 0x02 = Left Shift, 0x40 = Right Alt (AltGr).
// deadKey = true means the physical key is a dead key; a trailing Space is sent
// automatically to resolve it to the literal character.
struct LayoutKey {
  uint16_t codepoint;
  uint8_t  usage;     // raw HID usage ID (physical key position)
  uint8_t  modifier;  // HID modifier byte
  bool     deadKey;
};

static const LayoutKey kLatamLayout[] = {
  {' ', 0x2c, 0x00, false},
  {'!', 0x1e, 0x02, false},
  {'"', 0x1f, 0x02, false},
  {'#', 0x20, 0x02, false},
  {'$', 0x21, 0x02, false},
  {'%', 0x22, 0x02, false},
  {'&', 0x23, 0x02, false},
  {'\'', 0x2d, 0x00, false},
  {'(', 0x25, 0x02, false},
  {')', 0x26, 0x02, false},
  {'*', 0x30, 0x02, false},
  {'+', 0x30, 0x00, false},
  {',', 0x36, 0x00, false},
  {'-', 0x38, 0x00, false},
  {'.', 0x37, 0x00, false},
  {'/', 0x24, 0x02, false},
  {'0', 0x27, 0x00, false},
  {'1', 0x1e, 0x00, false},
  {'2', 0x1f, 0x00, false},
  {'3', 0x20, 0x00, false},
  {'4', 0x21, 0x00, false},
  {'5', 0x22, 0x00, false},
  {'6', 0x23, 0x00, false},
  {'7', 0x24, 0x00, false},
  {'8', 0x25, 0x00, false},
  {'9', 0x26, 0x00, false},
  {':', 0x37, 0x02, false},
  {';', 0x36, 0x02, false},
  {'<', 0x64, 0x00, false},
  {'=', 0x27, 0x02, false},
  {'>', 0x64, 0x02, false},
  {'?', 0x2d, 0x02, false},
  {'@', 0x14, 0x40, false},  // AltGr+Q on LATAM
  {'[', 0x34, 0x02, false},
  {'\\', 0x2d, 0x40, false},
  {']', 0x31, 0x02, false},
  {'^', 0x34, 0x40, true},
  {'_', 0x38, 0x02, false},
  {'`', 0x31, 0x40, true},
  {'{', 0x34, 0x00, false},
  {'|', 0x35, 0x00, false},
  {'}', 0x31, 0x00, false},
  {'~', 0x21, 0x40, false},
  {0x00A1, 0x2e, 0x02, false},  // ¡
  {0x00AC, 0x35, 0x40, false},  // ¬
  {0x00B0, 0x35, 0x02, false},  // °
  {0x00B4, 0x2f, 0x00, true},   // ´
  {0x00A8, 0x2f, 0x02, true},   // ¨
  {0x00BF, 0x2e, 0x00, false},  // ¿
  {0x00D1, 0x33, 0x02, false},  // Ñ
  {0x00F1, 0x33, 0x00, false},  // ñ
};

class KeyboardSink {
 public:
  enum class Layout {
    Us,
    Latam,
  };

  bool begin() {
    keyboard_.begin();
    USB.begin();
    delay(250);
    keyboard_.releaseAll();
    return true;
  }

  Layout toggleLayout() {
    layout_ = layout_ == Layout::Us ? Layout::Latam : Layout::Us;
    resetUtf8State();
    return layout_;
  }

  const char *layoutName() const {
    return layout_ == Layout::Us ? "US" : "ES-MX/LATAM";
  }

  const char *takeEchoLabel() {
    const char *label = pendingEchoLabel_;
    pendingEchoLabel_ = nullptr;
    return label;
  }

  bool ansiSequencePending() const {
    return ansiState_ != AnsiState::Idle;
  }

  bool sendByte(uint8_t byte) {
    if (handleAnsi(byte)) {
      return true;
    }

    // UTF-8 multi-byte continuation
    if (utf8State_ > 0) {
      if ((byte & 0xC0) == 0x80) {
        utf8Codepoint_ = (utf8Codepoint_ << 6) | (byte & 0x3F);
        if (--utf8State_ == 0) {
          dispatchCodepoint(utf8Codepoint_);
        }
      } else {
        utf8State_ = 0;  // malformed — reset and reprocess as new byte
        sendByte(byte);
      }
      return true;
    }

    // UTF-8 sequence start bytes
    if (byte >= 0xF0) { utf8State_ = 3; utf8Codepoint_ = byte & 0x07; return true; }
    if (byte >= 0xE0) { utf8State_ = 2; utf8Codepoint_ = byte & 0x0F; return true; }
    if (byte >= 0xC0) { utf8State_ = 1; utf8Codepoint_ = byte & 0x1F; return true; }
    if (byte >= 0x80) { return true; }  // stray continuation — ignore

    // ASCII control characters
    if (byte == '\r') {
      lastByteWasCarriageReturn_ = true;
      pendingEchoLabel_ = "[Enter]";
      keyboard_.write(KEY_RETURN);
      return true;
    }
    if (byte == '\n') {
      if (lastByteWasCarriageReturn_) {
        lastByteWasCarriageReturn_ = false;
        return true;
      }
      pendingEchoLabel_ = "[Enter]";
      keyboard_.write(KEY_RETURN);
      return true;
    }
    lastByteWasCarriageReturn_ = false;

    if (byte == '\t') { pendingEchoLabel_ = "[Tab]"; keyboard_.write(KEY_TAB); return true; }
    if (byte == 0x08 || byte == 0x7F) { pendingEchoLabel_ = "[Backspace]"; keyboard_.write(KEY_BACKSPACE); return true; }
    if (byte == 0x1B) { ansiState_ = AnsiState::Esc; ansiLength_ = 0; return true; }
    if (byte >= 2 && byte <= 26) {
      keyboard_.press(KEY_LEFT_CTRL);
      keyboard_.press(static_cast<uint8_t>('a' + byte - 1));
      delay(8);
      keyboard_.releaseAll();
      pendingEchoLabel_ = controlEchoLabel(byte);
      return true;
    }

    // Printable ASCII — route through the layout-aware dispatcher so that
    // characters whose physical key positions differ between US and Spanish ES
    // (e.g. |, {, }, [, ], @, #, -, =, /, …) produce the correct output on a
    // machine configured with Spanish ES keyboard layout.
    if (byte >= 0x20) {
      dispatchCodepoint(static_cast<uint32_t>(byte));
    }
    return true;
  }

  const char *statusText() const {
    return "USB HID keyboard mode active.\r\n";
  }

 private:
  enum class AnsiState {
    Idle,
    Esc,
    Csi,
    Ss3,
  };

  bool handleAnsi(uint8_t byte) {
    if (ansiState_ == AnsiState::Idle) {
      return false;
    }

    if (ansiState_ == AnsiState::Esc) {
      if (byte == '[') {
        ansiState_ = AnsiState::Csi;
        ansiLength_ = 0;
        return true;
      }
      if (byte == 'O') {
        ansiState_ = AnsiState::Ss3;
        return true;
      }
      ansiState_ = AnsiState::Idle;
      keyboard_.write(KEY_ESC);
      return sendByte(byte);
    }

    if (ansiState_ == AnsiState::Ss3) {
      ansiState_ = AnsiState::Idle;
      switch (byte) {
        case 'P': keyboard_.write(KEY_F1); break;
        case 'Q': keyboard_.write(KEY_F2); break;
        case 'R': keyboard_.write(KEY_F3); break;
        case 'S': keyboard_.write(KEY_F4); break;
        default:
          keyboard_.write(KEY_ESC);
          keyboard_.write('O');
          keyboard_.write(byte);
          break;
      }
      return true;
    }

    if (ansiState_ == AnsiState::Csi) {
      if (ansiLength_ < sizeof(ansiBuffer_) - 1) {
        ansiBuffer_[ansiLength_++] = static_cast<char>(byte);
        ansiBuffer_[ansiLength_] = '\0';
      }

      if ((byte >= 'A' && byte <= 'Z') || byte == '~') {
        dispatchAnsi();
        ansiState_ = AnsiState::Idle;
      }
      return true;
    }

    ansiState_ = AnsiState::Idle;
    return false;
  }

  void resetUtf8State() {
    utf8State_ = 0;
    utf8Codepoint_ = 0;
  }

  // Returns the modifier bitmask from a CSI sequence with a semicolon (e.g. "1;5A" → 5).
  // Returns 1 (no modifier) if there is no semicolon.
  int parseModifier() const {
    const char *semi = strchr(ansiBuffer_, ';');
    return semi ? atoi(semi + 1) : 1;
  }

  // Resolves the HID key for the accumulated CSI buffer, ignoring any modifier suffix.
  // For ~-terminated sequences the leading number identifies the key.
  // For letter-terminated sequences the final letter identifies the key.
  uint8_t resolveAnsiKey() const {
    if (ansiLength_ == 0) return 0;
    const char finalChar = ansiBuffer_[ansiLength_ - 1];

    if (finalChar == '~') {
      // atoi stops at ';' or '~', giving us the key code.
      switch (atoi(ansiBuffer_)) {
        case 1: case 7: return KEY_HOME;
        case 2:         return KEY_INSERT;
        case 3:         return KEY_DELETE;
        case 4: case 8: return KEY_END;
        case 5:         return KEY_PAGE_UP;
        case 6:         return KEY_PAGE_DOWN;
        case 11:        return KEY_F1;
        case 12:        return KEY_F2;
        case 13:        return KEY_F3;
        case 14:        return KEY_F4;
        case 15:        return KEY_F5;
        case 17:        return KEY_F6;
        case 18:        return KEY_F7;
        case 19:        return KEY_F8;
        case 20:        return KEY_F9;
        case 21:        return KEY_F10;
        case 23:        return KEY_F11;
        case 24:        return KEY_F12;
        default:        return 0;
      }
    }

    // Letter-terminated (arrows, Home, End). The modifier sits after ';' so
    // we only need the final letter to identify the key.
    switch (finalChar) {
      case 'A': return KEY_UP_ARROW;
      case 'B': return KEY_DOWN_ARROW;
      case 'C': return KEY_RIGHT_ARROW;
      case 'D': return KEY_LEFT_ARROW;
      case 'H': return KEY_HOME;
      case 'F': return KEY_END;
      default:  return 0;
    }
  }

  void dispatchAnsi() {
    const uint8_t key = resolveAnsiKey();
    if (key == 0) {
      keyboard_.write(KEY_ESC);
      for (size_t i = 0; i < ansiLength_; ++i) {
        keyboard_.write(static_cast<uint8_t>(ansiBuffer_[i]));
      }
      return;
    }

    const int mod = parseModifier();
    // modifier encoding: 2=Shift, 3=Alt, 4=Shift+Alt, 5=Ctrl, 6=Ctrl+Shift, 7=Ctrl+Alt, 8=Ctrl+Shift+Alt
    const bool shiftDown = (mod == 2 || mod == 4 || mod == 6 || mod == 8);
    const bool ctrlDown  = (mod == 5 || mod == 6 || mod == 7 || mod == 8);
    pendingEchoLabel_ = keyEchoLabel(key, shiftDown, ctrlDown);

    if (shiftDown || ctrlDown) {
      if (shiftDown) keyboard_.press(KEY_LEFT_SHIFT);
      if (ctrlDown)  keyboard_.press(KEY_LEFT_CTRL);
      keyboard_.press(key);
      delay(8);
      keyboard_.releaseAll();
    } else {
      keyboard_.write(key);
    }
  }

  const char *controlEchoLabel(uint8_t byte) const {
    switch (byte) {
      case 0x02: return "[Ctrl+B]";
      case 0x03: return "[Ctrl+C]";
      case 0x05: return "[Ctrl+E]";
      case 0x06: return "[Ctrl+F]";
      case 0x07: return "[Ctrl+G]";
      case 0x08: return "[Backspace]";
      case 0x09: return "[Tab]";
      case 0x0A: return "[Enter]";
      case 0x0B: return "[Ctrl+K]";
      case 0x0C: return "[Ctrl+L]";
      case 0x0D: return "[Enter]";
      case 0x0E: return "[Ctrl+N]";
      case 0x0F: return "[Ctrl+O]";
      case 0x10: return "[Ctrl+P]";
      case 0x11: return "[Ctrl+Q]";
      case 0x12: return "[Ctrl+R]";
      case 0x13: return "[Ctrl+S]";
      case 0x14: return "[Ctrl+T]";
      case 0x15: return "[Ctrl+U]";
      case 0x16: return "[Ctrl+V]";
      case 0x17: return "[Ctrl+W]";
      case 0x18: return "[Ctrl+X]";
      case 0x19: return "[Ctrl+Y]";
      case 0x1A: return "[Ctrl+Z]";
      default: return "[Ctrl]";
    }
  }

  const char *keyEchoLabel(uint8_t key, bool shiftDown, bool ctrlDown) const {
    if (ctrlDown && shiftDown) {
      switch (key) {
        case KEY_UP_ARROW: return "[Ctrl+Shift+Arrow Up]";
        case KEY_DOWN_ARROW: return "[Ctrl+Shift+Arrow Down]";
        case KEY_LEFT_ARROW: return "[Ctrl+Shift+Arrow Left]";
        case KEY_RIGHT_ARROW: return "[Ctrl+Shift+Arrow Right]";
      }
    }
    if (ctrlDown) {
      switch (key) {
        case KEY_UP_ARROW: return "[Ctrl+Arrow Up]";
        case KEY_DOWN_ARROW: return "[Ctrl+Arrow Down]";
        case KEY_LEFT_ARROW: return "[Ctrl+Arrow Left]";
        case KEY_RIGHT_ARROW: return "[Ctrl+Arrow Right]";
      }
    }
    if (shiftDown) {
      switch (key) {
        case KEY_UP_ARROW: return "[Shift+Arrow Up]";
        case KEY_DOWN_ARROW: return "[Shift+Arrow Down]";
        case KEY_LEFT_ARROW: return "[Shift+Arrow Left]";
        case KEY_RIGHT_ARROW: return "[Shift+Arrow Right]";
      }
    }

    switch (key) {
      case KEY_UP_ARROW: return "[Arrow Up]";
      case KEY_DOWN_ARROW: return "[Arrow Down]";
      case KEY_LEFT_ARROW: return "[Arrow Left]";
      case KEY_RIGHT_ARROW: return "[Arrow Right]";
      case KEY_HOME: return "[Home]";
      case KEY_END: return "[End]";
      case KEY_INSERT: return "[Insert]";
      case KEY_DELETE: return "[Delete]";
      case KEY_PAGE_UP: return "[Page Up]";
      case KEY_PAGE_DOWN: return "[Page Down]";
      case KEY_F1: return "[F1]";
      case KEY_F2: return "[F2]";
      case KEY_F3: return "[F3]";
      case KEY_F4: return "[F4]";
      case KEY_F5: return "[F5]";
      case KEY_F6: return "[F6]";
      case KEY_F7: return "[F7]";
      case KEY_F8: return "[F8]";
      case KEY_F9: return "[F9]";
      case KEY_F10: return "[F10]";
      case KEY_F11: return "[F11]";
      case KEY_F12: return "[F12]";
      default: return "[Key]";
    }
  }

  void tapRaw(uint8_t usage, uint8_t modifier = 0) {
    if (modifier & 0x02) {
      keyboard_.pressRaw(0xE1);  // Left Shift
    }
    if (modifier & 0x40) {
      keyboard_.pressRaw(0xE6);  // Right Alt / AltGr
    }

    keyboard_.pressRaw(usage);
    delay(8);
    keyboard_.releaseRaw(usage);

    if (modifier & 0x40) {
      keyboard_.releaseRaw(0xE6);
    }
    if (modifier & 0x02) {
      keyboard_.releaseRaw(0xE1);
    }
  }

  void dispatchCodepoint(uint32_t codepoint) {
    if (layout_ == Layout::Us) {
      if (codepoint < 0x80) {
        keyboard_.write(static_cast<uint8_t>(codepoint));
      } else {
        keyboard_.write('?');
      }
      return;
    }

    if ((codepoint >= 'a' && codepoint <= 'z') ||
        (codepoint >= 'A' && codepoint <= 'Z')) {
      keyboard_.write(static_cast<uint8_t>(codepoint));
      return;
    }

    for (const auto &entry : kLatamLayout) {
      if (entry.codepoint != codepoint) {
        continue;
      }

      tapRaw(entry.usage, entry.modifier);
      if (entry.deadKey) {
        keyboard_.write(' ');
      }
      return;
    }

    keyboard_.write('?');
  }

  USBHIDKeyboard keyboard_;
  Layout layout_ = Layout::Us;
  AnsiState ansiState_ = AnsiState::Idle;
  char ansiBuffer_[8] = {0};
  size_t ansiLength_ = 0;
  bool lastByteWasCarriageReturn_ = false;
  uint8_t utf8State_ = 0;
  uint32_t utf8Codepoint_ = 0;
  const char *pendingEchoLabel_ = nullptr;
};

KeyboardSink gKeyboardSink;

struct ScanCache {
  String ssids[kScanCacheMax];
  int32_t rssi[kScanCacheMax] = {};
  int count = 0;
  bool scanning = false;
  uint32_t lastMs = 0;
};

class ProvisioningPortal {
 public:
  explicit ProvisioningPortal(ConfigStore &store) : store_(store), server_(kHttpPort) {}

  [[noreturn]] void run() {
    startAccessPoint();
    configureRoutes();
    server_.begin();
    dnsServer_.start(kDnsPort, "*", kPortalIp);
    gStatusLed.setMode(StatusLed::Mode::Provisioning);

    Serial.println("[PORTAL] Provisioning portal started.");
    Serial.printf("[PORTAL] Connect to SSID '%s' and open http://%s/\n", kPortalSsid, kPortalIp.toString().c_str());

    // Give the AP a moment to fully initialise before scanning.
    delay(300);
    WiFi.scanNetworks(true, false, false, 600);  // 600 ms/channel for thorough scan
    scanCache_.scanning = true;
    gStatusLed.setMode(StatusLed::Mode::Scanning);

    for (;;) {
      pollFactoryReset(store_);
      dnsServer_.processNextRequest();
      server_.handleClient();
      gStatusLed.tick();
      tickScan();
      delay(5);
    }
  }

 private:
  void tickScan() {
    if (!scanCache_.scanning) return;
    const int n = WiFi.scanComplete();
    if (n == WIFI_SCAN_RUNNING) return;

    // Build deduplicated list sorted strongest-first (scan results already come
    // sorted by RSSI; we just skip duplicate SSIDs keeping the strongest entry).
    scanCache_.count = 0;
    for (int i = 0; i < n && scanCache_.count < kScanCacheMax; ++i) {
      const String ssid = WiFi.SSID(i);
      if (ssid.isEmpty()) continue;
      bool dup = false;
      for (int j = 0; j < scanCache_.count; ++j) {
        if (scanCache_.ssids[j] == ssid) { dup = true; break; }
      }
      if (!dup) {
        scanCache_.ssids[scanCache_.count] = ssid;
        scanCache_.rssi[scanCache_.count] = WiFi.RSSI(i);
        ++scanCache_.count;
      }
    }

    scanCache_.scanning = false;
    scanCache_.lastMs = millis();
    WiFi.scanDelete();
    gStatusLed.setMode(StatusLed::Mode::Provisioning);
    Serial.printf("[PORTAL] Scan complete: %d unique network(s).\n", scanCache_.count);
  }

  void startAccessPoint() {
    WiFi.persistent(false);
    WiFi.mode(WIFI_AP_STA);  // STA mode required for WiFi.scanNetworks() to work
    WiFi.softAPdisconnect(true);
    WiFi.disconnect(false);  // disconnect STA without disabling the STA interface
    delay(100);
    WiFi.softAPConfig(kPortalIp, kPortalGateway, kPortalSubnet);
    WiFi.softAP(kPortalSsid);
  }

  void configureRoutes() {
    server_.on("/", HTTP_GET, [this]() { serveForm(""); });
    server_.on("/scan", HTTP_GET, [this]() { handleScan(); });
    server_.on("/generate_204", HTTP_GET, [this]() { redirectToPortal(); });
    server_.on("/gen_204", HTTP_GET, [this]() { redirectToPortal(); });
    server_.on("/hotspot-detect.html", HTTP_GET, [this]() { redirectToPortal(); });
    server_.on("/connecttest.txt", HTTP_GET, [this]() { redirectToPortal(); });
    server_.on("/ncsi.txt", HTTP_GET, [this]() { redirectToPortal(); });
    server_.on("/fwlink", HTTP_GET, [this]() { redirectToPortal(); });
    server_.on("/save", HTTP_POST, [this]() { handleSave(); });
    server_.onNotFound([this]() { redirectToPortal(); });
  }

  void redirectToPortal() {
    server_.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    server_.sendHeader("Pragma", "no-cache");
    server_.sendHeader("Expires", "-1");
    server_.sendHeader("Location", String("http://") + kPortalIp.toString() + "/");
    server_.send(302, "text/plain", "");
  }

  void serveForm(const String &message) {
    String html;
    html.reserve(4200);
    html += F("<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>");
    html += F("<title>SSHWK Setup</title><style>");
    html += F("body{font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px;}");
    html += F(".card{max-width:620px;margin:0 auto;background:#111827;border:1px solid #334155;border-radius:16px;padding:24px;}");
    html += F("h1{margin-top:0;}label{display:block;margin-top:16px;margin-bottom:6px;font-weight:700;}");
    html += F("input{width:100%;padding:12px;border-radius:10px;border:1px solid #475569;background:#0b1220;color:#e2e8f0;box-sizing:border-box;}");
    html += F(".btn-primary{margin-top:20px;padding:12px 16px;border:0;border-radius:10px;background:#38bdf8;color:#082f49;font-weight:700;cursor:pointer;}");
    html += F(".btn-scan{padding:12px 14px;border:0;border-radius:10px;background:#334155;color:#e2e8f0;cursor:pointer;white-space:nowrap;flex-shrink:0;}");
    html += F(".btn-scan:disabled{opacity:.5;cursor:default;}");
    html += F(".msg{margin-top:12px;padding:12px;border-radius:10px;background:#172554;color:#bfdbfe;white-space:pre-line;}");
    html += F(".hint{margin-top:16px;color:#94a3b8;font-size:14px;line-height:1.5;}");
    html += F(".scan-row{display:flex;gap:8px;align-items:stretch;}.scan-row input{flex:1;width:auto;min-width:0;}");
    html += F(".scan-opts{display:flex;align-items:center;gap:8px;margin-top:6px;color:#94a3b8;font-size:13px;}");
    html += F(".scan-opts input{width:56px;text-align:center;padding:8px;}");
    html += F(".ctrl-row{display:flex;gap:16px;margin-top:6px;}");
    html += F(".ctrl-item{flex:1;}.ctrl-item span{font-size:14px;color:#94a3b8;}");
    html += F(".ctrl-item input{width:52px;text-align:center;padding:10px 8px;}");
    html += F("</style><script>");
    html += F("function pickSsid(v){document.getElementById('wifi_ssid').value=v;}");
    html += F("function showResults(s){");
    html += F("var sel=document.getElementById('ssid_select');");
    html += F("sel.innerHTML='<option value=\"\">-- select network --</option>';");
    html += F("s.forEach(function(x){var o=document.createElement('option');o.value=x.s;o.textContent=x.s+' ('+x.r+' dBm)';sel.appendChild(o);});");
    html += F("sel.style.display='block';");
    html += F("var b=document.getElementById('sbtn');b.textContent='Scan';b.disabled=false;}");
    html += F("function pollScan(m,n){");
    html += F("if(n>12){var b=document.getElementById('sbtn');b.textContent='Scan';b.disabled=false;return;}");
    html += F("fetch('/scan?max='+m).then(function(r){return r.json();})");
    html += F(".then(function(s){if(s.length>0){showResults(s);}else{setTimeout(function(){pollScan(m,n+1);},2000);}})");
    html += F(".catch(function(){setTimeout(function(){pollScan(m,n+1);},2000);});}");
    html += F("function scanNetworks(){");
    html += F("var b=document.getElementById('sbtn');b.textContent='Scanning...';b.disabled=true;");
    html += F("var m=parseInt(document.getElementById('scan_max').value)||10;");
    html += F("pollScan(m,0);}");
    html += F("</script></head><body><div class='card'>");
    html += F("<h1>SSHWK Setup <span style='font-size:14px;font-weight:400;color:#64748b'>");
    html += kFirmwareVersion;
    html += F("</span></h1><p>Configure Wi-Fi and SSH credentials for the device.</p>");
    if (!message.isEmpty()) {
      html += "<div class='msg'>" + message + "</div>";
    }
    html += F("<form method='post' action='/save'>");
    html += F("<label for='wifi_ssid'>Wi-Fi SSID</label>");
    html += F("<div class='scan-row'>");
    html += F("<input id='wifi_ssid' name='wifi_ssid' maxlength='32' required>");
    html += F("<button id='sbtn' class='btn-scan' type='button' onclick='scanNetworks()'>Scan</button>");
    html += F("</div>");
    html += F("<select id='ssid_select' style='display:none;margin-top:8px;width:100%;padding:12px;border-radius:10px;border:1px solid #475569;background:#0b1220;color:#e2e8f0;box-sizing:border-box;' onchange='if(this.value)pickSsid(this.value)'></select>");
    html += F("<div class='scan-opts'><span>Max networks to show:</span><input id='scan_max' name='scan_max' type='number' min='1' max='50' value='10'></div>");
    html += F("<label for='wifi_pass'>Wi-Fi Password</label><input id='wifi_pass' name='wifi_pass' type='password' maxlength='64'>");
    html += F("<label for='ssh_user'>SSH Username</label><input id='ssh_user' name='ssh_user' maxlength='32' required>");
    html += F("<label for='ssh_pass'>SSH Password</label><input id='ssh_pass' name='ssh_pass' type='password' minlength='8' maxlength='64' required>");
    html += F("<label>Session Keys &mdash; leave blank for defaults (A and D)</label>");
    html += F("<div class='ctrl-row'>");
    html += F("<div class='ctrl-item'><span>Layout toggle: Ctrl+</span><input id='ctrl_layout' name='ctrl_layout' maxlength='1' placeholder='A'></div>");
    html += F("<div class='ctrl-item'><span>Disconnect: Ctrl+</span><input id='ctrl_disc' name='ctrl_disc' maxlength='1' placeholder='D'></div>");
    html += F("</div>");
    html += F("<button class='btn-primary' type='submit'>Save And Reboot</button></form>");
    html += F("<div class='hint'>AP SSID: <strong>SSHWK</strong>. AP IP: <strong>10.10.10.1</strong>. ");
    html += F("RGB LED is white while the provisioning hotspot is active.</div>");
    html += F("</div></body></html>");
    server_.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    server_.sendHeader("Pragma", "no-cache");
    server_.send(200, "text/html", html);
  }

  void handleSave() {
    const String wifiSsid = server_.arg("wifi_ssid");
    const String wifiPassword = server_.arg("wifi_pass");
    const String sshUser = server_.arg("ssh_user");
    const String sshPass = server_.arg("ssh_pass");

    if (wifiSsid.isEmpty()) {
      serveForm("Wi-Fi SSID is required.");
      return;
    }
    if (!isValidSshUsername(sshUser)) {
      serveForm("SSH username must be 1-32 chars and use only letters, numbers, '_', '-', or '.'.");
      return;
    }
    if (sshPass.length() < 8) {
      serveForm("SSH password must be at least 8 characters.");
      return;
    }

    const String ctrlLayoutArg = server_.arg("ctrl_layout");
    const String ctrlDiscArg = server_.arg("ctrl_disc");
    char ctrlLayoutKey = 'A';
    char ctrlDiscKey = 'D';
    if (!ctrlLayoutArg.isEmpty()) {
      const char c = static_cast<char>(toupper(static_cast<unsigned char>(ctrlLayoutArg[0])));
      if (c >= 'A' && c <= 'Z') ctrlLayoutKey = c;
    }
    if (!ctrlDiscArg.isEmpty()) {
      const char c = static_cast<char>(toupper(static_cast<unsigned char>(ctrlDiscArg[0])));
      if (c >= 'A' && c <= 'Z') ctrlDiscKey = c;
    }
    if (ctrlLayoutKey == ctrlDiscKey) {
      serveForm("Layout toggle and disconnect keys must be different.");
      return;
    }

    gStatusLed.setMode(StatusLed::Mode::Connecting);

    if (!testWifi(wifiSsid, wifiPassword)) {
      gStatusLed.setMode(StatusLed::Mode::Provisioning);
      serveForm("Wi-Fi connection failed. Check the SSID or password and try again.");
      return;
    }

    const String salt = generateSalt();
    AppConfig config;
    config.wifiSsid = wifiSsid;
    config.wifiPassword = wifiPassword;
    config.sshUsername = sshUser;
    config.sshPasswordSalt = salt;
    config.sshPasswordHash = sha256HexSalted(sshPass, salt);
    config.ctrlLayoutKey = ctrlLayoutKey;
    config.ctrlDiscKey = ctrlDiscKey;

    if (!store_.save(config)) {
      gStatusLed.setMode(StatusLed::Mode::Error);
      serveForm("Failed to save configuration to flash.");
      return;
    }

    server_.send(200, "text/html",
                 "<html><body style='font-family:Arial;padding:24px'>Configuration saved. Rebooting now...</body></html>");
    delay(1200);
    ESP.restart();
  }

  void handleScan() {
    const String maxArg = server_.arg("max");
    const int maxResults = maxArg.isEmpty() ? 10 : constrain(static_cast<int>(maxArg.toInt()), 1, kScanCacheMax);

    // If cache is empty/stale and no scan is running, start one.
    const bool stale = scanCache_.lastMs == 0 || millis() - scanCache_.lastMs > 30000;
    if (!scanCache_.scanning && (stale || scanCache_.count == 0)) {
      WiFi.scanNetworks(true, false, false, 600);  // 600 ms/channel
      scanCache_.scanning = true;
      gStatusLed.setMode(StatusLed::Mode::Scanning);
    }

    // Return whatever is cached right now (may be [] while scan runs; JS polls until populated).
    // Format: [{"s":"SSID","r":-65}, ...]
    String json = "[";
    const int count = min(scanCache_.count, maxResults);
    for (int i = 0; i < count; ++i) {
      if (i > 0) json += ',';
      json += F("{\"s\":\"");
      const String &ssid = scanCache_.ssids[i];
      for (size_t j = 0; j < ssid.length(); ++j) {
        const char c = ssid[j];
        if (c == '"' || c == '\\') json += '\\';
        json += c;
      }
      json += F("\",\"r\":");
      json += scanCache_.rssi[i];
      json += '}';
    }
    json += ']';
    server_.sendHeader("Cache-Control", "no-cache");
    server_.send(200, "application/json", json);
  }

  bool testWifi(const String &ssid, const String &password) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.begin(ssid.c_str(), password.c_str());
    const uint32_t start = millis();

    while (WiFi.status() != WL_CONNECTED && millis() - start < kProvisioningConnectTimeoutMs) {
      delay(250);
      server_.handleClient();
      gStatusLed.tick();
    }

    const bool connected = WiFi.status() == WL_CONNECTED;
    if (connected) {
      Serial.printf("[PORTAL] Wi-Fi validation succeeded. DHCP IP: %s\n", WiFi.localIP().toString().c_str());
    } else {
      Serial.println("[PORTAL] Wi-Fi validation failed.");
    }

    WiFi.disconnect(true, false);
    delay(250);
    if (!connected) {
      startAccessPoint();
    }
    return connected;
  }

  ConfigStore &store_;
  WebServer server_;
  DNSServer dnsServer_;
  ScanCache scanCache_;
};

class SshKeyboardServer {
 public:
  SshKeyboardServer(const AppConfig &config, KeyboardSink &sink, ConfigStore &store)
      : config_(config), sink_(sink), store_(store) {}

  bool begin() {
    libssh_begin();

    hostKey_ = nullptr;
    if (!loadOrGenerateHostKey()) {
      Serial.println("[SSH] Failed to initialize host key.");
      return false;
    }

    bind_ = ssh_bind_new();
    if (bind_ == nullptr) {
      Serial.println("[SSH] Failed to allocate ssh_bind.");
      cleanup();
      return false;
    }

    if (ssh_bind_options_set(bind_, SSH_BIND_OPTIONS_BINDPORT, &sshPort_) != SSH_OK) {
      Serial.println("[SSH] Failed to set bind port.");
      cleanup();
      return false;
    }
    if (ssh_bind_options_set(bind_, SSH_BIND_OPTIONS_IMPORT_KEY, hostKey_) != SSH_OK) {
      Serial.println("[SSH] Failed to import host key.");
      cleanup();
      return false;
    }

    if (ssh_bind_listen(bind_) != SSH_OK) {
      Serial.printf("[SSH] Listen failed: %s\n", ssh_get_error(bind_));
      cleanup();
      return false;
    }

    Serial.printf("[SSH] Listening on port %u\n", sshPort_);
    return true;
  }

  [[noreturn]] void runForever() {
    uint32_t lastReconnectAttemptMs = 0;

    for (;;) {
      if (pollFactoryReset(store_)) {
        continue;
      }
      gStatusLed.refreshForWifi();

      if (WiFi.status() != WL_CONNECTED) {
        if (millis() - lastReconnectAttemptMs >= kReconnectIntervalMs) {
          lastReconnectAttemptMs = millis();
          Serial.println("[WIFI] Reconnecting...");
          WiFi.disconnect();
          WiFi.begin(config_.wifiSsid.c_str(), config_.wifiPassword.c_str());
        }
        gStatusLed.tick();
        delay(50);
        continue;
      }

      handleOneClient();
      gStatusLed.tick();
      delay(10);
    }
  }

 private:
  void handleOneClient() {
    // Poll for a pending connection with a short timeout so the caller can
    // tick the LED and check the factory-reset button even when idle.
    const int bindFd = ssh_bind_get_fd(bind_);
    if (bindFd >= 0) {
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(static_cast<unsigned int>(bindFd), &rfds);
      struct timeval tv = {0, 100000};  // 100 ms
      if (select(bindFd + 1, &rfds, nullptr, nullptr, &tv) <= 0) {
        return;
      }
    }

    ssh_session session = ssh_new();
    if (session == nullptr) {
      Serial.println("[SSH] Failed to allocate session.");
      return;
    }

    if (ssh_bind_accept(bind_, session) != SSH_OK) {
      ssh_free(session);
      return;
    }

    uint8_t clientMac[6] = {};
    const bool hasMac = getClientMac(session, clientMac);
    if (hasMac && isMacBanned(clientMac)) {
      Serial.printf("[SSH] Rejected banned MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
                    clientMac[0], clientMac[1], clientMac[2], clientMac[3], clientMac[4], clientMac[5]);
      ssh_disconnect(session);
      ssh_free(session);
      return;
    }

    Serial.println("[SSH] Client connected.");
    gStatusLed.setMode(StatusLed::Mode::SshActive);
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
    ssh_set_blocking(session, 1);

    if (ssh_handle_key_exchange(session) != SSH_OK) {
      Serial.printf("[SSH] Key exchange failed: %s\n", ssh_get_error(session));
      ssh_disconnect(session);
      ssh_free(session);
      gStatusLed.refreshForWifi();
      return;
    }

    if (!authenticate(session, clientMac, hasMac)) {
      Serial.println("[SSH] Authentication failed.");
      ssh_disconnect(session);
      ssh_free(session);
      gStatusLed.refreshForWifi();
      return;
    }

    ssh_channel channel = acceptInteractiveChannel(session);
    if (channel == nullptr) {
      Serial.println("[SSH] No interactive shell channel was opened.");
      ssh_disconnect(session);
      ssh_free(session);
      gStatusLed.refreshForWifi();
      return;
    }

    sendBanner(channel);
    pumpChannel(channel);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    Serial.println("[SSH] Client disconnected.");
    gStatusLed.refreshForWifi();
  }

  bool authenticate(ssh_session session, const uint8_t mac[6], bool hasMac) {
    int attempts = 0;
    for (;;) {
      ssh_message msg = ssh_message_get(session);
      if (msg == nullptr) {
        return false;
      }

      const int type = ssh_message_type(msg);
      const int subtype = ssh_message_subtype(msg);

      if (type == SSH_REQUEST_AUTH && subtype == SSH_AUTH_METHOD_PASSWORD) {
        const char *user = ssh_message_auth_user(msg);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        const char *password = ssh_message_auth_password(msg);
#pragma GCC diagnostic pop
        const bool allowed = user != nullptr && password != nullptr &&
                             config_.sshUsername == user &&
                             config_.sshPasswordHash == sha256HexSalted(String(password), config_.sshPasswordSalt);

        if (allowed) {
          ssh_message_auth_reply_success(msg, 0);
          ssh_message_free(msg);
          Serial.printf("[SSH] Authenticated as '%s'\n", user);
          return true;
        }

        ++attempts;
        if (hasMac) recordAuthFailure(mac);

        if (attempts >= kMaxAuthAttempts) {
          ssh_message_reply_default(msg);
          ssh_message_free(msg);
          Serial.println("[SSH] Max auth attempts reached; disconnecting.");
          return false;
        }

        delay(500);
        ssh_message_auth_set_methods(msg, SSH_AUTH_METHOD_PASSWORD);
        ssh_message_reply_default(msg);
      } else {
        ssh_message_reply_default(msg);
      }

      ssh_message_free(msg);
    }
  }

  ssh_channel acceptInteractiveChannel(ssh_session session) {
    ssh_channel channel = nullptr;
    bool shellAccepted = false;

    while (!shellAccepted) {
      ssh_message msg = ssh_message_get(session);
      if (msg == nullptr) {
        break;
      }

      const int type = ssh_message_type(msg);
      const int subtype = ssh_message_subtype(msg);

      if (type == SSH_REQUEST_CHANNEL_OPEN && subtype == SSH_CHANNEL_SESSION) {
        channel = ssh_message_channel_request_open_reply_accept(msg);
      } else if (type == SSH_REQUEST_CHANNEL && channel != nullptr) {
        if (subtype == SSH_CHANNEL_REQUEST_PTY || subtype == SSH_CHANNEL_REQUEST_SHELL) {
          ssh_message_channel_request_reply_success(msg);
          if (subtype == SSH_CHANNEL_REQUEST_SHELL) {
            shellAccepted = true;
          }
        } else {
          ssh_message_reply_default(msg);
        }
      } else {
        ssh_message_reply_default(msg);
      }

      ssh_message_free(msg);
    }

    return shellAccepted ? channel : nullptr;
  }

  void sendBanner(ssh_channel channel) {
    String banner;
    banner += "SSHWK ";
    banner += kFirmwareVersion;
    banner += "\r\n";
    banner += "SSHWK ready on ";
    banner += WiFi.localIP().toString();
    banner += "\r\n";
    banner += "Every byte from this SSH session is translated to USB HID keyboard events.\r\n";
    banner += "RGB LED: white=portal, blue=connected, yellow=weak Wi-Fi.\r\n";
    banner += "Layout: ";
    banner += sink_.layoutName();
    banner += "\r\n";
    banner += sink_.statusText();
    banner += "Press Ctrl+";
    banner += config_.ctrlLayoutKey;
    banner += " to toggle keyboard layout (US / ES-MX-LATAM).\r\n";
    banner += "Press Ctrl+";
    banner += config_.ctrlDiscKey;
    banner += " to close the session.\r\n\r\n";
    ssh_channel_write(channel, banner.c_str(), banner.length());
  }

  void pumpChannel(ssh_channel channel) {
    uint8_t buffer[kSshBufferSize];

    while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
      gStatusLed.tick();
      pollFactoryReset(store_);

      if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[SSH] WiFi lost during session; closing channel.");
        break;
      }

      const int available = ssh_channel_poll(channel, 0);
      if (available == SSH_ERROR) {
        break;
      }

      if (available <= 0) {
        delay(10);
        continue;
      }

      const int readBytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
      if (readBytes <= 0) {
        delay(10);
        continue;
      }

      for (int i = 0; i < readBytes; ++i) {
        const uint8_t byte = buffer[i];
        if (byte == config_.ctrlLayoutByte()) {
          const char *layoutMsgPrefix = "\r\n[layout] switched to ";
          const char *layoutMsgSuffix = "\r\n";
          sink_.toggleLayout();
          ssh_channel_write(channel, layoutMsgPrefix, strlen(layoutMsgPrefix));
          ssh_channel_write(channel, sink_.layoutName(), strlen(sink_.layoutName()));
          ssh_channel_write(channel, layoutMsgSuffix, strlen(layoutMsgSuffix));
          continue;
        }
        if (byte == config_.ctrlDiscByte()) {
          return;
        }

        sink_.sendByte(byte);
        if (const char *label = sink_.takeEchoLabel()) {
          ssh_channel_write(channel, label, strlen(label));
          continue;
        }
        if (sink_.ansiSequencePending()) {
          continue;
        }

        // Echo only what won't corrupt the terminal display.
        // Escape sequences (arrows, F-keys, …) must NOT be echoed raw because
        // the SSH client's terminal emulator would act on them (e.g. move the
        // cursor) instead of just showing them.
        if (byte >= 0x20 && byte < 0x7F) {
          ssh_channel_write(channel, &byte, 1);
        } else if (byte == '\r') {
          const char *crlf = "\r\n";
          ssh_channel_write(channel, crlf, 2);
        } else if (byte == 0x08 || byte == 0x7F) {
          const char *bsp = "\b \b";
          ssh_channel_write(channel, bsp, 3);
        }
        // Control codes and ESC sequences: no echo.
      }
    }
  }

  // Loads the Ed25519 host key from NVS. Generates and persists a new one if
  // absent or corrupt. This keeps the host fingerprint stable across reboots so
  // SSH clients don't get a host-key-mismatch warning every time.
  bool loadOrGenerateHostKey() {
    Preferences prefs;
    if (prefs.begin(kPreferencesNamespace, true)) {
      const String b64 = prefs.getString("host_key", "");
      prefs.end();
      if (!b64.isEmpty()) {
        if (ssh_pki_import_privkey_base64(b64.c_str(), nullptr, nullptr, nullptr, &hostKey_) == SSH_OK &&
            hostKey_ != nullptr) {
          Serial.println("[SSH] Host key loaded from NVS.");
          return true;
        }
        Serial.println("[SSH] Stored host key invalid; regenerating.");
      }
    }

    if (ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &hostKey_) != SSH_OK || hostKey_ == nullptr) {
      return false;
    }

    char *b64 = nullptr;
    if (ssh_pki_export_privkey_base64(hostKey_, nullptr, nullptr, nullptr, &b64) == SSH_OK && b64) {
      Preferences prefs;
      if (prefs.begin(kPreferencesNamespace, false)) {
        prefs.putString("host_key", b64);
        prefs.end();
        Serial.println("[SSH] New host key generated and saved to NVS.");
      }
      free(b64);
    }
    return true;
  }

  void cleanup() {
    if (bind_ != nullptr) {
      ssh_bind_free(bind_);
      bind_ = nullptr;
    }
    if (hostKey_ != nullptr) {
      ssh_key_free(hostKey_);
      hostKey_ = nullptr;
    }
  }

  const AppConfig &config_;
  KeyboardSink &sink_;
  ConfigStore &store_;
  ssh_bind bind_ = nullptr;
  ssh_key hostKey_ = nullptr;
  int sshPort_ = kSshPort;
};

bool connectToConfiguredWifi(const AppConfig &config) {
  WiFi.persistent(false);
  WiFi.setSleep(false);
  WiFi.mode(WIFI_STA);
  WiFi.begin(config.wifiSsid.c_str(), config.wifiPassword.c_str());

  Serial.printf("[WIFI] Connecting to '%s'\n", config.wifiSsid.c_str());
  gStatusLed.setMode(StatusLed::Mode::Connecting);

  const uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < kWifiConnectTimeoutMs) {
    gStatusLed.tick();
    delay(100);
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WIFI] Connection failed.");
    gStatusLed.setMode(StatusLed::Mode::Error);
    return false;
  }

  Serial.printf("[WIFI] Connected. DHCP IP: %s RSSI: %d dBm\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
  gStatusLed.setMode(WiFi.RSSI() <= kLowSignalThresholdDbm ? StatusLed::Mode::ConnectedWeak
                                                           : StatusLed::Mode::ConnectedGood);
  return true;
}

}  // namespace

void setup() {
  pinMode(kFactoryResetPin, INPUT_PULLUP);

  // HID must be registered before the USB host finishes enumerating the device.
  // On ESP32-S3 native USB the host sees VBUS immediately after reset; any call
  // to Serial.begin() (which triggers USB.begin() internally) before this point
  // would lock the descriptor as CDC-only and Windows would never see a keyboard.
  gKeyboardSink.begin();

  // With ARDUINO_USB_CDC_ON_BOOT=0, Serial maps to hardware UART0
  // (GPIO43 TX / GPIO44 RX) instead of USB CDC — USB is HID-only.
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("SSHWK booting on ESP32-S3...");
  Serial.println("[HID] USB HID keyboard started.");
  Serial.printf("[RESET] Factory reset button configured on GPIO%u, idle=%u\n",
                kFactoryResetPin, digitalRead(kFactoryResetPin));

  gStatusLed.begin();

  AppConfig config;
  ConfigStore store;
  WiFi.persistent(false);
  WiFi.setSleep(false);

  if (!store.load(config)) {
    Serial.println("[BOOT] No saved configuration. Entering provisioning mode.");
    ProvisioningPortal portal(store);
    portal.run();
  }

  if (!connectToConfiguredWifi(config)) {
    Serial.println("[BOOT] Saved Wi-Fi credentials failed. Clearing configuration and returning to portal.");
    store.clear();
    delay(250);
    ProvisioningPortal portal(store);
    portal.run();
  }

  SshKeyboardServer server(config, gKeyboardSink, store);
  if (!server.begin()) {
    Serial.println("[BOOT] SSH server failed to start. Restarting in 5 seconds.");
    gStatusLed.setMode(StatusLed::Mode::Error);
    delay(5000);
    ESP.restart();
  }

  server.runForever();
}

void loop() {
  delay(1000);
}
