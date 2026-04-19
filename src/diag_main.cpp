#include <Arduino.h>
#include <WiFi.h>

namespace {

constexpr const char *kDiagSsid = "SSHWK-DIAG";
const IPAddress kDiagIp(10, 10, 10, 1);
const IPAddress kDiagGateway(10, 10, 10, 1);
const IPAddress kDiagSubnet(255, 255, 255, 0);

void setLed(uint8_t r, uint8_t g, uint8_t b) {
  neopixelWrite(RGB_BUILTIN, r, g, b);
}

}

void setup() {
  delay(500);
  setLed(24, 24, 24);
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(kDiagIp, kDiagGateway, kDiagSubnet);
  WiFi.softAP(kDiagSsid);
}

void loop() {
  static uint32_t lastToggle = 0;
  static bool on = true;
  if (millis() - lastToggle > 500) {
    lastToggle = millis();
    on = !on;
    setLed(on ? 24 : 0, on ? 24 : 0, on ? 24 : 0);
  }
  delay(100);
}
