/*
 * ESP32 BLE Calibration Beacon
 * ---------------------------------
 * Copyright (c) 2026, Vincent Demanet
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved
 * by the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 *     https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * Purpose: a movable reference transmitter so that 3 uncalibrated
 * Raspberry Pi sniffers can derive per-Pi RSSI calibration maps.
 *
 * Features:
 *  - iBeacon-format advertisement (easy to parse on the Pi with bluez/hcitool/nhc.)
 *  - 2 push buttons (active-LOW, internal pullups):
 *      BTN_POWER : cycles TX power  [-12, 0, +4, +8 dBm]  (chip max depends on module)
 *      BTN_POINT : cycles measurement point ID 0..7
 *  - The beacon UUID embeds the point ID and the calibrated TX power,
 *    so the Pi can read "who / at what power" from the packet itself.
 *  - Eddystone-UID is not used, but the same idea applies if you prefer it.
 *
 * WiFi coexistence: the ESP32 (classic, single antenna) shares the 2.4 GHz
 * radio between WiFi and BT. Coexistence works but with time-slicing.
 * Recommended setup: BLE advertises continuously (non-connectable),
 * and WiFi is only switched on when you need to report status (e.g. the
 * current point/power over MQTT/HTTP). In Arduino:
 *      WiFi.begin(...) works alongside BLE, but expect slightly
 *      higher advertising jitter. For best RSSI stability, keep WiFi off
 *      during measurements and only use it between campaigns.
 *
 * Note: newer ESP32-C3/S3 with NimBLE behave the same way (shared radio).
 *
 * Board: ESP32 Dev Module (Arduino core 2.x/3.x)
 * Libraries: ESP32 built-in BLE (Bluetooth.h / BLEDevice.h)
 */

#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEBeacon.h>
#include <esp_bt.h>

// ---------- Pins ----------
constexpr int BTN_POWER = 4;   // cycle TX power
constexpr int BTN_POINT = 5;   // cycle measurement point
constexpr int LED_PIN   = 2;

// ---------- Beacon identity ----------
// Base UUID: keep it fixed, byte 13 (index 13, the "minor-major" area) is
// repurposed: we store POINT_ID in the Major field and TX_POWER dBm in Minor.
// Actually cleaner: Major = pointId, Minor = txPower (in dBm, signed offset from 128).
// iBeacon Major/Minor are the last 4 bytes of the 30-byte adv payload.
constexpr uint16_t BEACON_MAJOR_FIXED = 0xB1B0; // sanity tag: identifies "calibration beacon"

// ---------- TX power steps (dBm, as requested from the radio) ----------
constexpr esp_power_level_t POWER_STEPS[] = {
  ESP_PWR_LVL_N12,  // -12 dBm
  ESP_PWR_LVL_N0,   //   0 dBm
  ESP_PWR_LVL_P4,   //  +4 dBm
  ESP_PWR_LVL_P9    //  +8 dBm  (check your module PA limit; some cap at +4/+9)
};
constexpr int POWER_DBM[] = { -12, 0, 4, 8 };
constexpr int NUM_POWER_STEPS = 4;
constexpr int NUM_POINTS = 8;   // 8 measurement points max

// ---------- State ----------
static int powerIdx = 1;   // start at 0 dBm
static int pointId  = 0;
static BLEAdvertising *advertising;

// ---------- Button helpers (debounced edge detect) ----------
static bool btnPressed(int pin) {
  static uint32_t lastEdge[40] = {0};
  static int lastState[40];
  int st = digitalRead(pin);
  if (st != lastState[pin] && millis() - lastEdge[pin] > 200) {
    lastEdge[pin] = millis();
    lastState[pin] = st;
    return (st == LOW);            // pressed = falling edge
  }
  lastState[pin] = st;
  return false;
}

// ---------- Build & advertise beacon ----------
static void updateAdvertisement() {
  BLEAdvertisementData adv;
  adv.setFlags(ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT);

  // ---- iBeacon manufacturer data (Apple 0x004C) ----
  uint8_t mfg[25] = {0};
  mfg[0] = 0x4C; mfg[1] = 0x00;      // Apple company ID
  mfg[2] = 0x02;                     // iBeacon type
  mfg[3] = 0x15;                     // length
  // UUID (16 bytes): fixed "lab" UUID, bytes 0-1 encode device class
  const uint8_t uuid[16] = {
    0xCA, 0x1B, 0x3A, 0x11, 0xB0, 0x0B, 0x40, 0xD3,
    0x8E, 0x33, 0x9A, 0xC0, 0x00, 0x00, 0x00, 0x00
  };
  memcpy(&mfg[4], uuid, 16);
  mfg[20] = BEACON_MAJOR_FIXED >> 8;          // Major hi  : tag
  mfg[21] = BEACON_MAJOR_FIXED & 0xFF;        // Major lo
  mfg[22] = (uint8_t)pointId;                // Minor hi  : measurement point ID
  // Minor lo : *calibrated measured TX power at 1 m* — this is what a
  // receiver should use for path-loss math, not a datasheet number.
  // Calibrate once per power level with a reference receiver (see README notes)
  // and store here. Placeholder: assumed EIRP = requested dBm - 0 dB antenna.
  mfg[23] = (uint8_t)(128 + POWER_DBM[powerIdx]);  // offset-coded (0 = -128)
  mfg[24] = (uint8_t)(128 + POWER_DBM[powerIdx]);  // iBeacon field: TX at 1 m

  // ESP32 Arduino core 3.x BLE API takes Arduino String.
  // String(char*, length) preserves embedded 0x00 bytes.
  adv.setManufacturerData(String((char*)mfg, 25));
  advertising->setAdvertisementData(adv);

  // ---- Apply requested TX power ----
  // Default BLE power is per-connection; use the advertising handle for adv packets.
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, POWER_STEPS[powerIdx]);

  // Also set the default power type as a safety net for some core versions:
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, POWER_STEPS[powerIdx]);

  digitalWrite(LED_PIN, !digitalRead(LED_PIN));  // visual feedback

  Serial.printf("[BEACON] point=%d txPower=%d dBm\n", pointId, POWER_DBM[powerIdx]);
}

void setup() {
  Serial.begin(115200);

  pinMode(BTN_POWER, INPUT_PULLUP);
  pinMode(BTN_POINT, INPUT_PULLUP);
  pinMode(LED_PIN, OUTPUT);

  BLEDevice::init("calib-beacon");
  BLEDevice::setPower(POWER_STEPS[powerIdx]); // sets ESP_PWR_TYPE_DEFAULT in some cores

  // Non-connectable advertiser: pure beacon, no connection, no pairing.
  BLEServer *server = BLEDevice::createServer(); // needed to init adv engine
  advertising = server->getAdvertising();
  advertising->setAdvertisementType(ADV_TYPE_NONCONN_IND);

  updateAdvertisement();
  advertising->start();
  Serial.print("BLE MAC: ");
  Serial.println(BLEDevice::getAddress().toString().c_str());
  Serial.println("Calibration beacon running. BTN_POWER=change power, BTN_POINT=change point.");
}

void loop() {
  if (btnPressed(BTN_POWER)) {
    powerIdx = (powerIdx + 1) % NUM_POWER_STEPS;
    updateAdvertisement();
  }
  if (btnPressed(BTN_POINT)) {
    pointId = (pointId + 1) % NUM_POINTS;
    updateAdvertisement();
  }
  delay(10);
}

/* =====================================================================
 * OPTIONAL: WiFi status channel (ESP32 can run WiFi + BLE concurrently,
 * time-shared on the same radio). Enable only between measurement runs
 * to keep RSSI clean during calibration.
 *
 *   #include <WiFi.h>
 *   #include <PubSubClient.h>   // MQTT, or just use HTTPClient
 *   void startWifi() {
 *     WiFi.begin("ssid", "pass");
 *     while (WiFi.status() != WL_CONNECTED) delay(100);
 *     // publish JSON: {"point": pointId, "tx": POWER_DBM[powerIdx], "uptime":...}
 *   }
 *   void stopWifi() { WiFi.disconnect(true); WiFi.mode(WIFI_OFF); }
 *
 * Better still: let the ESP32 *receive* commands over WiFi (simple HTTP
 * or ESP-NOW) to change point/power remotely instead of buttons:
 *   - buttons still useful as fallback when moving the device around.
 * ===================================================================== */