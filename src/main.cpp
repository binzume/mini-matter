#include <Arduino.h>

#define LOG Serial


void dump(const char* msg, const uint8_t* buf, int len) {
  if (msg) {
      Serial.print(msg);
      Serial.print(": ");
  }
  for (int i = 0; i < len; i++) {
    if (buf[i] < 0x10) {
      Serial.print("0");
    }
    Serial.print(buf[i], HEX);
    if (i != len - 1) {
      Serial.print(",");
    }
  }
  Serial.println();
}


#include <NimBLEDevice.h>

#include "matter_pase.h"

static const NimBLEUUID SERVICE_UUID((uint16_t)0xfff6);
static const NimBLEUUID TX_UUID("18EE2EF5-263D-4559-959F-4F9C429F9D11");
static const NimBLEUUID RX_UUID("18EE2EF5-263D-4559-959F-4F9C429F9D12");
// static const NimBLEUUID
// ADDITIONAL_UUID("64630238-8772-45F2-B87D-748A83218F04");

static NimBLEAdvertising* pAdvertising = nullptr;
static NimBLECharacteristic* pTXCharacteristic = nullptr;
static NimBLECharacteristic* pRXCharacteristic = nullptr;

int state = 0;
uint8_t sendbuf[256];
uint8_t sendsize = 0;
PaseContext* pase;

class CharacteristicCallbacks : public NimBLECharacteristicCallbacks {
  void onRead(NimBLECharacteristic* pCharacteristic) {
    Serial.print(pCharacteristic->getUUID().toString().c_str());
    Serial.print(": onRead(), value: ");
    Serial.println(pCharacteristic->getValue().length());
  };

  void onWrite(NimBLECharacteristic* pCharacteristic) {
    if (pCharacteristic == pTXCharacteristic) {
      Serial.print("RECV:[");
      auto v = pCharacteristic->getValue();
      for (auto c : v) {
        Serial.print(",");
        Serial.print(c, HEX);
      }
      Serial.println("]");

      if (state == 0) {
        pase = new PaseContext();  // todo delete
        sendsize = make_handshake_res(pase, v.data(), v.size(), sendbuf);
      } else if (state == 2) {
        sendsize = make_pbdkres(pase, v.data(), v.size(), sendbuf);
      } else if (state == 4) {
        sendsize = make_pake2(pase, v.data(), v.size(), sendbuf);
      }
      state++;
    } else {
      Serial.print(pCharacteristic->getUUID().toString().c_str());
      Serial.print(": onWrite(), value: ");
      Serial.println(pCharacteristic->getValue().length());
    }
  };
  /** Called before notification or indication is sent,
   *  the value can be changed here before sending if desired.
   */
  void onNotify(NimBLECharacteristic* pCharacteristic) {
    Serial.println("Sending notification to clients");
  };

  /** The status returned in status is defined in NimBLECharacteristic.h.
   *  The value returned in code is the NimBLE host return code.
   */
  void onStatus(NimBLECharacteristic* pCharacteristic, Status status,
                int code) {
    String str = ("Notification/Indication status code: ");
    str += status;
    str += ", return code: ";
    str += code;
    str += ", ";
    str += NimBLEUtils::returnCodeToString(code);
    Serial.println(str);
  };

  void onSubscribe(NimBLECharacteristic* pCharacteristic,
                   ble_gap_conn_desc* desc, uint16_t subValue) {
    String str = "Client ID: ";
    str += desc->conn_handle;
    str += " Address: ";
    str += std::string(NimBLEAddress(desc->peer_ota_addr)).c_str();
    if (subValue == 0) {
      str += " Unsubscribed to ";
    } else if (subValue == 1) {
      str += " Subscribed to notfications for ";
    } else if (subValue == 2) {
      str += " Subscribed to indications for ";
    } else if (subValue == 3) {
      str += " Subscribed to notifications and indications for ";
    }
    str += std::string(pCharacteristic->getUUID()).c_str();

    Serial.println(str);
  };
};

static CharacteristicCallbacks chrCallbacks;

#define BLE_ADVERTISEMENT_VERSION 0
#define DEVICE_DISCRIMINATOR 3840
#define BLE_VENDOR_ID 0xFFF1
#define BLE_PRODUCT_ID 0x8001

void startAdv() {
  NimBLEAdvertisementData data;
  data.setFlags(0x06);
  uint8_t buf[8] = {
      0x00,
      DEVICE_DISCRIMINATOR & 0xff,
      (DEVICE_DISCRIMINATOR >> 8) | (BLE_ADVERTISEMENT_VERSION << 4),
      BLE_VENDOR_ID & 0xff,
      BLE_VENDOR_ID >> 8,
      BLE_PRODUCT_ID & 0xff,
      BLE_PRODUCT_ID >> 8,
      0};
  data.setServiceData(SERVICE_UUID, std::string((char*)buf, sizeof(buf)));
  pAdvertising->stop();
  pAdvertising->setAdvertisementData(data);
  pAdvertising->start();
}

void setup() {
  LOG.begin(115200);
  LOG.println("Starting BLE work!");

  NimBLEDevice::init("ESP32");

  // Create the BLE Server
  NimBLEServer* pServer = NimBLEDevice::createServer();
  // pServer->setCallbacks(new MyServerCallbacks());
  pServer->advertiseOnDisconnect(true);

  // Create the BLE Service
  NimBLEService* pService = pServer->createService(SERVICE_UUID);

  // Create a BLE Characteristic
  pTXCharacteristic =
      pService->createCharacteristic(TX_UUID, NIMBLE_PROPERTY::WRITE);
  pTXCharacteristic->setCallbacks(&chrCallbacks);
  pRXCharacteristic = pService->createCharacteristic(
      RX_UUID, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  pRXCharacteristic->setCallbacks(&chrCallbacks);

  // Start the service
  pService->start();

  pAdvertising = NimBLEDevice::getAdvertising();
  startAdv();
}

void loop() {
  if (sendsize > 0) {
    delay(50);
    // BTP Handshake Response
    pRXCharacteristic->setValue(sendbuf, sendsize);
    pRXCharacteristic->notify();
    state++;
    sendsize = 0;
    LOG.println("SEND RESPONSE");
  }
  delay(1);
}
