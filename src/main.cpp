#include <Arduino.h>
#include <NimBLEDevice.h>

#include "matter.h"
#include "matter_config.h"
#include "matter_utils.h"

#define LOG Serial

static const NimBLEUUID SERVICE_UUID((uint16_t)MATTER_BLE_SERVICE_UUID);
static const NimBLEUUID TX_UUID(MATTER_BLE_TX_UUID);
static const NimBLEUUID RX_UUID(MATTER_BLE_RX_UUID);

static NimBLEAdvertising* pAdvertising = nullptr;
static NimBLECharacteristic* pTXCharacteristic = nullptr;
static NimBLECharacteristic* pRXCharacteristic = nullptr;

MatterSession* pase = nullptr;
bool ready = false;

class CharacteristicCallbacks : public NimBLECharacteristicCallbacks {
  void onRead(NimBLECharacteristic* pCharacteristic) {
    LOG.print(pCharacteristic->getUUID().toString().c_str());
    LOG.print(": onRead(), value: ");
    LOG.println(pCharacteristic->getValue().length());
  };

  void onWrite(NimBLECharacteristic* pCharacteristic) {
    if (pCharacteristic == pTXCharacteristic) {
      auto v = pCharacteristic->getValue();
      if (pase == nullptr) {
        pase = pase_init();  // todo delete
        ready = false;
      }
      handle_btp_packet(pase, v.data(), v.size());
    } else {
      LOG.print(pCharacteristic->getUUID().toString().c_str());
      LOG.print(": onWrite(), value: ");
      LOG.println(pCharacteristic->getValue().length());
    }
  };
  /** Called before notification or indication is sent,
   *  the value can be changed here before sending if desired.
   */
  void onNotify(NimBLECharacteristic* pCharacteristic) {
    LOG.println("Sending notification to clients");
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
    LOG.println(str);
  };

  void onSubscribe(NimBLECharacteristic* pCharacteristic,
                   ble_gap_conn_desc* desc, uint16_t subValue) {
    String str = "Client ID: ";
    str += desc->conn_handle;
    str += " Address: ";
    str += std::string(NimBLEAddress(desc->peer_ota_addr)).c_str();
    if (subValue == 0) {
      str += " Unsubscribed to ";
      ready = false;
    } else if (subValue == 1) {
      str += " Subscribed to notfications for ";
      ready = true;
    } else if (subValue == 2) {
      str += " Subscribed to indications for ";
    } else if (subValue == 3) {
      str += " Subscribed to notifications and indications for ";
      ready = true;
    }
    str += std::string(pCharacteristic->getUUID()).c_str();
    LOG.println(str);
  };
};

static CharacteristicCallbacks chrCallbacks;

#define BLE_ADVERTISEMENT_VERSION 0

void startAdv() {
  NimBLEAdvertisementData data;
  data.setFlags(0x06);
  uint8_t buf[8] = {
      0x00,
      DEVICE_DISCRIMINATOR & 0xff,
      (DEVICE_DISCRIMINATOR >> 8) | (BLE_ADVERTISEMENT_VERSION << 4),
      MATTER_VENDOR_ID & 0xff,
      MATTER_VENDOR_ID >> 8,
      MATTER_PRODUCT_ID & 0xff,
      MATTER_PRODUCT_ID >> 8,
      0};
  data.setServiceData(SERVICE_UUID, std::string((char*)buf, sizeof(buf)));
  pAdvertising->stop();
  pAdvertising->setAdvertisementData(data);
  pAdvertising->start();
}

void setup() {
  LOG.begin(115200);
  LOG.println("Starting Matter PASE");

  NimBLEDevice::init("ESP32");

  // Create the BLE Server
  NimBLEServer* pServer = NimBLEDevice::createServer();
  pServer->advertiseOnDisconnect(true);

  // Create the BLE Service
  NimBLEService* pService = pServer->createService(SERVICE_UUID);

  // Create BLE Characteristics
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

  char qr[32];
  get_qr_code_string(qr, MATTER_VENDOR_ID, MATTER_PRODUCT_ID, DEVICE_DISCRIMINATOR,
                     MATTER_PASSCODE);
  LOG.print("QR: https://chart.apis.google.com/chart?chs=200x200&cht=qr&chl=");
  LOG.println(qr);
}

void loop() {
  if (ready && pase != nullptr) {
    uint8_t* data;
    uint16_t size = check_btp_packet_send(pase, &data);
    if (size > 0) {
      pRXCharacteristic->setValue(data, size);
      pRXCharacteristic->notify();
      LOG.print("SEND RESPONSE ");
      LOG.print(size);
      LOG.println(" bytes");
    }
  }
  delay(1);
}
