#include <Arduino.h>
#include <NimBLEDevice.h>

#include "matter.h"
#include "matter_ble_server.h"

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
    debug_dump("Sending notification to clients");
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
    debug_dump(str.c_str());
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
    debug_dump(str.c_str());
  };
};

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

void wait_for_commissioning_complete() {
  NimBLEDevice::init("ESP32");

  // Create the BLE Server
  NimBLEServer* pServer = NimBLEDevice::createServer();
  pServer->advertiseOnDisconnect(true);

  // Create the BLE Service
  NimBLEService* pService = pServer->createService(SERVICE_UUID);

  // Create BLE Characteristics
  CharacteristicCallbacks chrCallbacks;
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

  bool connected = false;
  while (!connected) {
    if (ready && pase != nullptr) {
      uint8_t* data;
      uint16_t size = next_btp_packet_to_send(pase, &data);
      if (size > 0) {
        pRXCharacteristic->setValue(data, size);
        pRXCharacteristic->notify();
        debug_printf("SEND RESPONSE (%d bytes)", size);
      }
      if (get_network_state(pase) == MATTER_NETWORK_CONNECTED) {
        break;
      }
    }
    delay(1);
  }
  delay(500);
  NimBLEDevice::deinit(true);
}
