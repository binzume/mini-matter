#include <stdint.h>
#define MATTER_BLE_SERVICE_UUID 0xfff6
#define MATTER_BLE_TX_UUID "18EE2EF5-263D-4559-959F-4F9C429F9D11"
#define MATTER_BLE_RX_UUID "18EE2EF5-263D-4559-959F-4F9C429F9D12"
#define MATTER_BLE_ADDITIONAL_UUID "64630238-8772-45F2-B87D-748A83218F04"

struct MatterSession *pase_init();
// void pase_free(struct PaseContext *);

int handle_btp_packet(struct MatterSession *ctx, const uint8_t *req, int reqsize);
uint16_t check_btp_packet_send(MatterSession *ctx, uint8_t **data);
