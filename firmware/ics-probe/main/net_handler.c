// net_handler.c — W5500 Ethernet controller handler
// Exposes TCP/UDP socket operations over the probe's SPI Ethernet NIC.

#include <string.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_eth.h"
#include "esp_eth_mac.h"
#include "esp_eth_phy.h"
#include "esp_eth_netif_glue.h"
#include "esp_netif.h"
#include "esp_netif_defaults.h"
#include "esp_event.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/dhcp.h"
#include "cJSON.h"

#include "config.h"
#include "handlers.h"

static const char* TAG = "net_handler";
static bool s_initialized = false;

static esp_netif_t* s_eth_netif = NULL;
static esp_eth_handle_t s_eth_handle = NULL;

void net_init(void)
{
    ESP_LOGI(TAG, "initializing W5500 Ethernet");

    // SPI3 already used by MCP2515 — reuse the bus. spi_bus_initialize will
    // return ESP_ERR_INVALID_STATE if already initialized, which we treat as
    // success (matches the graceful detection pattern used elsewhere).
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = CAN_SPI_MOSI,
        .miso_io_num = CAN_SPI_MISO,
        .sclk_io_num = CAN_SPI_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    esp_err_t err = spi_bus_initialize(SPI3_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "SPI bus init failed: %s — net disabled", esp_err_to_name(err));
        s_initialized = false;
        return;
    }

    spi_device_interface_config_t devcfg = {
        .mode = 0,
        .clock_speed_hz = W5500_SPI_MHZ * 1000 * 1000,
        .spics_io_num = W5500_CS_PIN,
        .queue_size = 20,
    };

    eth_w5500_config_t w5500_cfg = ETH_W5500_DEFAULT_CONFIG(SPI3_HOST, &devcfg);
    w5500_cfg.int_gpio_num = W5500_INT_PIN;

    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.phy_addr = W5500_PHY_ADDR;
    phy_cfg.reset_gpio_num = W5500_RST_PIN;

    esp_eth_mac_t* mac = esp_eth_mac_new_w5500(&w5500_cfg, &mac_cfg);
    esp_eth_phy_t* phy = esp_eth_phy_new_w5500(&phy_cfg);
    if (!mac || !phy) {
        ESP_LOGW(TAG, "W5500 MAC/PHY alloc failed — net disabled");
        s_initialized = false;
        return;
    }

    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    if (esp_eth_driver_install(&eth_cfg, &s_eth_handle) != ESP_OK) {
        ESP_LOGW(TAG, "esp_eth_driver_install failed — W5500 absent?");
        s_initialized = false;
        return;
    }

    // Assign a locally-administered MAC address (W5500 has no built-in).
    uint8_t mac_addr[6] = { 0x02, 0x00, 0x00, 0x12, 0x34, 0x56 };
    esp_err_t mac_err = esp_eth_ioctl(s_eth_handle, ETH_CMD_S_MAC_ADDR, mac_addr);
    if (mac_err != ESP_OK) {
        ESP_LOGW(TAG, "ETH_CMD_S_MAC_ADDR failed: %s", esp_err_to_name(mac_err));
    }

    // Initialize TCP/IP stack (safe to call multiple times).
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    s_eth_netif = esp_netif_new(&netif_cfg);
    if (!s_eth_netif) {
        ESP_LOGW(TAG, "esp_netif_new failed — net disabled");
        s_initialized = false;
        return;
    }
    esp_netif_attach(s_eth_netif, esp_eth_new_netif_glue(s_eth_handle));

    if (esp_eth_start(s_eth_handle) != ESP_OK) {
        ESP_LOGW(TAG, "esp_eth_start failed — net disabled");
        s_initialized = false;
        return;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "W5500 Ethernet ready");
}

bool net_is_ready(void)
{
    return s_initialized;
}

// ─── Command implementations ────────────────────────────────────────────────

static cJSON* cmd_status(void)
{
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    if (!s_initialized) {
        cJSON_AddBoolToObject(resp, "link", false);
        cJSON_AddStringToObject(resp, "error", "not_initialized");
        return resp;
    }
    esp_netif_ip_info_t ip;
    if (esp_netif_get_ip_info(s_eth_netif, &ip) == ESP_OK) {
        char buf[32];
        snprintf(buf, sizeof(buf), IPSTR, IP2STR(&ip.ip));
        cJSON_AddStringToObject(resp, "ip", buf);
        snprintf(buf, sizeof(buf), IPSTR, IP2STR(&ip.netmask));
        cJSON_AddStringToObject(resp, "netmask", buf);
        snprintf(buf, sizeof(buf), IPSTR, IP2STR(&ip.gw));
        cJSON_AddStringToObject(resp, "gw", buf);
    }
    // ESP-IDF v5.1.2 does not expose a PHY link-status ioctl command in
    // esp_eth_io_cmd_t. Report netif up/down as a proxy for link state —
    // esp_netif flips the flag via the ETH_EVENT_CONNECTED/DISCONNECTED
    // events that esp_eth drives internally.
    bool link_up = esp_netif_is_netif_up(s_eth_netif);
    cJSON_AddBoolToObject(resp, "link", link_up);
    return resp;
}

static cJSON* cmd_dhcp(cJSON* params)
{
    cJSON* resp = cJSON_CreateObject();
    if (!s_initialized) {
        cJSON_AddStringToObject(resp, "status", "error");
        cJSON_AddStringToObject(resp, "error", "not_initialized");
        return resp;
    }
    int timeout_s = 10;
    cJSON* t = cJSON_GetObjectItemCaseSensitive(params, "timeout_s");
    if (t && cJSON_IsNumber(t)) timeout_s = t->valueint;

    esp_netif_dhcpc_stop(s_eth_netif);
    esp_netif_dhcpc_start(s_eth_netif);

    // Poll for IP assignment
    for (int i = 0; i < timeout_s * 10; i++) {
        esp_netif_ip_info_t ip;
        if (esp_netif_get_ip_info(s_eth_netif, &ip) == ESP_OK && ip.ip.addr != 0) {
            cJSON_AddStringToObject(resp, "status", "ok");
            char buf[32];
            snprintf(buf, sizeof(buf), IPSTR, IP2STR(&ip.ip));
            cJSON_AddStringToObject(resp, "ip", buf);
            return resp;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    cJSON_AddStringToObject(resp, "status", "error");
    cJSON_AddStringToObject(resp, "error", "dhcp_timeout");
    return resp;
}

cJSON* net_handle_command(const char* action, cJSON* params)
{
    if (!action) {
        cJSON* r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "status", "error");
        cJSON_AddStringToObject(r, "error", "missing_action");
        return r;
    }
    if (strcmp(action, "selftest") == 0 || strcmp(action, "status") == 0) {
        return cmd_status();
    }
    if (strcmp(action, "dhcp") == 0) return cmd_dhcp(params);

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "error");
    cJSON_AddStringToObject(r, "error", "unknown_action");
    return r;
}
