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

// ─── Socket table ───────────────────────────────────────────────────────────

#define NET_MAX_SOCKS 4
static struct { int fd; bool in_use; } s_socks[NET_MAX_SOCKS];

// ─── Hex codec helpers ──────────────────────────────────────────────────────

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

// Decodes `hex` into `out`, returning number of bytes written, or -1 on
// malformed input. `out_cap` is the max bytes writeable.
static int hex_decode(const char* hex, uint8_t* out, size_t out_cap)
{
    if (!hex) return -1;
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;
    size_t nbytes = len / 2;
    if (nbytes > out_cap) return -1;
    for (size_t i = 0; i < nbytes; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)nbytes;
}

// Encodes `in`/`n` bytes into `out` as lowercase hex. `out` must have
// capacity of at least 2*n + 1 bytes.
static void hex_encode(const uint8_t* in, size_t n, char* out)
{
    static const char tbl[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = tbl[(in[i] >> 4) & 0x0f];
        out[2 * i + 1] = tbl[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

// Allocate a slot in the socket table. Returns index ≥ 0 or -1 if full.
static int sock_alloc(int fd)
{
    for (int i = 0; i < NET_MAX_SOCKS; i++) {
        if (!s_socks[i].in_use) {
            s_socks[i].fd = fd;
            s_socks[i].in_use = true;
            return i;
        }
    }
    return -1;
}

static cJSON* err_resp(const char* code)
{
    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "error");
    cJSON_AddStringToObject(r, "error", code);
    return r;
}

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

static cJSON* cmd_static(cJSON* params)
{
    cJSON* resp = cJSON_CreateObject();
    if (!s_initialized) {
        cJSON_AddStringToObject(resp, "status", "error");
        cJSON_AddStringToObject(resp, "error", "not_initialized");
        return resp;
    }
    cJSON* ip_j   = cJSON_GetObjectItemCaseSensitive(params, "ip");
    cJSON* mask_j = cJSON_GetObjectItemCaseSensitive(params, "mask");
    cJSON* gw_j   = cJSON_GetObjectItemCaseSensitive(params, "gw");
    if (!cJSON_IsString(ip_j) || !cJSON_IsString(mask_j) || !cJSON_IsString(gw_j)) {
        cJSON_AddStringToObject(resp, "status", "error");
        cJSON_AddStringToObject(resp, "error", "missing_ip_mask_gw");
        return resp;
    }

    esp_netif_ip_info_t info = { 0 };
    if (esp_netif_str_to_ip4(ip_j->valuestring,   &info.ip)      != ESP_OK ||
        esp_netif_str_to_ip4(mask_j->valuestring, &info.netmask) != ESP_OK ||
        esp_netif_str_to_ip4(gw_j->valuestring,   &info.gw)      != ESP_OK) {
        cJSON_AddStringToObject(resp, "status", "error");
        cJSON_AddStringToObject(resp, "error", "invalid_ip_format");
        return resp;
    }

    // Stop DHCP client before assigning static addresses; ignore "already
    // stopped" return since the caller may invoke static twice.
    esp_netif_dhcpc_stop(s_eth_netif);

    esp_err_t err = esp_netif_set_ip_info(s_eth_netif, &info);
    if (err != ESP_OK) {
        cJSON_AddStringToObject(resp, "status", "error");
        cJSON_AddStringToObject(resp, "error", esp_err_to_name(err));
        return resp;
    }

    cJSON_AddStringToObject(resp, "status", "ok");
    cJSON_AddStringToObject(resp, "ip",      ip_j->valuestring);
    cJSON_AddStringToObject(resp, "netmask", mask_j->valuestring);
    cJSON_AddStringToObject(resp, "gw",      gw_j->valuestring);
    return resp;
}

// ─── TCP socket commands ────────────────────────────────────────────────────

static cJSON* cmd_tcp_connect(cJSON* params)
{
    if (!s_initialized) return err_resp("not_initialized");
    cJSON* host_j = cJSON_GetObjectItemCaseSensitive(params, "host");
    cJSON* port_j = cJSON_GetObjectItemCaseSensitive(params, "port");
    if (!cJSON_IsString(host_j) || !cJSON_IsNumber(port_j)) {
        return err_resp("missing_host_or_port");
    }

    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port_j->valueint);

    struct addrinfo* res = NULL;
    if (getaddrinfo(host_j->valuestring, port_str, &hints, &res) != 0 || !res) {
        return err_resp("dns_failed");
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return err_resp("socket_failed");
    }

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return err_resp("connect_failed");
    }
    freeaddrinfo(res);

    int slot = sock_alloc(fd);
    if (slot < 0) {
        close(fd);
        return err_resp("sock_table_full");
    }

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    cJSON_AddNumberToObject(resp, "sock", slot);
    return resp;
}

static cJSON* cmd_tcp_send(cJSON* params)
{
    if (!s_initialized) return err_resp("not_initialized");
    cJSON* sock_j = cJSON_GetObjectItemCaseSensitive(params, "sock");
    cJSON* data_j = cJSON_GetObjectItemCaseSensitive(params, "data");
    if (!cJSON_IsNumber(sock_j) || !cJSON_IsString(data_j)) {
        return err_resp("missing_sock_or_data");
    }
    int slot = sock_j->valueint;
    if (slot < 0 || slot >= NET_MAX_SOCKS) return err_resp("invalid_sock");
    if (!s_socks[slot].in_use) return err_resp("not_open");

    uint8_t buf[512];
    int n = hex_decode(data_j->valuestring, buf, sizeof(buf));
    if (n < 0) return err_resp("bad_hex");

    int sent = send(s_socks[slot].fd, buf, n, 0);
    if (sent < 0) return err_resp("send_failed");

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    cJSON_AddNumberToObject(resp, "bytes_sent", sent);
    return resp;
}

static cJSON* cmd_tcp_recv(cJSON* params)
{
    if (!s_initialized) return err_resp("not_initialized");
    cJSON* sock_j = cJSON_GetObjectItemCaseSensitive(params, "sock");
    if (!cJSON_IsNumber(sock_j)) return err_resp("missing_sock");
    int slot = sock_j->valueint;
    if (slot < 0 || slot >= NET_MAX_SOCKS) return err_resp("invalid_sock");
    if (!s_socks[slot].in_use) return err_resp("not_open");

    int timeout_ms = 1000;
    cJSON* t = cJSON_GetObjectItemCaseSensitive(params, "timeout_ms");
    if (cJSON_IsNumber(t)) timeout_ms = t->valueint;

    struct timeval tv = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    setsockopt(s_socks[slot].fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t buf[512];
    int n = recv(s_socks[slot].fd, buf, sizeof(buf), 0);
    if (n < 0) {
        // EAGAIN/EWOULDBLOCK → timeout; return empty data rather than error
        cJSON* resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "status", "ok");
        cJSON_AddStringToObject(resp, "data", "");
        cJSON_AddNumberToObject(resp, "bytes", 0);
        return resp;
    }

    char hex[1025];
    hex_encode(buf, (size_t)n, hex);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    cJSON_AddStringToObject(resp, "data", hex);
    cJSON_AddNumberToObject(resp, "bytes", n);
    return resp;
}

static cJSON* cmd_tcp_close(cJSON* params)
{
    cJSON* sock_j = cJSON_GetObjectItemCaseSensitive(params, "sock");
    if (!cJSON_IsNumber(sock_j)) return err_resp("missing_sock");
    int slot = sock_j->valueint;
    if (slot < 0 || slot >= NET_MAX_SOCKS) return err_resp("invalid_sock");
    if (!s_socks[slot].in_use) return err_resp("not_open");

    close(s_socks[slot].fd);
    s_socks[slot].fd = -1;
    s_socks[slot].in_use = false;

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
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
    if (strcmp(action, "dhcp") == 0)   return cmd_dhcp(params);
    if (strcmp(action, "static") == 0) return cmd_static(params);
    if (strcmp(action, "tcp_connect") == 0) return cmd_tcp_connect(params);
    if (strcmp(action, "tcp_send") == 0)    return cmd_tcp_send(params);
    if (strcmp(action, "tcp_recv") == 0)    return cmd_tcp_recv(params);
    if (strcmp(action, "tcp_close") == 0)   return cmd_tcp_close(params);

    cJSON* r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "error");
    cJSON_AddStringToObject(r, "error", "unknown_action");
    return r;
}
