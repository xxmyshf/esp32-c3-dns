// ============================================================================
//  C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3
//  Pure ESP-IDF port (no Arduino framework, no PSRAM required).
//
//  Blocklist = sorted 40-bit FNV-1a hashes in flash (SPIFFS), binary-searched.
//  Dashboard at http://c3adblock.local : per-client stats, system info,
//  ban clients, add custom block domains. All control state persisted to flash.
// ============================================================================
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_spiffs.h"
#include "nvs_flash.h"
// mDNS implemented manually (no external component needed)
#include "lwip/sockets.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "driver/gpio.h"
#include "esp_random.h"
#include "esp_timer.h"

#include <string>
#include <vector>

#include "secrets.h"
#include "page.h"
#include "oled.h"

static const char* TAG = "c3adblock";

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP   "9.9.9.9"          // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/spiffs/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;
static const int CACHE_SIZE = 256;
static const int MAX_RANGE = 256;


// ---- globals ----
static uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
static uint8_t dnsbuf[1536];

// first-level flash index + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

// mutex for shared state
static SemaphoreHandle_t g_mutex  = nullptr;  // clients, counters, banned, blocking, custom
static SemaphoreHandle_t bl_mutex = nullptr;  // blocklist file, cache, index

struct Dev {
    uint32_t ip;
    uint8_t mac[6];
    uint32_t blocked, allowed, lastSeen;
    bool banned;
};
static const int MAX_CLIENTS = 96;
static Dev clients[MAX_CLIENTS];
static int numClients = 0;

static const int MAX_CUSTOM = 200;
static std::string customDom[MAX_CUSTOM];
static uint64_t customHash[MAX_CUSTOM];
static int numCustom = 0;

static const int MAX_BAN = 32;
static uint32_t bannedIP[MAX_BAN];
static int numBanned = 0;

// remote blocklist auto-update
static std::string updateUrl;
static uint32_t updateIntervalH = 24;
static uint32_t lastCheckMs = 0;
static std::string updateStatus = "never";

// blocking pause
static bool     blockingOn = true;
static uint32_t resumeAt   = 0;

// upstream IP (parsed at init)
static uint32_t upstreamAddr = 0;
static std::string upstreamDnsStr = "9.9.9.9";  // configurable upstream DNS

// Custom DNS overrides: domain -> specific IP (like a hosts file)
struct DnsOverride { char domain[64]; uint32_t ip; uint64_t hash; };
static const int MAX_DNS_OVERRIDE = 50;
static DnsOverride dnsOverrides[MAX_DNS_OVERRIDE];
static int numDnsOverrides = 0;

// DNS query log (ring buffer)
struct DnsLog { char domain[64]; uint32_t clientIp; uint8_t result; uint32_t ts; };
static const int MAX_DNS_LOG = 60;
static DnsLog dnsLogBuf[MAX_DNS_LOG];
static int dnsLogHead = 0, dnsLogCount = 0;
static void addDnsLog(const char* domain, uint32_t ip, uint8_t result) {
    DnsLog& e = dnsLogBuf[dnsLogHead];
    strncpy(e.domain, domain, 63); e.domain[63] = 0;
    e.clientIp = ip; e.result = result; e.ts = (uint32_t)(esp_timer_get_time() / 1000000);
    dnsLogHead = (dnsLogHead + 1) % MAX_DNS_LOG;
    if (dnsLogCount < MAX_DNS_LOG) dnsLogCount++;
}

// blocklist file handle (opened read-only, kept open for seeks)
static FILE* blFile = nullptr;

// WiFi connected flag
static volatile bool wifiConnected = false;
static EventGroupHandle_t wifiEvents = nullptr;
#define BIT_CONNECTING  (1 << 0)
#define BIT_CONNECTED   (1 << 1)
#define BIT_FAIL        (1 << 2)

// HTTP server handle
static httpd_handle_t httpd = nullptr;

// mDNS hostname (configurable via web dashboard, persisted to SPIFFS)
static char mdnsName[64] = "c3adblock";

// ============================================================================
//  Utility
// ============================================================================
static uint32_t millis() { return (uint32_t)(esp_timer_get_time() / 1000); }

static std::string ipToString(uint32_t ip) {
    struct in_addr a; a.s_addr = ip;
    return std::string(inet_ntoa(a));
}
static std::string macStr(const uint8_t* m) {
    char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
    return std::string(s);
}
static std::string jesc(const std::string& s) {
    std::string o; for (char ch : s) { if (ch=='"'||ch=='\\') o+='\\'; o+=ch; } return o;
}
static std::string htmlEscape(const std::string& s) {
    std::string o; o.reserve(s.length());
    for (char ch : s) {
        switch (ch) {
            case '&':  o += "&amp;";  break;
            case '<':  o += "&lt;";   break;
            case '>':  o += "&gt;";   break;
            case '"':  o += "&quot;"; break;
            case '\'': o += "&#39;";  break;
            default:   o += ch;
        }
    }
    return o;
}
static std::string trim(std::string s) {
    auto a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
static std::string toLower(std::string s) {
    for (auto& c : s) c = tolower((unsigned char)c);
    return s;
}

// ============================================================================
//  Hashing / matching
// ============================================================================
static uint64_t fnv40(const char* s, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
    return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
    uint64_t v = 0;
    for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
    for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
    if (!blFile || numHashes == 0) return;
    for (int i = 0; i < INDEX_ENTRIES; i++) {
        uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
        fseek(blFile, (uint32_t)pos * HASH_BYTES, SEEK_SET);
        size_t rd = fread(blIndex[i], 1, HASH_BYTES, blFile);
        (void)rd;
    }
    for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
    if (numHashes == 0 || !blFile) return false;
    uint64_t first = unpackHash(blIndex[0]);
    uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
    if (h < first || h > last) return false;

    int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        uint64_t midv = unpackHash(blIndex[mid]);
        if (midv < h)      { seg = mid; lo = mid + 1; }
        else if (midv > h) { hi = mid - 1; }
        else               { return true; }
    }

    uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
    uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
    if (endPos >= numHashes) endPos = numHashes - 1;
    uint32_t rangeCount = endPos - startPos + 1;
    if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

    fseek(blFile, (uint32_t)startPos * HASH_BYTES, SEEK_SET);
    size_t rd = fread(rangeBuf, 1, (uint32_t)rangeCount * HASH_BYTES, blFile);
    (void)rd;

    for (uint32_t i = 0; i < rangeCount; i++) {
        uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
        if (v == h) return true;
        if (v > h) break;
    }
    return false;
}

static bool inCustom(uint64_t h) {
    for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true;
    return false;
}

static bool isBlockedHash(uint64_t h) {
    if (inCustom(h)) return true;
    uint32_t slot = h & (CACHE_SIZE - 1);
    if (cacheValid[slot]) {
        uint8_t want[HASH_BYTES]; packHash(h, want);
        bool same = true;
        for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
        if (same) return cacheRes[slot] != 0;
    }
    bool res = inFlash(h);
    cacheValid[slot] = 1;
    cacheRes[slot] = res ? 1 : 0;
    packHash(h, cacheKey[slot]);
    return res;
}

static bool isBlocked(const char* domain) {
    const char* p = domain;
    while (p && *p) {
        uint64_t h = fnv40(p, strlen(p));
        if (isBlockedHash(h)) return true;
        const char* dot = strchr(p, '.');
        if (!dot) break;
        const char* next = dot + 1;
        if (!strchr(next, '.')) break;
        p = next;
    }
    return false;
}

// ============================================================================
//  Persistence (SPIFFS)
// ============================================================================
static void loadCustom() {
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    numCustom = 0;
    FILE* f = fopen("/spiffs/custom.txt", "r");
    if (f) {
        char line[256];
        while (numCustom < MAX_CUSTOM && fgets(line, sizeof(line), f)) {
            std::string l = toLower(trim(std::string(line)));
            if (l.length() && l.find('.') != std::string::npos) {
                customDom[numCustom] = l;
                customHash[numCustom] = fnv40(l.c_str(), l.length());
                numCustom++;
            }
        }
        fclose(f);
    }
    xSemaphoreGive(g_mutex);
}
static void saveCustom() {
    FILE* f = fopen("/spiffs/custom.txt", "w");
    if (!f) return;
    for (int i = 0; i < numCustom; i++) fprintf(f, "%s\n", customDom[i].c_str());
    fclose(f);
}
static bool addCustom(std::string d) {
    d = toLower(trim(d));
    if (d.rfind("www.", 0) == 0) d = d.substr(4);
    if (!d.length() || d.find('.') == std::string::npos || numCustom >= MAX_CUSTOM) return false;
    for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    customDom[numCustom] = d;
    customHash[numCustom] = fnv40(d.c_str(), d.length());
    numCustom++;
    xSemaphoreGive(g_mutex);
    saveCustom();
    return true;
}
static void removeCustom(std::string d) {
    d = toLower(d);
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
        for (int j = i; j < numCustom - 1; j++) {
            customDom[j] = customDom[j+1];
            customHash[j] = customHash[j+1];
        }
        numCustom--;
        break;
    }
    xSemaphoreGive(g_mutex);
    saveCustom();
}

static bool isBannedIP(uint32_t ip) {
    for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true;
    return false;
}
static void loadBanned() {
    FILE* f = fopen("/spiffs/banned.txt", "r");
    if (!f) return;
    numBanned = 0;
    char line[64];
    while (numBanned < MAX_BAN && fgets(line, sizeof(line), f)) {
        std::string l = trim(std::string(line));
        if (l.length()) {
            struct in_addr a;
            if (inet_pton(AF_INET, l.c_str(), &a) == 1)
                bannedIP[numBanned++] = a.s_addr;
        }
    }
    fclose(f);
}
static void saveBanned() {
    numBanned = 0;
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    for (int i = 0; i < numClients && numBanned < MAX_BAN; i++)
        if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
    xSemaphoreGive(g_mutex);
    FILE* f = fopen("/spiffs/banned.txt", "w");
    if (!f) return;
    for (int i = 0; i < numBanned; i++) {
        struct in_addr a; a.s_addr = bannedIP[i];
        fprintf(f, "%s\n", inet_ntoa(a));
    }
    fclose(f);
}

static void loadUpdateCfg() {
    FILE* f = fopen("/spiffs/update.cfg", "r");
    if (!f) return;
    char line[512];
    if (fgets(line, sizeof(line), f)) updateUrl = trim(std::string(line));
    if (fgets(line, sizeof(line), f)) { std::string iv = trim(std::string(line)); if (iv.length()) updateIntervalH = atoi(iv.c_str()); }
    fclose(f);
    if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
    FILE* f = fopen("/spiffs/update.cfg", "w");
    if (!f) return;
    fprintf(f, "%s\n%u\n", updateUrl.c_str(), (unsigned int)updateIntervalH);
    fclose(f);
}

// ============================================================================
//  Blocklist swap
// ============================================================================
static void reopenBlocklist() {
    xSemaphoreTake(bl_mutex, portMAX_DELAY);
    if (blFile) { fclose(blFile); blFile = nullptr; }
    blFile = fopen(BLOCKLIST_PATH, "rb");
    if (blFile) {
        fseek(blFile, 0, SEEK_END);
        long sz = ftell(blFile);
        numHashes = sz / HASH_BYTES;
    } else {
        numHashes = 0;
    }
    buildFlashIndex();
    xSemaphoreGive(bl_mutex);
}
static void beginBlocklistSwap() {
    xSemaphoreTake(bl_mutex, portMAX_DELAY);
    if (blFile) { fclose(blFile); blFile = nullptr; }
    numHashes = 0;
    remove("/spiffs/blocklist.new");
    xSemaphoreGive(bl_mutex);
}
static bool commitNewBlocklist() {
    FILE* f = fopen("/spiffs/blocklist.new", "rb");
    long sz = 0;
    if (f) { fseek(f, 0, SEEK_END); sz = ftell(f); fclose(f); }
    bool ok = sz > 0 && (sz % HASH_BYTES) == 0;
    if (ok) {
        remove(BLOCKLIST_PATH);
        rename("/spiffs/blocklist.new", BLOCKLIST_PATH);
    } else {
        remove("/spiffs/blocklist.new");
    }
    reopenBlocklist();
    return ok;
}

// ============================================================================
//  Client table
// ============================================================================
static void getMac(uint32_t ip, uint8_t* mac) {
    memset(mac, 0, 6);
    ip4_addr_t ipa; ipa.addr = ip;
    struct eth_addr* eth = nullptr;
    const ip4_addr_t* ipret = nullptr;
    for (struct netif* nif = netif_list; nif; nif = nif->next)
        if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
    for (int i = 0; i < numClients; i++)
        if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
    if (numClients < MAX_CLIENTS) {
        Dev* c = &clients[numClients++];
        c->ip = ip;
        c->blocked = c->allowed = 0;
        c->lastSeen = millis();
        c->banned = isBannedIP(ip);
        getMac(ip, c->mac);
        return c;
    }
    return nullptr;
}

// ============================================================================
//  DNS protocol
// ============================================================================
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
    if (len < 13) return 0;
    int i = 12; size_t o = 0;
    while (i < len) {
        uint8_t l = pkt[i++];
        if (l == 0) break;
        if (l & 0xC0) return 0;
        if (o + l + 1 >= 250 || i + l > len) return 0;
        if (o) out[o++] = '.';
        for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]);
    }
    out[o] = 0;
    if (i + 4 > len) return 0;
    *qtype = (pkt[i] << 8) | pkt[i + 1];
    *qend = i + 4;
    if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
    return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
    dnsbuf[2] = 0x81; dnsbuf[3] = 0x80; dnsbuf[6] = 0; dnsbuf[7] = (qtype == 1) ? 1 : 0;
    dnsbuf[8] = 0; dnsbuf[9] = 0; dnsbuf[10] = 0; dnsbuf[11] = 0;
    if (qtype != 1) return qend;
    const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
    memcpy(dnsbuf + qend, ans, sizeof(ans));
    return qend + sizeof(ans);
}

// Build a DNS A-record response with a specific IP (for custom DNS overrides)
static int buildCustomDns(int qend, uint16_t qtype, uint32_t ip) {
    dnsbuf[2] = 0x81; dnsbuf[3] = 0x80; dnsbuf[6] = 0; dnsbuf[7] = (qtype == 1) ? 1 : 0;
    dnsbuf[8] = 0; dnsbuf[9] = 0; dnsbuf[10] = 0; dnsbuf[11] = 0;
    if (qtype != 1) return qend;
    const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4};
    memcpy(dnsbuf + qend, ans, sizeof(ans));
    memcpy(dnsbuf + qend + sizeof(ans), &ip, 4);
    return qend + sizeof(ans) + 4;
}
// Check if domain has a custom DNS override, return IP or 0
static uint32_t checkDnsOverride(const char* domain) {
    const char* p = domain;
    while (p && *p) {
        uint64_t h = fnv40(p, strlen(p));
        for (int i = 0; i < numDnsOverrides; i++)
            if (dnsOverrides[i].hash == h) return dnsOverrides[i].ip;
        const char* dot = strchr(p, '.'); if (!dot) break;
        const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
    }
    return 0;
}
// Load/save upstream DNS config
static void loadUpstreamCfg() {
    FILE* f = fopen("/spiffs/upstream.cfg", "r");
    if (!f) return;
    char line[64];
    if (fgets(line, sizeof(line), f)) { upstreamDnsStr = trim(std::string(line)); }
    fclose(f);
    struct in_addr a;
    if (inet_pton(AF_INET, upstreamDnsStr.c_str(), &a) == 1) upstreamAddr = a.s_addr;
    ESP_LOGI(TAG, "upstream DNS: %s", upstreamDnsStr.c_str());
}
static void saveUpstreamCfg() {
    FILE* f = fopen("/spiffs/upstream.cfg", "w");
    if (!f) return;
    fprintf(f, "%s\n", upstreamDnsStr.c_str());
    fclose(f);
}

// Load/save mDNS hostname
static void loadMdnsCfg() {
    FILE* f = fopen("/spiffs/mdns.cfg", "r");
    if (!f) return;
    char line[64];
    if (fgets(line, sizeof(line), f)) {
        std::string s = trim(std::string(line));
        if (s.length() > 0 && s.length() < sizeof(mdnsName)) {
            strncpy(mdnsName, s.c_str(), sizeof(mdnsName) - 1);
            mdnsName[sizeof(mdnsName) - 1] = 0;
        }
    }
    fclose(f);
    ESP_LOGI(TAG, "mDNS hostname: %s", mdnsName);
}
static void saveMdnsCfg() {
    FILE* f = fopen("/spiffs/mdns.cfg", "w");
    if (!f) return;
    fprintf(f, "%s\n", mdnsName);
    fclose(f);
}
// Load/save custom DNS overrides
static void loadDnsOverrides() {
    numDnsOverrides = 0;
    FILE* f = fopen("/spiffs/customdns.txt", "r");
    if (!f) return;
    char line[128];
    while (numDnsOverrides < MAX_DNS_OVERRIDE && fgets(line, sizeof(line), f)) {
        std::string l = trim(std::string(line));
        size_t eq = l.find('=');
        if (eq == std::string::npos) continue;
        std::string dom = toLower(trim(l.substr(0, eq)));
        std::string ipStr = trim(l.substr(eq + 1));
        struct in_addr a;
        if (dom.length() > 0 && dom.length() < 63 &&
            inet_pton(AF_INET, ipStr.c_str(), &a) == 1) {
            DnsOverride& o = dnsOverrides[numDnsOverrides];
            strncpy(o.domain, dom.c_str(), 63);
            o.domain[63] = 0;
            o.ip = a.s_addr;
            o.hash = fnv40(dom.c_str(), dom.length());
            numDnsOverrides++;
        }
    }
    fclose(f);
    ESP_LOGI(TAG, "custom DNS overrides: %d", numDnsOverrides);
}
static void saveDnsOverrides() {
    FILE* f = fopen("/spiffs/customdns.txt", "w");
    if (!f) return;
    for (int i = 0; i < numDnsOverrides; i++) {
        struct in_addr a; a.s_addr = dnsOverrides[i].ip;
        fprintf(f, "%s=%s\n", dnsOverrides[i].domain, inet_ntoa(a));
    }
    fclose(f);
}
static bool addDnsOverride(std::string dom, std::string ipStr) {
    dom = toLower(trim(dom));
    if (dom.rfind("www.", 0) == 0) dom = dom.substr(4);
    if (dom.empty() || dom.length() >= 63) return false;
    struct in_addr a;
    if (inet_pton(AF_INET, ipStr.c_str(), &a) != 1) return false;
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    for (int i = 0; i < numDnsOverrides; i++)
        if (strcmp(dnsOverrides[i].domain, dom.c_str()) == 0) {
            dnsOverrides[i].ip = a.s_addr;
            dnsOverrides[i].hash = fnv40(dom.c_str(), dom.length());
            xSemaphoreGive(g_mutex);
            saveDnsOverrides();
            return true;
        }
    if (numDnsOverrides >= MAX_DNS_OVERRIDE) { xSemaphoreGive(g_mutex); return false; }
    DnsOverride& o = dnsOverrides[numDnsOverrides];
    strncpy(o.domain, dom.c_str(), 63);
    o.domain[63] = 0;
    o.ip = a.s_addr;
    o.hash = fnv40(dom.c_str(), dom.length());
    numDnsOverrides++;
    xSemaphoreGive(g_mutex);
    saveDnsOverrides();
    return true;
}
static void delDnsOverride(std::string dom) {
    dom = toLower(trim(dom));
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    for (int i = 0; i < numDnsOverrides; i++)
        if (strcmp(dnsOverrides[i].domain, dom.c_str()) == 0) {
            for (int j = i; j < numDnsOverrides - 1; j++)
                dnsOverrides[j] = dnsOverrides[j + 1];
            numDnsOverrides--;
            break;
        }
    xSemaphoreGive(g_mutex);
    saveDnsOverrides();
}

// Forward to upstream DNS and relay the reply (with txid matching).
static int forwardUpstream(int qlen, int qend) {
    int upSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (upSock < 0) return 0;

    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(upSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const uint8_t cid0 = dnsbuf[0], cid1 = dnsbuf[1];
    const uint16_t wid = (uint16_t)esp_random();
    uint8_t q[260]; int ql = qend - 12;
    const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
    if (haveQ) memcpy(q, dnsbuf + 12, ql);
    dnsbuf[0] = wid >> 8; dnsbuf[1] = wid & 0xFF;

    struct sockaddr_in upAddr;
    memset(&upAddr, 0, sizeof(upAddr));
    upAddr.sin_family = AF_INET;
    upAddr.sin_port = htons(UPSTREAM_PORT);
    upAddr.sin_addr.s_addr = upstreamAddr;

    sendto(upSock, dnsbuf, qlen, 0, (struct sockaddr*)&upAddr, sizeof(upAddr));

    int retLen = 0;
    // try up to 2 times within 1s total
    uint32_t t0 = millis();
    while (millis() - t0 < 1000) {
        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);
        int n = recvfrom(upSock, dnsbuf, sizeof(dnsbuf), 0, (struct sockaddr*)&fromAddr, &fromLen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        if (n < 12) continue;
        if (fromAddr.sin_addr.s_addr != upstreamAddr) continue;
        if (dnsbuf[0] != (wid >> 8) || dnsbuf[1] != (wid & 0xFF)) continue;
        if (haveQ && (n < 12 + ql || memcmp(dnsbuf + 12, q, ql) != 0)) continue;
        dnsbuf[0] = cid0; dnsbuf[1] = cid1;
        retLen = n;
        break;
    }
    close(upSock);
    return retLen;
}

// ============================================================================
//  DNS server task
// ============================================================================
static void dns_task(void* param) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { ESP_LOGE(TAG, "DNS socket create failed: %s", strerror(errno)); vTaskDelete(nullptr); return; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "DNS bind failed: %s", strerror(errno));
        close(sock);
        vTaskDelete(nullptr);
        return;
    }

    ESP_LOGI(TAG, "DNS server listening on :53");

    uint8_t rxbuf[1536];
    while (true) {
        struct sockaddr_in cliAddr;
        socklen_t cliLen = sizeof(cliAddr);
        int qlen = recvfrom(sock, rxbuf, sizeof(rxbuf), 0,
                            (struct sockaddr*)&cliAddr, &cliLen);
        if (qlen < 13) continue;

        memcpy(dnsbuf, rxbuf, qlen);

        char domain[256];
        uint16_t qtype = 0;
        int qend = qlen;
        size_t dl = parseQuery(dnsbuf, qlen, domain, &qtype, &qend);

        uint32_t cip = cliAddr.sin_addr.s_addr;
        bool ban = false;
        bool blocked;

        xSemaphoreTake(g_mutex, portMAX_DELAY);
        Dev* c = getClient(cip);
        ban = c && c->banned;
        bool willBlock = blockingOn && dl && numHashes > 0;
        xSemaphoreGive(g_mutex);

        if (ban) {
            blocked = true;
        } else if (willBlock) {
            xSemaphoreTake(bl_mutex, portMAX_DELAY);
            blocked = isBlocked(domain);
            xSemaphoreGive(bl_mutex);
        } else {
            blocked = false;
        }

        // Check custom DNS overrides (domain -> specific IP)
        uint32_t customIp = 0;
        if (!blocked && dl) {
            xSemaphoreTake(g_mutex, portMAX_DELAY);
            customIp = checkDnsOverride(domain);
            xSemaphoreGive(g_mutex);
        }

        int rlen;
        if (blocked) {
            rlen = buildBlocked(qend, qtype);
            xSemaphoreTake(g_mutex, portMAX_DELAY);
            totalBlocked++;
            if (c) c->blocked++;
            xSemaphoreGive(g_mutex);
        } else if (customIp != 0) {
            rlen = buildCustomDns(qend, qtype, customIp);
            xSemaphoreTake(g_mutex, portMAX_DELAY);
            totalAllowed++;
            if (c) c->allowed++;
            xSemaphoreGive(g_mutex);
        } else {
            rlen = forwardUpstream(qlen, qend);
            xSemaphoreTake(g_mutex, portMAX_DELAY);
            totalAllowed++;
            if (c) c->allowed++;
            xSemaphoreGive(g_mutex);
        }

        if (rlen > 0) {
            sendto(sock, dnsbuf, rlen, 0, (struct sockaddr*)&cliAddr, cliLen);
        }
        // Log the query
        if (dl > 0) {
            uint8_t result = blocked ? 2 : (customIp != 0 ? 3 : 1);
            addDnsLog(domain, cip, result);
        }
    }
}

// ============================================================================
//  HTTP server — helpers
// ============================================================================
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";

// Base64 decode
static int b64Val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static int b64decode(const char* in, int len, char* out) {
    int o = 0;
    uint32_t v = 0; int bits = 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        int d = b64Val(c);
        if (d < 0) continue;
        v = (v << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (char)((v >> bits) & 0xFF);
        }
    }
    out[o] = 0;
    return o;
}

static bool checkAuth(httpd_req_t* req) { (void)req; return true; }
static bool requireAuth(httpd_req_t* req) { (void)req; return true; }

// Parse query parameter from URI
static std::string getQueryParam(httpd_req_t* req, const char* key) {
    const char* uri = req->uri;
    const char* q = strchr(uri, '?');
    if (!q) return "";
    std::string query(q + 1);
    std::string needle = std::string(key) + "=";
    size_t pos = query.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.length();
    size_t end = query.find('&', pos);
    if (end == std::string::npos) end = query.length();
    std::string val = query.substr(pos, end - pos);
    // URL decode
    std::string out;
    for (size_t i = 0; i < val.length(); i++) {
        if (val[i] == '%' && i + 2 < val.length()) {
            char hex[3] = {val[i+1], val[i+2], 0};
            out += (char)strtol(hex, nullptr, 16);
            i += 2;
        } else if (val[i] == '+') {
            out += ' ';
        } else {
            out += val[i];
        }
    }
    return out;
}

// ============================================================================
//  HTTP handlers
// ============================================================================
static esp_err_t handler_root(httpd_req_t* req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, PAGE, strlen(PAGE));
    return ESP_OK;
}

static esp_err_t handler_stats(httpd_req_t* req) {
    uint32_t up = millis() / 1000;
    char ut[24];
    snprintf(ut, sizeof(ut), "%lud %luh %lu", (unsigned long)(up/86400), (unsigned long)((up%86400)/3600), (unsigned long)((up%3600)/60));

    // Get STA IP
    esp_netif_ip_info_t ipInfo;
    esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"), &ipInfo);

    int8_t rssi = 0;
    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) rssi = ap.rssi;

    uint32_t freeHeap = esp_get_free_heap_size();

    bool defCreds = false;  // auth disabled, no warning
    uint32_t resumeIn = 0;
    if (!blockingOn && resumeAt)
        resumeIn = (int32_t)(resumeAt - millis()) > 0 ? (resumeAt - millis()) / 1000 : 0;

    xSemaphoreTake(g_mutex, portMAX_DELAY);
    // Build JSON
    std::string j = "{\"ip\":\"" + ipToString(ipInfo.ip.addr) +
                    "\",\"blocked\":" + std::to_string(totalBlocked) +
                    ",\"allowed\":" + std::to_string(totalAllowed) +
                    ",\"domains\":" + std::to_string(numHashes) +
                    ",\"rssi\":" + std::to_string(rssi) +
                    ",\"temp\":0" +
                    ",\"heap\":" + std::to_string(freeHeap) +
                    ",\"uptime\":\"" + std::string(ut) + "\"" +
                    ",\"upurl\":\"" + jesc(updateUrl) + "\"" +
                    ",\"upiv\":" + std::to_string(updateIntervalH) +
                    ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
                    ",\"blocking\":" + (blockingOn ? "true" : "false") +
                    ",\"resumeIn\":" + std::to_string(resumeIn) +
                    ",\"defcreds\":" + (defCreds ? "true" : "false") +
                    ",\"clients\":[";
    for (int i = 0; i < numClients; i++) {
        Dev& c = clients[i];
        if (i) j += ",";
        j += "{\"ip\":\"" + ipToString(c.ip) + "\",\"mac\":\"" + macStr(c.mac) +
             "\",\"blocked\":" + std::to_string(c.blocked) +
             ",\"allowed\":" + std::to_string(c.allowed) +
             ",\"banned\":" + (c.banned ? "true" : "false") + "}";
    }
    j += "],\"custom\":[";
    for (int i = 0; i < numCustom; i++) {
        if (i) j += ",";
        j += "\"" + jesc(customDom[i]) + "\"";
    }
    j += "],\"customDns\":[";
    for (int i = 0; i < numDnsOverrides; i++) {
        if (i) j += ",";
        struct in_addr a; a.s_addr = dnsOverrides[i].ip;
        j += "{\"domain\":\"" + std::string(dnsOverrides[i].domain) + "\",\"ip\":\"" + std::string(inet_ntoa(a)) + "\"}";
    }
    j += "],\"upstream\":\"" + upstreamDnsStr + "\"";
    j += ",\"mdns\":\"" + jesc(std::string(mdnsName)) + "\"";
    j += "}";
    xSemaphoreGive(g_mutex);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, j.c_str(), j.length());
    return ESP_OK;
}

static esp_err_t handler_ban(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    std::string ipStr = getQueryParam(req, "ip");
    struct in_addr a;
    if (inet_pton(AF_INET, ipStr.c_str(), &a) == 1) {
        xSemaphoreTake(g_mutex, portMAX_DELAY);
        Dev* c = getClient(a.s_addr);
        if (c) { c->banned = !c->banned; }
        xSemaphoreGive(g_mutex);
        saveBanned();
    }
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "ok", -1);
    return ESP_OK;
}

static esp_err_t handler_addblock(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    std::string d = getQueryParam(req, "d");
    addCustom(d);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "ok", -1);
    return ESP_OK;
}

static esp_err_t handler_unblock(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    std::string d = getQueryParam(req, "d");
    removeCustom(d);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "ok", -1);
    return ESP_OK;
}

static esp_err_t handler_pause(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    std::string sStr = getQueryParam(req, "s");
    long s = sStr.length() ? atol(sStr.c_str()) : 0;
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    blockingOn = false;
    resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    xSemaphoreGive(g_mutex);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "paused", -1);
    return ESP_OK;
}

static esp_err_t handler_resume(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    blockingOn = true;
    resumeAt = 0;
    xSemaphoreGive(g_mutex);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "resumed", -1);
    return ESP_OK;
}

static esp_err_t handler_forgetwifi(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "cleared — rebooting into setup portal", -1);
    nvs_handle_t h;
    nvs_open("wifi", NVS_READWRITE, &h);
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

static esp_err_t handler_setupdate(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    std::string u = getQueryParam(req, "u");
    std::string hStr = getQueryParam(req, "h");
    if (u.length()) updateUrl = u;
    if (hStr.length()) { updateIntervalH = atoi(hStr.c_str()); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg();
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "ok", -1);
    return ESP_OK;
}

// ---- Multipart file upload parser ----
// Extracts the file data from multipart/form-data and writes to a callback.
// The callback receives chunks of raw file data.
typedef bool (*UploadCallback)(const uint8_t* data, size_t len, void* ctx);

struct UploadCtx {
    bool authOk;
    bool ok;
};

static bool parseMultipartUpload(httpd_req_t* req, UploadCallback cb, void* cbCtx) {
    // Get boundary from Content-Type
    char ctBuf[256] = {0};
    if (httpd_req_get_hdr_value_str(req, "Content-Type", ctBuf, sizeof(ctBuf)) != ESP_OK)
        return false;

    const char* bp = strstr(ctBuf, "boundary=");
    if (!bp) return false;
    std::string boundary = "--" + std::string(bp + 9);

    int totalLen = req->content_len;
    int received = 0;

    // State machine:
    // 0 = looking for first boundary + headers
    // 1 = in file data, looking for closing boundary
    int phase = 0;

    // We need to find the end of multipart headers (\r\n\r\n) then stream file data
    // until we hit the closing boundary.
    std::string headerBuf;  // accumulates data until we find \r\n\r\n

    // For detecting boundary in streaming data, keep a small lookback
    uint8_t rxBuf[2048];
    std::string tail;  // leftover from previous chunk that might span boundary

    while (received < totalLen) {
        int toRead = sizeof(rxBuf);
        if (totalLen - received < toRead) toRead = totalLen - received;
        int n = httpd_req_recv(req, (char*)rxBuf, toRead);
        if (n <= 0) {
            if (n == HTTPD_SOCK_ERR_TIMEOUT) continue;
            break;
        }
        received += n;

        if (phase == 0) {
            // Accumulate until we find \r\n\r\n (end of part headers)
            headerBuf.append((char*)rxBuf, n);
            size_t hdrEnd = headerBuf.find("\r\n\r\n");
            if (hdrEnd != std::string::npos) {
                size_t dataStart = hdrEnd + 4;
                std::string dataChunk = headerBuf.substr(dataStart);
                phase = 1;
                headerBuf.clear();

                // Process this first chunk of file data
                // Check if it contains the closing boundary
                size_t bpos = dataChunk.find(boundary);
                if (bpos != std::string::npos) {
                    // File data ends before the boundary (minus \r\n)
                    size_t fileLen = bpos > 1 ? bpos - 2 : 0;  // \r\n before boundary
                    if (fileLen > 0)
                        if (!cb((const uint8_t*)dataChunk.data(), fileLen, cbCtx))
                            return false;
                    return true;  // done, single chunk had everything
                }
                // No boundary found, write all data and keep the tail
                if (dataChunk.length() > 0) {
                    // Keep last (boundary.length()+4) bytes as tail
                    size_t safeLen = dataChunk.length() > boundary.length() + 4
                        ? dataChunk.length() - (boundary.length() + 4) : 0;
                    if (safeLen > 0) {
                        if (!cb((const uint8_t*)dataChunk.data(), safeLen, cbCtx))
                            return false;
                    }
                    tail = dataChunk.substr(safeLen);
                }
            }
        } else if (phase == 1) {
            // In file data phase: combine tail + new data
            std::string combined = tail + std::string((char*)rxBuf, n);
            size_t bpos = combined.find(boundary);
            if (bpos != std::string::npos) {
                // File data ends at bpos - 2 (the \r\n before boundary)
                size_t fileLen = bpos > 1 ? bpos - 2 : 0;
                if (fileLen > 0)
                    if (!cb((const uint8_t*)combined.data(), fileLen, cbCtx))
                        return false;
                return true;  // done
            }
            // No boundary: write safe portion, keep tail
            size_t safeLen = combined.length() > boundary.length() + 4
                ? combined.length() - (boundary.length() + 4) : 0;
            if (safeLen > 0) {
                if (!cb((const uint8_t*)combined.data(), safeLen, cbCtx))
                    return false;
            }
            tail = combined.substr(safeLen);
        }
    }
    // If we exit the loop without finding closing boundary, flush remaining tail
    if (phase == 1 && tail.length() > 0) {
        // Check for boundary one more time
        size_t bpos = tail.find(boundary);
        if (bpos != std::string::npos) {
            size_t fileLen = bpos > 1 ? bpos - 2 : 0;
            if (fileLen > 0)
                if (!cb((const uint8_t*)tail.data(), fileLen, cbCtx))
                    return false;
        } else {
            // No closing boundary found, write what we have
            if (!cb((const uint8_t*)tail.data(), tail.length(), cbCtx))
                return false;
        }
    }
    return true;
}

// ---- Blocklist upload handler ----
struct BlUploadCtx {
    FILE* f;
    bool ok;
};

static bool blUploadCb(const uint8_t* data, size_t len, void* ctx) {
    BlUploadCtx* uc = (BlUploadCtx*)ctx;
    if (!uc->f) return false;
    size_t w = fwrite(data, 1, len, uc->f);
    return w == len;
}

static esp_err_t handler_upload(httpd_req_t* req) {
    // Auth is checked before we process the upload
    if (!checkAuth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"c3-adblock\"");
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_send(req, "auth required", -1);
        // Drain remaining body
        char drain[256];
        while (httpd_req_recv(req, drain, sizeof(drain)) > 0);
        return ESP_OK;
    }

    beginBlocklistSwap();
    BlUploadCtx uc;
    uc.f = fopen("/spiffs/blocklist.new", "wb");
    uc.ok = uc.f != nullptr;

    if (uc.f) {
        parseMultipartUpload(req, blUploadCb, &uc);
        fclose(uc.f);
    }

    bool ok = commitNewBlocklist();
    httpd_resp_set_type(req, "text/plain");
    if (ok) {
        httpd_resp_send(req, "ok", -1);
    } else {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_send(req, "rejected: empty or size not a multiple of 5", -1);
    }
    return ESP_OK;
}

// ---- Firmware OTA upload handler ----
struct FwUploadCtx {
    esp_ota_handle_t handle;
    const esp_partition_t* partition;
    bool ok;
    bool started;
};

static bool fwUploadCb(const uint8_t* data, size_t len, void* ctx) {
    FwUploadCtx* uc = (FwUploadCtx*)ctx;
    if (!uc->started) {
        uc->partition = esp_ota_get_next_update_partition(nullptr);
        if (!uc->partition) return false;
        esp_err_t err = esp_ota_begin(uc->partition, OTA_WITH_SEQUENTIAL_WRITES, &uc->handle);
        if (err != ESP_OK) { ESP_LOGE(TAG, "esp_ota_begin: %s", esp_err_to_name(err)); return false; }
        uc->started = true;
        uc->ok = true;
    }
    if (len == 0) return true;
    esp_err_t err = esp_ota_write(uc->handle, data, len);
    if (err != ESP_OK) { ESP_LOGE(TAG, "esp_ota_write: %s", esp_err_to_name(err)); uc->ok = false; return false; }
    return true;
}

static esp_err_t handler_update(httpd_req_t* req) {
    if (!checkAuth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"c3-adblock\"");
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_send(req, "auth required", -1);
        char drain[256];
        while (httpd_req_recv(req, drain, sizeof(drain)) > 0);
        return ESP_OK;
    }

    FwUploadCtx uc;
    uc.handle = 0;
    uc.partition = nullptr;
    uc.ok = false;
    uc.started = false;

    ESP_LOGI(TAG, "[fw-ota] receiving firmware upload...");
    parseMultipartUpload(req, fwUploadCb, &uc);

    if (uc.started) {
        if (uc.ok) {
            esp_err_t err = esp_ota_end(uc.handle);
            if (err == ESP_OK) {
                err = esp_ota_set_boot_partition(uc.partition);
                if (err == ESP_OK) {
                    ESP_LOGI(TAG, "[fw-ota] OK, rebooting");
                    httpd_resp_set_type(req, "text/plain");
                    httpd_resp_send(req, "ok, rebooting", -1);
                    vTaskDelay(pdMS_TO_TICKS(300));
                    esp_restart();
                    return ESP_OK;
                } else {
                    ESP_LOGE(TAG, "set_boot_partition: %s", esp_err_to_name(err));
                }
            } else {
                ESP_LOGE(TAG, "ota_end: %s", esp_err_to_name(err));
            }
        } else {
            esp_ota_abort(uc.handle);
        }
    }

    httpd_resp_set_status(req, "500 Internal Server Error");
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "firmware update failed", -1);
    return ESP_OK;
}

// ---- Clear custom blocked domains ----
static esp_err_t handler_clearcustom(httpd_req_t* req) {
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    numCustom = 0;
    xSemaphoreGive(g_mutex);
    saveCustom();
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "cleared", -1);
    return ESP_OK;
}

// ---- Import custom domains from text file ----
struct TxtImportCtx { std::string buf; int count; };
static bool txtImportCb(const uint8_t* data, size_t len, void* ctx) {
    TxtImportCtx* tc = (TxtImportCtx*)ctx;
    tc->buf.append((char*)data, len);
    return true;
}
static esp_err_t handler_importcustom(httpd_req_t* req) {
    TxtImportCtx tc;
    tc.count = 0;
    parseMultipartUpload(req, txtImportCb, &tc);

    // Parse lines and add each domain
    std::string& buf = tc.buf;
    size_t pos = 0;
    while (pos < buf.length()) {
        size_t nl = buf.find('\n', pos);
        std::string line = (nl == std::string::npos) ? buf.substr(pos) : buf.substr(pos, nl - pos);
        pos = (nl == std::string::npos) ? buf.length() : nl + 1;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        // strip "0.0.0.0 " prefix if hosts file format
        if (line.find("0.0.0.0 ") == 0) line = line.substr(8);
        if (addCustom(line)) tc.count++;
    }
    char msg[32];
    snprintf(msg, sizeof(msg), "imported %d domains", tc.count);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, msg, -1);
    return ESP_OK;
}

// ---- Upstream DNS configuration ----
static esp_err_t handler_setupstream(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    std::string ipStr = getQueryParam(req, "ip");
    if (ipStr.length()) {
        struct in_addr a;
        if (inet_pton(AF_INET, ipStr.c_str(), &a) == 1) {
            upstreamDnsStr = ipStr;
            upstreamAddr = a.s_addr;
            saveUpstreamCfg();
            ESP_LOGI(TAG, "upstream DNS set to %s", ipStr.c_str());
            httpd_resp_set_type(req, "text/plain");
            httpd_resp_send(req, "ok", -1);
            return ESP_OK;
        }
    }
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "invalid IP", -1);
    return ESP_OK;
}


static esp_err_t handler_setmdns(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    std::string name = getQueryParam(req, "name");
    if (name.length() > 0 && name.length() < 63) {
        bool valid = true;
        for (char c : name) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-')) {
                valid = false; break;
            }
        }
        if (valid) {
            strncpy(mdnsName, name.c_str(), sizeof(mdnsName) - 1);
            mdnsName[sizeof(mdnsName) - 1] = 0;
            saveMdnsCfg();
            ESP_LOGI(TAG, "mDNS name set to %s, rebooting...", mdnsName);
            httpd_resp_set_type(req, "text/plain");
            httpd_resp_send(req, "ok — rebooting", -1);
            vTaskDelay(pdMS_TO_TICKS(500));
            esp_restart();
            return ESP_OK;
        }
    }
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "invalid name (letters, digits, hyphens; max 63 chars)", -1);
    return ESP_OK;
}

// ---- Custom DNS override endpoints ----
static esp_err_t handler_addcustomdns(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    std::string d = getQueryParam(req, "d");
    std::string ip = getQueryParam(req, "ip");
    bool ok = addDnsOverride(d, ip);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, ok ? "ok" : "failed", -1);
    return ESP_OK;
}
static esp_err_t handler_delcustomdns(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    std::string d = getQueryParam(req, "d");
    delDnsOverride(d);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "ok", -1);
    return ESP_OK;
}

// ---- Remote blocklist fetch ----
static bool fetchBlocklist(std::string url) {
    url = trim(url);
    if (!url.length()) { updateStatus = "no url set"; return false; }
    ESP_LOGI(TAG, "[remote] GET %s", url.c_str());

    esp_http_client_config_t config = {};
    config.url = url.c_str();
    config.timeout_ms = 20000;
    config.disable_auto_redirect = false;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) { updateStatus = "init failed"; return false; }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        updateStatus = "open failed: " + std::string(esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return false;
    }

    esp_http_client_fetch_headers(client);
    int statusCode = esp_http_client_get_status_code(client);
    if (statusCode != 200) {
        updateStatus = "HTTP " + std::to_string(statusCode);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        ESP_LOGI(TAG, "[remote] %s", updateStatus.c_str());
        return false;
    }

    beginBlocklistSwap();
    FILE* f = fopen("/spiffs/blocklist.new", "wb");
    if (!f) {
        updateStatus = "fs open failed";
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        reopenBlocklist();
        return false;
    }

    uint8_t b[1024];
    size_t total = 0;
    int rd;
    while ((rd = esp_http_client_read(client, (char*)b, sizeof(b))) > 0) {
        fwrite(b, 1, rd, f);
        total += rd;
    }
    fclose(f);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    bool ok = commitNewBlocklist();
    updateStatus = ok ? ("ok: " + std::to_string(numHashes) + " domains")
                      : ("bad data (" + std::to_string(total) + "B)");
    ESP_LOGI(TAG, "[remote] %s", updateStatus.c_str());
    return ok;
}

static esp_err_t handler_fetchnow(httpd_req_t* req) {
    if (!requireAuth(req)) return ESP_OK;
    fetchBlocklist(updateUrl);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, updateStatus.c_str(), updateStatus.length());
    return ESP_OK;
}

// ---- DNS query log ----
static esp_err_t handler_log(httpd_req_t* req) {
    std::string j = "[";
    xSemaphoreTake(g_mutex, portMAX_DELAY);
    int idx = dnsLogHead - dnsLogCount;
    if (idx < 0) idx += MAX_DNS_LOG;
    for (int i = 0; i < dnsLogCount; i++) {
        DnsLog& e = dnsLogBuf[(idx + i) % MAX_DNS_LOG];
        if (i) j += ",";
        struct in_addr a; a.s_addr = e.clientIp;
        const char* resultStr = e.result == 2 ? "blocked" : (e.result == 3 ? "override" : "allowed");
        j += "{\"domain\":\"" + jesc(std::string(e.domain)) + "\",\"client\":\"" + std::string(inet_ntoa(a)) + "\"," ;
        j += "\"result\":\"" + std::string(resultStr) + "\"," ;
        char ts[16]; snprintf(ts, sizeof(ts), "%u", (unsigned int)e.ts);
        j += "\"ts\":" + std::string(ts) + "}";
    }
    xSemaphoreGive(g_mutex);
    j += "]";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, j.c_str(), j.length());
    return ESP_OK;
}

// ============================================================================
//  HTTP server registration
// ============================================================================
static void registerHttpHandlers() {
    httpd_uri_t uri;

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/";
    uri.method = HTTP_GET;
    uri.handler = handler_root;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/stats.json";
    uri.method = HTTP_GET;
    uri.handler = handler_stats;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/ban";
    uri.method = HTTP_GET;
    uri.handler = handler_ban;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/addblock";
    uri.method = HTTP_GET;
    uri.handler = handler_addblock;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/unblock";
    uri.method = HTTP_GET;
    uri.handler = handler_unblock;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/pause";
    uri.method = HTTP_GET;
    uri.handler = handler_pause;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/resume";
    uri.method = HTTP_GET;
    uri.handler = handler_resume;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/forgetwifi";
    uri.method = HTTP_GET;
    uri.handler = handler_forgetwifi;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/setupdate";
    uri.method = HTTP_GET;
    uri.handler = handler_setupdate;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/fetchnow";
    uri.method = HTTP_GET;
    uri.handler = handler_fetchnow;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/upload";
    uri.method = HTTP_POST;
    uri.handler = handler_upload;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/update";
    uri.method = HTTP_POST;
    uri.handler = handler_update;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/setmdns";
    uri.method = HTTP_GET;
    uri.handler = handler_setmdns;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/setupstream";
    uri.method = HTTP_GET;
    uri.handler = handler_setupstream;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/addcustomdns";
    uri.method = HTTP_GET;
    uri.handler = handler_addcustomdns;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/delcustomdns";
    uri.method = HTTP_GET;
    uri.handler = handler_delcustomdns;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/log.json";
    uri.method = HTTP_GET;
    uri.handler = handler_log;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/importcustom";
    uri.method = HTTP_POST;
    uri.handler = handler_importcustom;
    httpd_register_uri_handler(httpd, &uri);

    memset(&uri, 0, sizeof(uri));
    uri.uri = "/clearcustom";
    uri.method = HTTP_GET;
    uri.handler = handler_clearcustom;
    httpd_register_uri_handler(httpd, &uri);
}

static void startHttpServer() {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 24;
    config.stack_size = 8192;
    config.max_req_hdr_len = 1024;
    config.lru_purge_enable = true;
    if (httpd_start(&httpd, &config) == ESP_OK) {
        registerHttpHandlers();
        ESP_LOGI(TAG, "HTTP dashboard on :80");
    } else {
        ESP_LOGE(TAG, "Failed to start HTTP server");
    }
}

// ============================================================================
//  WiFi
// ============================================================================
static int wifiRetryCount = 0;
static void wifiEventHandler(void* arg, esp_event_base_t base, int32_t id, void* data) {
    if (base == WIFI_EVENT) {
        switch (id) {
            case WIFI_EVENT_STA_START:
                esp_wifi_connect();
                break;
            case WIFI_EVENT_STA_DISCONNECTED: {
                wifiRetryCount++;
                if (wifiRetryCount < 8) {
                    ESP_LOGW(TAG, "WiFi retry %d...", wifiRetryCount);
                    esp_wifi_connect();
                } else {
                    wifiConnected = false;
                    xEventGroupSetBits(wifiEvents, BIT_FAIL);
                    ESP_LOGW(TAG, "WiFi failed after %d retries", wifiRetryCount);
                }
                break;
            }
            default: break;
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        wifiRetryCount = 0;
        ip_event_got_ip_t* event = (ip_event_got_ip_t*)data;
        ESP_LOGI(TAG, "WiFi up: " IPSTR, IP2STR(&event->ip_info.ip));
        wifiConnected = true;
        xEventGroupSetBits(wifiEvents, BIT_CONNECTED);
    }
}

static bool hasCreds() {
    nvs_handle_t h;
    bool nvs = false;
    if (nvs_open("wifi", NVS_READONLY, &h) == ESP_OK) {
        size_t len = 0;
        if (nvs_get_str(h, "ssid", nullptr, &len) == ESP_OK && len > 1) nvs = true;
        nvs_close(h);
    }
    return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}

static bool connectWiFi() {
    // Try provisioned NVS creds first, then secrets.h fallback
    std::string ssid, pass;
    nvs_handle_t h;
    if (nvs_open("wifi", NVS_READONLY, &h) == ESP_OK) {
        char buf[128];
        size_t len;
        len = sizeof(buf);
        if (nvs_get_str(h, "ssid", buf, &len) == ESP_OK) ssid = buf;
        len = sizeof(buf);
        if (nvs_get_str(h, "pass", buf, &len) == ESP_OK) pass = buf;
        nvs_close(h);
    }

    if (!ssid.length()) {
        ssid = WIFI_SSID;
        pass = WIFI_PASS;
    }
    if (!ssid.length() || ssid == "YOUR_WIFI_SSID") return false;

    ESP_LOGI(TAG, "WiFi: connecting to \"%s\"%s", ssid.c_str(),
             (nvs_open("wifi", NVS_READONLY, &h) == ESP_OK) ? " (provisioned)" : " (secrets.h)");

    wifi_config_t cfg = {};
    strncpy((char*)cfg.sta.ssid, ssid.c_str(), sizeof(cfg.sta.ssid) - 1);
    strncpy((char*)cfg.sta.password, pass.c_str(), sizeof(cfg.sta.password) - 1);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &cfg);
    xEventGroupClearBits(wifiEvents, BIT_CONNECTED | BIT_FAIL);
    wifiRetryCount = 0;
    esp_wifi_start();  // triggers STA_START -> esp_wifi_connect() in event handler

    EventBits_t bits = xEventGroupWaitBits(wifiEvents,
        BIT_CONNECTED | BIT_FAIL, pdFALSE, pdFALSE,
        pdMS_TO_TICKS(30000));

    return (bits & BIT_CONNECTED) != 0;
}

// ============================================================================
//  Captive portal
// ============================================================================
// Simple DNS catch-all that responds to all queries with the AP IP.
static void portalDnsTask(void* param) {
    uint32_t apIp = (uint32_t)(uintptr_t)param;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { vTaskDelete(nullptr); return; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    uint8_t buf[512];
    struct sockaddr_in cli;
    socklen_t cliLen;
    while (true) {
        cliLen = sizeof(cli);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&cli, &cliLen);
        if (n < 12) continue;
        // Build a DNS response: copy query, add A record pointing to AP IP
        uint8_t resp[512];
        memcpy(resp, buf, n);
        resp[2] = 0x81; resp[3] = 0x80;  // response, recursion available
        resp[6] = 0; resp[7] = 1;        // ANCOUNT = 1
        resp[8] = 0; resp[9] = 0; resp[10] = 0; resp[11] = 0;
        // Append A record
        int pos = n;
        resp[pos++] = 0xC0; resp[pos++] = 0x0C;  // pointer to name
        resp[pos++] = 0; resp[pos++] = 1;        // type A
        resp[pos++] = 0; resp[pos++] = 1;        // class IN
        resp[pos++] = 0; resp[pos++] = 0; resp[pos++] = 0; resp[pos++] = 60; // TTL 60s
        resp[pos++] = 0; resp[pos++] = 4;        // RDLENGTH
        memcpy(resp + pos, &apIp, 4); pos += 4;
        sendto(sock, resp, pos, 0, (struct sockaddr*)&cli, cliLen);
    }
}

static esp_err_t handler_portal_root(httpd_req_t* req) {
    std::string html =
        "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>C3 AdBlock setup</title>"
        "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
        "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
        "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
        "<form method=POST action=/wifisave>"
        "<input name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
        "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
        "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
        "</form></body>";
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, html.c_str(), html.length());
    return ESP_OK;
}

static esp_err_t handler_wifisave(httpd_req_t* req) {
    // Read POST body (url-encoded form data)
    char buf[512];
    int totalLen = req->content_len;
    if (totalLen <= 0 || totalLen > (int)sizeof(buf)) {
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_send(req, "bad request", -1);
        return ESP_OK;
    }
    int received = 0;
    while (received < totalLen) {
        int n = httpd_req_recv(req, buf + received, totalLen - received);
        if (n <= 0) break;
        received += n;
    }
    buf[received] = 0;

    // Parse s=xxx&p=yyy
    std::string body(buf, received);
    std::string ssid, pass;
    // URL decode helper
    auto urlDecode = [](const std::string& s) {
        std::string o;
        for (size_t i = 0; i < s.length(); i++) {
            if (s[i] == '%' && i + 2 < s.length()) {
                char hex[3] = {s[i+1], s[i+2], 0};
                o += (char)strtol(hex, nullptr, 16);
                i += 2;
            } else if (s[i] == '+') o += ' ';
            else o += s[i];
        }
        return o;
    };

    // Find s=
    size_t pos = body.find("s=");
    if (pos == std::string::npos) {
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_send(req, "missing WiFi name", -1);
        return ESP_OK;
    }
    size_t end = body.find('&', pos);
    ssid = urlDecode(body.substr(pos + 2, end == std::string::npos ? std::string::npos : end - pos - 2));

    pos = body.find("p=");
    if (pos != std::string::npos) {
        end = body.find('&', pos);
        pass = urlDecode(body.substr(pos + 2, end == std::string::npos ? std::string::npos : end - pos - 2));
    }

    if (!ssid.length()) {
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_send(req, "missing WiFi name", -1);
        return ESP_OK;
    }

    nvs_handle_t h;
    nvs_open("wifi", NVS_READWRITE, &h);
    nvs_set_str(h, "ssid", ssid.c_str());
    nvs_set_str(h, "pass", pass.c_str());
    nvs_commit(h);
    nvs_close(h);

    std::string resp = "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                       "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ssid) + "</b>&hellip;<br><br>"
                       "Reconnect your phone to your normal WiFi, then find the box at <b>" + std::string(mdnsName) + ".local</b>.</body>";
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, resp.c_str(), resp.length());

    vTaskDelay(pdMS_TO_TICKS(900));
    esp_restart();
    return ESP_OK;
}

static void startConfigPortal() {
    ESP_LOGI(TAG, "[setup] Starting captive portal...");
    // Show portal message on OLED if available
    oledInit();
    oledClear();
    oledText(6, 0, "WiFi Setup");
    oledText(0, 2, "Join AP:");
    oledText(0, 3, "C3-AdBlock");
    oledText(0, 4, "192.168.4.1");
    oledShow();

    // Start AP mode
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_AP, mac);
    char apName[24];
    snprintf(apName, sizeof(apName), "C3-AdBlock-%02X%02X", mac[4], mac[5]);

    wifi_config_t apCfg = {};
    strcpy((char*)apCfg.ap.ssid, apName);
    apCfg.ap.channel = 1;
    apCfg.ap.authmode = WIFI_AUTH_OPEN;
    apCfg.ap.max_connection = 4;

    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &apCfg);
    esp_wifi_start();

    vTaskDelay(pdMS_TO_TICKS(100));

    // Get AP IP
    esp_netif_ip_info_t apIpInfo;
    esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("WIFI_AP_DEF"), &apIpInfo);
    uint32_t apIp = apIpInfo.ip.addr;

    ESP_LOGI(TAG, "[setup] Join open network \"%s\" and a setup page pops up (or http://%s)",
             apName, ipToString(apIp).c_str());

    // Start catch-all DNS portal
    xTaskCreate(portalDnsTask, "portal_dns", 4096, (void*)(uintptr_t)apIp, 5, nullptr);

    // Start HTTP server with portal handlers
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 8;
    config.stack_size = 8192;
    config.lru_purge_enable = true;
    if (httpd_start(&httpd, &config) == ESP_OK) {
        httpd_uri_t uri;

        memset(&uri, 0, sizeof(uri));
        uri.uri = "/";
        uri.method = HTTP_GET;
        uri.handler = handler_portal_root;
        httpd_register_uri_handler(httpd, &uri);

        memset(&uri, 0, sizeof(uri));
        uri.uri = "/wifisave";
        uri.method = HTTP_POST;
        uri.handler = handler_wifisave;
        httpd_register_uri_handler(httpd, &uri);

        // Wildcard handler for captive portal probes
        memset(&uri, 0, sizeof(uri));
        uri.uri = "/*";
        uri.method = HTTP_GET;
        uri.handler = handler_portal_root;
        httpd_register_uri_handler(httpd, &uri);
    }

    // Block here: if nobody uses the portal for 3 min and we had creds, retry
    const bool configured = hasCreds();
    uint32_t t0 = millis();
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wifi_sta_list_t staList;
        if (esp_wifi_ap_get_sta_list(&staList) == ESP_OK && staList.num > 0)
            t0 = millis();
        if (configured && millis() - t0 > 180000) {
            ESP_LOGI(TAG, "[setup] retrying WiFi");
            esp_restart();
        }
    }
}



// ============================================================================
//  OLED display update task
// ============================================================================
static volatile bool oledOn = true;

// BOOT button (GPIO9): short press toggles OLED on/off (debounced)
static void checkButton() {
    static bool lastLevel = true;      // pull-up, idle high
    static uint32_t lastChange = 0;
    static bool pressed = false;
    bool lvl = gpio_get_level((gpio_num_t)9);
    if (lvl != lastLevel) {
        lastLevel = lvl;
        lastChange = millis();
    }
    if (millis() - lastChange > 50) {  // stable for 50 ms
        if (lvl == 0 && !pressed) {
            pressed = true;
            oledOn = !oledOn;
            oledPower(oledOn);
            ESP_LOGI(TAG, "OLED %s", oledOn ? "on" : "off");
        } else if (lvl == 1) {
            pressed = false;
        }
    }
}

// Delay while polling the button so it stays responsive
static void delayWithButton(uint32_t ms) {
    uint32_t end = millis() + ms;
    while ((int32_t)(end - millis()) > 0) {
        checkButton();
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

static void oledDisplayTask(void* param) {
    // Show boot screen
    oledClear();
    oledText(8, 0, "C3 AdBlock");
    oledText(8, 2, "Starting...");
    oledShow();

    vTaskDelay(pdMS_TO_TICKS(2000));

    while (true) {
        // Get current stats
        esp_netif_ip_info_t ipInfo;
        esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"), &ipInfo);

        int8_t rssi = -100;
        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) rssi = ap.rssi;

        uint32_t up = millis() / 1000;
        uint32_t days = up / 86400;
        uint32_t hours = (up % 86400) / 3600;
        uint32_t mins = (up % 3600) / 60;

        uint32_t bl, al, nh;
        bool blkOn;
        xSemaphoreTake(g_mutex, portMAX_DELAY);
        bl = totalBlocked;
        al = totalAllowed;
        nh = numHashes;
        blkOn = blockingOn;
        xSemaphoreGive(g_mutex);

        struct in_addr addr;
        addr.s_addr = ipInfo.ip.addr;
        std::string ipStr = std::string(inet_ntoa(addr));

        // Format display — 72x40, 5 pages, ~12 chars per line
        char line1[16], line2[16], line3[16], line4[16], line5[16];

        snprintf(line1, sizeof(line1), "%s %ddBm",
                 blkOn ? "ADBLOCK" : "PAUSED", (int)rssi);
        snprintf(line2, sizeof(line2), "%s", ipStr.c_str());
        snprintf(line3, sizeof(line3), "B:%lu A:%lu",
                 (unsigned long)bl, (unsigned long)al);
        snprintf(line4, sizeof(line4), "Dom:%lu", (unsigned long)nh);
        if (days > 0)
            snprintf(line5, sizeof(line5), "Up:%lud%luh", (unsigned long)days, (unsigned long)hours);
        else
            snprintf(line5, sizeof(line5), "Up:%luh%lum", (unsigned long)hours, (unsigned long)mins);

        if (oledOn) {
            oledClear();
            oledText(0, 0, line1);
            oledText(0, 1, line2);
            oledText(0, 2, line3);
            oledText(0, 3, line4);
            oledText(0, 4, line5);
            oledShow();
        }
        delayWithButton(10000);  // page 1 (10s)

        // Page 2: upstream DNS + stats (no IP)
        char line6[16], line7[16], line8[16];
        snprintf(line6, sizeof(line6), "DNS:%s", upstreamDnsStr.c_str());
        snprintf(line7, sizeof(line7), "Blk:%lu", (unsigned long)bl);
        snprintf(line8, sizeof(line8), "R:%d Dom:%lu", numDnsOverrides, (unsigned long)nh);
        if (oledOn) {
            oledClear();
            oledText(0, 0, line6);
            oledText(0, 1, line7);
            oledText(0, 2, line3);
            oledText(0, 3, line8);
            oledText(0, 4, line5);
            oledShow();
        }
        delayWithButton(10000);  // page 2 (10s)
    }
}

// ============================================================================
//  Minimal mDNS responder (no external component)
//  Answers A-record queries for <hostname>.local via multicast DNS.
// ============================================================================
static void mdnsTask(void* param) {
    const char* hostname = (const char*)param;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { ESP_LOGE(TAG, "mDNS socket failed"); vTaskDelete(nullptr); return; }

    struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Set SO_REUSEADDR
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5353);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "mDNS bind failed");
        close(sock);
        vTaskDelete(nullptr);
        return;
    }

    // Join multicast group 224.0.0.251 on STA interface
    esp_netif_ip_info_t ipInfo;
    esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"), &ipInfo);
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    mreq.imr_interface.s_addr = ipInfo.ip.addr;  // bind to STA interface
    setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    // Set TTL
    int ttl = 255;
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    ESP_LOGI(TAG, "mDNS responder up");

    uint8_t rx[1024];
    uint8_t tx[512];
    while (true) {
        struct sockaddr_in from;
        socklen_t fromLen = sizeof(from);
        int n = recvfrom(sock, rx, sizeof(rx), 0, (struct sockaddr*)&from, &fromLen);
        if (n < 12) { vTaskDelay(pdMS_TO_TICKS(10)); continue; }

        // Get our current IP
        esp_netif_ip_info_t ipInfo;
        if (esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"), &ipInfo) != ESP_OK)
            continue;
        if (ipInfo.ip.addr == 0) continue;

        // Parse DNS query: check if it's asking for hostname.local
        // Header: id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2)
        uint16_t qdCount = (rx[4] << 8) | rx[5];
        if (qdCount == 0) continue;

        // Parse the question
        int pos = 12;
        char qname[256];
        int qpos = 0;
        while (pos < n) {
            uint8_t len = rx[pos++];
            if (len == 0) break;
            if (len & 0xC0) break;
            if (qpos + len + 1 < (int)sizeof(qname)) {
                if (qpos) qname[qpos++] = '.';
                memcpy(qname + qpos, rx + pos, len);
                qpos += len;
            }
            pos += len;
        }
        qname[qpos] = 0;
        if (pos + 4 > n) continue;
        uint16_t qtype = (rx[pos] << 8) | rx[pos + 2 + 0]; // actually qtype is at pos, qclass at pos+2
        qtype = (rx[pos] << 8) | rx[pos + 1];
        // Skip qtype(2) + qclass(2)
        int qendSection = pos + 4;

        // Check if qname matches hostname.local or dns.local
        char expected[128];
        snprintf(expected, sizeof(expected), "%s.local", hostname);
        bool match = (strcasecmp(qname, expected) == 0);
        if (!match) match = (strcasecmp(qname, "dns.local") == 0);
        if (!match) continue;
        if (qtype != 1) continue;  // Only A records

        // Build response
        memcpy(tx, rx, qendSection);  // copy header + question
        // Set response flags
        tx[2] = 0x84;  // response, authoritative
        tx[3] = 0x00;
        // ANCOUNT = 1
        tx[6] = 0; tx[7] = 1;
        // NSCOUNT = 0, ARCOUNT = 0
        tx[8] = 0; tx[9] = 0; tx[10] = 0; tx[11] = 0;

        // Answer: pointer to name (0xC0 0x0C), type A, class IN, TTL 300, RDLENGTH 4, RDATA = IP
        int apos = qendSection;
        tx[apos++] = 0xC0; tx[apos++] = 0x0C;
        tx[apos++] = 0; tx[apos++] = 1;       // type A
        tx[apos++] = 0; tx[apos++] = 1;       // class IN
        tx[apos++] = 0; tx[apos++] = 0; tx[apos++] = 0x01; tx[apos++] = 0x2C; // TTL 300
        tx[apos++] = 0; tx[apos++] = 4;       // RDLENGTH
        memcpy(tx + apos, &ipInfo.ip.addr, 4); apos += 4;

        // Send unicast response to the querier
        sendto(sock, tx, apos, 0, (struct sockaddr*)&from, fromLen);
    }
}

static void startMdns(const char* hostname) {
    xTaskCreate(mdnsTask, "mdns", 4096, (void*)hostname, 3, nullptr);
}

// ============================================================================
//  Main
// ============================================================================
extern "C" void app_main() {
    ESP_LOGI(TAG, "[c3-adblock] booting");

    // Create mutexes
    g_mutex  = xSemaphoreCreateMutex();
    bl_mutex = xSemaphoreCreateMutex();
    wifiEvents = xEventGroupCreate();

    // Init NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    // Init SPIFFS
    esp_vfs_spiffs_conf_t spiffsConf = {};
    spiffsConf.base_path = "/spiffs";
    spiffsConf.partition_label = "spiffs";
    spiffsConf.format_if_mount_failed = true;
    spiffsConf.max_files = 8;
    if (esp_vfs_spiffs_register(&spiffsConf) != ESP_OK)
        ESP_LOGE(TAG, "SPIFFS FAILED");
    else
        ESP_LOGI(TAG, "SPIFFS mounted");

    // Open blocklist
    blFile = fopen(BLOCKLIST_PATH, "rb");
    if (blFile) {
        fseek(blFile, 0, SEEK_END);
        long sz = ftell(blFile);
        numHashes = sz / HASH_BYTES;
        ESP_LOGI(TAG, "blocklist: %u domains", (unsigned int)numHashes);
        buildFlashIndex();
    } else {
        ESP_LOGW(TAG, "no blocklist found on flash");
    }

    loadCustom();
    loadBanned();
    loadUpdateCfg();
    loadUpstreamCfg();
    loadDnsOverrides();
    ESP_LOGI(TAG, "custom: %d, banned: %d, dnsOverride: %d", numCustom, numBanned, numDnsOverrides);

    // Parse upstream IP (use configured or default)
    if (upstreamAddr == 0) {
        struct in_addr upIn;
        inet_pton(AF_INET, UPSTREAM_IP, &upIn);
        upstreamAddr = upIn.s_addr;
    }

    // Init WiFi: netif + event loop first, then wifi driver
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifiEventHandler, nullptr, nullptr);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifiEventHandler, nullptr, nullptr);

    // BOOT button: hold at power-on to wipe saved WiFi
    const int BOOT_PIN = 9;  // C3 BOOT button
    gpio_set_direction((gpio_num_t)BOOT_PIN, GPIO_MODE_INPUT);
    gpio_pullup_en((gpio_num_t)BOOT_PIN);
    if (gpio_get_level((gpio_num_t)BOOT_PIN) == 0) {
        vTaskDelay(pdMS_TO_TICKS(60));
        if (gpio_get_level((gpio_num_t)BOOT_PIN) == 0) {
            nvs_handle_t h;
            nvs_open("wifi", NVS_READWRITE, &h);
            nvs_erase_all(h);
            nvs_commit(h);
            nvs_close(h);
            ESP_LOGI(TAG, "[setup] BOOT held -> cleared saved WiFi");
        }
    }

    // Connect WiFi or start portal
    if (!connectWiFi()) {
        startConfigPortal();  // never returns; reboots on save
    }

    // WiFi connected — start services
    // Init OLED display
    oledInit();
    // Start OLED display update task
    xTaskCreate(oledDisplayTask, "oled_display", 4096, nullptr, 3, nullptr);

    // Auth disabled — no credential warning

    // mDNS (minimal responder — answers A queries for <hostname>.local)
    loadMdnsCfg();
    startMdns(mdnsName);
    ESP_LOGI(TAG, "dashboard: http://%s.local", mdnsName);

    // Start HTTP server
    startHttpServer();

    // Start DNS server task
    xTaskCreate(dns_task, "dns_server", 8192, nullptr, 5, nullptr);

    ESP_LOGI(TAG, "DNS :53 + dashboard :80 up");

    // Main loop: periodic tasks
    while (true) {
        // Auto-resume blocking
        if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) {
            xSemaphoreTake(g_mutex, portMAX_DELAY);
            blockingOn = true;
            resumeAt = 0;
            xSemaphoreGive(g_mutex);
        }

        // Periodic remote blocklist auto-update
        if (updateUrl.length()) {
            uint32_t now = millis();
            if (lastCheckMs == 0) {
                lastCheckMs = now;
            } else if (now - lastCheckMs >= updateIntervalH * 3600000UL) {
                lastCheckMs = now;
                fetchBlocklist(updateUrl);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
