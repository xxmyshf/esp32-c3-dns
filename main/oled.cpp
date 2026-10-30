// SSD1306 OLED — 72x40 (01Space ESP32-C3 0.42 OLED).
// Software I2C (bit-bang) — bypasses unreliable ESP-IDF async I2C driver.
#include "oled.h"
#include "driver/gpio.h"
#include "esp_rom_sys.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char* OLED_TAG = "oled";
static uint8_t fb[OLED_PAGES][OLED_WIDTH];

#define PIN_SDA  ((gpio_num_t)5)
#define PIN_SCL  ((gpio_num_t)6)
#define I2C_ADDR_W ((OLED_ADDR << 1) & 0xFE)

static inline void sda_lo() { gpio_set_level(PIN_SDA, 0); }
static inline void sda_hi() { gpio_set_level(PIN_SDA, 1); }
static inline void scl_lo() { gpio_set_level(PIN_SCL, 0); }
static inline void scl_hi() { gpio_set_level(PIN_SCL, 1); }
static inline int  sda_rd() { return gpio_get_level(PIN_SDA); }

// ~50kHz: 10us half-cycle
static inline void i2c_dly() {
    esp_rom_delay_us(5);
}

static bool i2c_wr(uint8_t b) {
    for (int i = 7; i >= 0; i--) {
        if (b & (1 << i)) sda_hi(); else sda_lo();
        i2c_dly();
        scl_hi(); i2c_dly(); scl_lo();
    }
    sda_hi(); i2c_dly();
    scl_hi(); i2c_dly();
    int ack = sda_rd();
    scl_lo();
    return ack == 0;
}

static void i2c_send(uint8_t ctrl, const uint8_t* data, int len) {
    // START
    sda_lo(); i2c_dly();
    scl_lo(); i2c_dly();

    i2c_wr(I2C_ADDR_W);
    i2c_wr(ctrl);
    for (int i = 0; i < len; i++) i2c_wr(data[i]);

    // STOP
    sda_lo(); i2c_dly();
    scl_hi(); i2c_dly();
    sda_hi(); i2c_dly();
}

static void oledCmd(uint8_t cmd) {
    i2c_send(0x00, &cmd, 1);
    vTaskDelay(pdMS_TO_TICKS(1));
}
static void oledCmd2(uint8_t a, uint8_t b) {
    uint8_t buf[2] = {a, b};
    i2c_send(0x00, buf, 2);
    vTaskDelay(pdMS_TO_TICKS(1));
}

void oledInit() {
    // GPIO: open-drain with pull-up
    gpio_set_direction(PIN_SDA, GPIO_MODE_INPUT_OUTPUT_OD);
    gpio_set_direction(PIN_SCL, GPIO_MODE_INPUT_OUTPUT_OD);
    gpio_pullup_en(PIN_SDA);
    gpio_pullup_en(PIN_SCL);
    sda_hi(); scl_hi();
    vTaskDelay(pdMS_TO_TICKS(100));

    // SSD1306 72x40 EastRising init
    oledCmd(0xAE);
    oledCmd2(0xD5, 0x80);
    oledCmd2(0xA8, 0x27);
    oledCmd2(0xD3, 0x00);
    oledCmd(0x40);
    oledCmd2(0xAD, 0x30);
    oledCmd2(0x8D, 0x14);
    oledCmd(0xA1);
    oledCmd(0xC8);
    oledCmd2(0xDA, 0x12);
    oledCmd2(0x81, 0xAF);
    oledCmd2(0xD9, 0x22);
    oledCmd2(0xDB, 0x20);
    oledCmd(0x2E);
    oledCmd(0xA4);
    oledCmd(0xA6);
    oledCmd(0xAF);

    oledClear();
    oledShow();
    ESP_LOGI(OLED_TAG, "OLED init OK (SW I2C, x_off=%d)", OLED_X_OFFSET);
}

void oledClear() { memset(fb, 0, sizeof(fb)); }

void oledText(int x, int y, const std::string& text, bool invert) {
    oledText(x, y, text.c_str(), invert);
}
void oledText(int x, int y, const char* text, bool invert) {
    if (y < 0 || y >= OLED_PAGES) return;
    for (int i = 0; text[i] && x < OLED_WIDTH; i++) {
        unsigned char ch = (unsigned char)text[i];
        if (ch < 32 || ch > 127) ch = ' ';
        const uint8_t* glyph = FONT5x7[ch - 32];
        for (int col = 0; col < 5 && x < OLED_WIDTH; col++) {
            fb[y][x] = invert ? ~glyph[col] : glyph[col];
            x++;
        }
        // No gap between chars — fits 14 chars in 72px
    }
}

void oledShow() {
    // Page addressing: set column+page, then write 72 bytes data.
    for (int page = 0; page < OLED_PAGES; page++) {
        int col = OLED_X_OFFSET;
        uint8_t cmds[3];
        cmds[0] = 0x10 | ((col >> 4) & 0x0F);
        cmds[1] = 0x00 | (col & 0x0F);
        cmds[2] = 0xB0 | (page & 0x0F);
        i2c_send(0x00, cmds, 3);
        vTaskDelay(pdMS_TO_TICKS(1));
        i2c_send(0x40, fb[page], OLED_WIDTH);
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

void oledPower(bool on) { oledCmd(on ? 0xAF : 0xAE); }
