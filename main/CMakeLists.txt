idf_component_register(
    SRCS "main.cpp" "oled.cpp"
    INCLUDE_DIRS "."
    REQUIRES
        esp_wifi
        esp_event
        esp_http_server
        nvs_flash
        spiffs
        esp_http_client
        app_update
        esp_netif
        esp_timer
        esp_hw_support
        lwip
        log
        esp_system
        esp_driver_gpio
        esp_rom
)
