# C3 AdBlock — ESP-IDF project
# DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM, no Arduino framework).
cmake_minimum_required(VERSION 3.16)

# Save the project name before including the IDF build system (it sets PROJECT).
set(PROJ_NAME "c3-adblock")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(${PROJ_NAME})
