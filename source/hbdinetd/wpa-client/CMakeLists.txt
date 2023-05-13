cmake_minimum_required(VERSION 3.10)

project(wifimanager)
ADD_DEFINITIONS(-O0 -g -Wall -DEAP_TLS -DEAP_PEAP -DEAP_TTLS -DEAP_MD5 -DEAP_MSCHAPv2 -DEAP_GTC -DEAP_OTP -DEAP_LEAP -DIEEE8021X_EAPOL -DPKCS12_FUNCS -DCONFIG_SMARTCARD -DEAP_TLS_OPENSSL -DCONFIG_SHA256 -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX  -DCONFIG_SME)
add_library(wifimanager SHARED network_manager.c udhcpc_thread.c wifi.c wifi_event.c wifimanager.c wifi_state_machine.c wpa_supplicant_conf.c wpa_ctrl.c wpa_debug.c os_unix.c common.c)
include_directories(${MINIGUI_INCLUDE_DIRS} ${PROJECT_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(wifimanager ${MINIGUI_LIBRARIES})
install(TARGETS wifimanager DESTINATION lib)
