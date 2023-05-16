list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
)

set(hbdinetd_DEFINITIONS
    CONFIG_CTRL_IFACE
    CONFIG_CTRL_IFACE_UNIX
)

list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
    "${HBDINETD_DIR}/ports/linux"
)

list(APPEND hbdinetd_SOURCES
    "${HBDINETD_DIR}/ports/linux/wpa-client/common.c"
    "${HBDINETD_DIR}/ports/linux/wpa-client/os_unix.c"
    "${HBDINETD_DIR}/ports/linux/wpa-client/wpa_debug.c"
    "${HBDINETD_DIR}/ports/linux/wpa-client/wpa_ctrl.c"
    "${HBDINETD_DIR}/ports/linux/wifi/wifi.c"
    "${HBDINETD_DIR}/ports/linux/wifi/wifi_event.c"
    "${HBDINETD_DIR}/ports/linux/wifi/wifimanager.c"
    "${HBDINETD_DIR}/ports/linux/wifi/wifi_state_machine.c"
    "${HBDINETD_DIR}/ports/linux/wifi/wpa_supplicant_conf.c"
    "${HBDINETD_DIR}/ports/linux/network-device.c"
    "${HBDINETD_DIR}/ports/linux/wifi-device.c"
)

