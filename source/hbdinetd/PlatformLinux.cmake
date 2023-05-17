list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
)

set(hbdinetd_DEFINITIONS
    CONFIG_CTRL_IFACE
    CONFIG_CTRL_IFACE_UNIX
)

list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
    "${HBDINETD_DIR}/port/linux"
)

list(APPEND hbdinetd_SOURCES
    "${HBDINETD_DIR}/port/linux/network-device.c"
    "${HBDINETD_DIR}/port/linux/wpa-client/common.c"
    "${HBDINETD_DIR}/port/linux/wpa-client/os_unix.c"
    "${HBDINETD_DIR}/port/linux/wpa-client/wpa_debug.c"
    "${HBDINETD_DIR}/port/linux/wpa-client/wpa_ctrl.c"
    "${HBDINETD_DIR}/port/linux/wifi/wifi-ops.c"
    "${HBDINETD_DIR}/port/linux/wifi/wifi.c"
    "${HBDINETD_DIR}/port/linux/wifi/wifi-event.c"
    "${HBDINETD_DIR}/port/linux/wifi/wpa-supplicant-conf.c"
#    "${HBDINETD_DIR}/port/linux/wifi/wifi_state_machine.c"
#    "${HBDINETD_DIR}/port/linux/wifi/wifimanager.c"
)

