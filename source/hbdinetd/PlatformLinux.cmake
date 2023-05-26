list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
)

set(hbdinetd_DEFINITIONS
    CONFIG_CTRL_IFACE
    CONFIG_CTRL_IFACE_UNIX
)

list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
    "${HBDINETD_DIR}/port/linux"
    "${HBDINETD_DIR}/port/linux/libnetutils/inc"
)

list(APPEND hbdinetd_SOURCES
    "${HBDINETD_DIR}/port/linux/network-device.c"
    "${HBDINETD_DIR}/port/linux/wpa-client/common.c"
    "${HBDINETD_DIR}/port/linux/wpa-client/os_unix.c"
    "${HBDINETD_DIR}/port/linux/wpa-client/wpa_debug.c"
    "${HBDINETD_DIR}/port/linux/wpa-client/wpa_ctrl.c"
    "${HBDINETD_DIR}/port/linux/wifi/wifi-ops.c"
    "${HBDINETD_DIR}/port/linux/wifi/wifi.c"
    "${HBDINETD_DIR}/port/linux/wifi/event.c"
    "${HBDINETD_DIR}/port/linux/wifi/helpers.c"
    "${HBDINETD_DIR}/port/linux/libnetutils/src/dhcpmsg.c"
    "${HBDINETD_DIR}/port/linux/libnetutils/src/dhcpclient.c"
    "${HBDINETD_DIR}/port/linux/libnetutils/src/ifc_utils.c"
    "${HBDINETD_DIR}/port/linux/libnetutils/src/packet.c"

)

install(FILES
    "${HBDINETD_DIR}/etc/wpa_supplicant.conf"
    DESTINATION "${HBDINETD_APP_INSTALL_DIR}/share/doc/"
)

