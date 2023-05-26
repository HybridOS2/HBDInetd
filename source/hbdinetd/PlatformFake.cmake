list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
)

set(hbdinetd_DEFINITIONS
    CONFIG_CTRL_IFACE
    CONFIG_CTRL_IFACE_UNIX
)

list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
    "${HBDINETD_DIR}/port/fake"
    "${HBDINETD_DIR}/port/fake/libnetutils/inc"
)

list(APPEND hbdinetd_SOURCES
    "${HBDINETD_DIR}/port/fake/network-device.c"
    "${HBDINETD_DIR}/port/fake/wifi/wifi-ops.c"
    "${HBDINETD_DIR}/port/fake/libnetutils/ifc.c"
    "${HBDINETD_DIR}/port/fake/libnetutils/dhcp.c"
)

install(FILES
    "${HBDINETD_DIR}/etc/wpa_supplicant.conf"
    DESTINATION "${HBDINETD_APP_INSTALL_DIR}/share/doc/"
)

