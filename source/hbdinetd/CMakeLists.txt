include(GlobalCommon)

HBDINETD_EXECUTABLE_DECLARE(hbdinetd)

list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
    "${CMAKE_BINARY_DIR}"
    "${HBDINETD_DIR}"
    "${HBDINETD_DIR}/include"
    "${PURC_INCLUDE_DIRS}"
    "${HBDBUS_INCLUDE_DIRS}"
    "${GLIB_INCLUDE_DIRS}"
)

set(hbdinetd_DEFINITIONS
    CONFIG_CTRL_IFACE
    CONFIG_CTRL_IFACE_UNIX
)

HBDINETD_EXECUTABLE(hbdinetd)

list(APPEND hbdinetd_SOURCES
    "${HBDINETD_DIR}/utils/avl.c"
    "${HBDINETD_DIR}/utils/avl-cmp.c"
    "${HBDINETD_DIR}/utils/kvlist.c"
    "${HBDINETD_DIR}/wpa-client/common.c"
    "${HBDINETD_DIR}/wpa-client/os_unix.c"
    "${HBDINETD_DIR}/wpa-client/wpa_debug.c"
    "${HBDINETD_DIR}/wpa-client/wpa_ctrl.c"
    "${HBDINETD_DIR}/wifi/wifi.c"
    "${HBDINETD_DIR}/wifi/wifi_event.c"
    "${HBDINETD_DIR}/wifi/wifimanager.c"
    "${HBDINETD_DIR}/wifi/wifi_state_machine.c"
    "${HBDINETD_DIR}/wifi/wpa_supplicant_conf.c"
    "${HBDINETD_DIR}/sbin/main.c"
    "${HBDINETD_DIR}/sbin/network-device.c"
    "${HBDINETD_DIR}/sbin/utils.c"
    "${HBDINETD_DIR}/sbin/common-impl.c"
#    "${HBDINETD_DIR}/sbin/wifi-impl.c"
#    "${HBDINETD_DIR}/sbin/tools.c"
#    "${HBDINETD_DIR}/sbin/wifi-ops.c"
)

set(hbdinetd_LIBRARIES
    PurC::PurC
    HBDBus::HBDBus
    "${GLIB_LIBRARIES}"
)

set_target_properties(hbdinetd PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/sbin"
)

HBDINETD_COMPUTE_SOURCES(hbdinetd)
HBDINETD_FRAMEWORK(hbdinetd)

install(TARGETS hbdinetd DESTINATION "${SYSEXEC_INSTALL_DIR}/")

