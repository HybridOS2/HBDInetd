include(GlobalCommon)

HBDINETD_EXECUTABLE_DECLARE(hbdinetd)

list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
    "${CMAKE_BINARY_DIR}"
    "${HBDINETD_DIR}"
    "${PURC_INCLUDE_DIRS}"
    "${HBDBUS_INCLUDE_DIRS}"
    "${GLIB_INCLUDE_DIRS}"
)

HBDINETD_EXECUTABLE(hbdinetd)

list(APPEND hbdinetd_SOURCES
    "${HBDINETD_DIR}/wpa-client/common.c"
    "${HBDINETD_DIR}/wpa-client/network_manager.c"
    "${HBDINETD_DIR}/wpa-client/os_unix.c"
    "${HBDINETD_DIR}/wpa-client/udhcpc_thread.c"
    "${HBDINETD_DIR}/wpa-client/wifi.c"
    "${HBDINETD_DIR}/wpa-client/wifi_event.c"
    "${HBDINETD_DIR}/wpa-client/wifimanager.c"
    "${HBDINETD_DIR}/wpa-client/wifi_state_machine.c"
    "${HBDINETD_DIR}/wpa-client/wpa_ctrl.c"
    "${HBDINETD_DIR}/wpa-client/wpa_debug.c"
    "${HBDINETD_DIR}/wpa-client/wpa_supplicant_conf.c"
    "${HBDINETD_DIR}/sbin/common-impl.c"
    "${HBDINETD_DIR}/sbin/ethernet-impl.c"
    "${HBDINETD_DIR}/sbin/mobile-impl.c"
    "${HBDINETD_DIR}/sbin/wifi-impl.c"
    "${HBDINETD_DIR}/sbin/main.c"
    "${HBDINETD_DIR}/sbin/tools.c"
    "${HBDINETD_DIR}/sbin/wifi-ops.c"
)

set(hbdinetd_LIBRARIES
    PurC::PurC
    HBDBus::HBDBus
)

set_target_properties(hbdinetd PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/sbin"
)

HBDINETD_COMPUTE_SOURCES(hbdinetd)
HBDINETD_FRAMEWORK(hbdinetd)

install(TARGETS hbdinetd DESTINATION "${SYSEXEC_INSTALL_DIR}/")
