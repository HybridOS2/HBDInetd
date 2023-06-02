include(GlobalCommon)

configure_file(include/hbdinetd.h.in ${FORWARDING_HEADERS_DIR}/hbdinetd.h @ONLY)

HBDINETD_EXECUTABLE_DECLARE(hbdinetd)

list(APPEND hbdinetd_PRIVATE_INCLUDE_DIRECTORIES
    "${CMAKE_BINARY_DIR}"
    "${HBDINETD_DIR}"
    "${HBDINETD_DIR}/include"
    "${FORWARDING_HEADERS_DIR}"
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
    "${HBDINETD_DIR}/sbin/main.c"
    "${HBDINETD_DIR}/sbin/utils.c"
    "${HBDINETD_DIR}/sbin/common-iface.c"
    "${HBDINETD_DIR}/sbin/wifi-iface.c"
    "${HBDINETD_DIR}/sbin/config.c"
)

HBDINETD_INCLUDE_CONFIG_FILES_IF_EXISTS()

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

install(TARGETS hbdinetd DESTINATION "${HBDINETD_APP_INSTALL_DIR}/sbin/")

set(HVML_FILES
    "hvml/scan.hvml"
    "hvml/connect.hvml"
)

HBDINETD_COPY_FILES(HVMLFiles
    DESTINATION "${CMAKE_BINARY_DIR}"
    FILES ${HVML_FILES}
)

