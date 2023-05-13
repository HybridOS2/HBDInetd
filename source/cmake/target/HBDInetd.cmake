if (NOT TARGET HBDInetd::HBDInetd)
    if (NOT INTERNAL_BUILD)
        message(FATAL_ERROR "HBDInetd::HBDInetd target not found")
    endif ()

    # This should be moved to an if block if the Apple Mac/iOS build moves completely to CMake
    # Just assuming Windows for the moment
    add_library(HBDInetd::HBDInetd STATIC IMPORTED)
    set_target_properties(HBDInetd::HBDInetd PROPERTIES
        IMPORTED_LOCATION ${WEBKIT_LIBRARIES_LINK_DIR}/HBDInetd${DEBUG_SUFFIX}.lib
    )
    set(HBDInetd_PRIVATE_FRAMEWORK_HEADERS_DIR "${CMAKE_BINARY_DIR}/../include/private")
    target_include_directories(HBDInetd::HBDInetd INTERFACE
        ${HBDInetd_PRIVATE_FRAMEWORK_HEADERS_DIR}
    )
endif ()
