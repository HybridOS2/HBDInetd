# FIXME: These should line up with versions in Version.xcconfig
set(HBDINETD_MAC_VERSION 0.0.1)
set(MACOSX_FRAMEWORK_BUNDLE_VERSION 0.0.1)

find_package(LibXml2 2.8.0)
find_package(LibXslt 1.1.7)
find_package(CURL 7.60.0)
find_package(OpenSSL 1.1.1)
find_package(SQLite3 3.10.0)

HBDINETD_OPTION_BEGIN()
# Private options shared with other HBDInetd ports. Add options here only if
# we need a value different from the default defined in GlobalFeatures.cmake.

HBDINETD_OPTION_DEFAULT_PORT_VALUE(ENABLE_XML PUBLIC OFF)
HBDINETD_OPTION_DEFAULT_PORT_VALUE(ENABLE_HTTP PUBLIC OFF)
HBDINETD_OPTION_DEFAULT_PORT_VALUE(ENABLE_LSQL PUBLIC OFF)
HBDINETD_OPTION_DEFAULT_PORT_VALUE(ENABLE_RSQL PUBLIC OFF)
HBDINETD_OPTION_DEFAULT_PORT_VALUE(ENABLE_HIBUS PUBLIC OFF)
HBDINETD_OPTION_DEFAULT_PORT_VALUE(ENABLE_SSL PUBLIC OFF)

HBDINETD_OPTION_END()

set(HBDInetd_PKGCONFIG_FILE ${CMAKE_BINARY_DIR}/src/hbdinetd/hbdinetd.pc)

set(HBDInetd_LIBRARY_TYPE SHARED)
set(HBDInetdTestSupport_LIBRARY_TYPE SHARED)

