add_definitions(-DBUILDING_FAKE__=1)

HBDINETD_OPTION_BEGIN()

# Public options specific to the HybridOS port. Do not add any options here unless
# there is a strong reason we should support changing the value of the option,
# and the option is not relevant to any other HBDInetd ports.
#HBDINETD_OPTION_DEFINE(USE_SYSTEMD "Whether to enable journald logging" PUBLIC ON)

# Private options specific to the HybridOS port. Changing these options is
# completely unsupported. They are intended for use only by HBDInetd developers.
#HBDINETD_OPTION_DEFINE(USE_ANGLE_WEBGL "Whether to use ANGLE as WebGL backend." PRIVATE OFF)
#HBDINETD_OPTION_DEPEND(ENABLE_WEBGL ENABLE_GRAPHICS_CONTEXT_GL)
#HBDINETD_OPTION_DEFAULT_PORT_VALUE(ENABLE_SSL PUBLIC ${ENABLE_SSL_DEFAULT})

# Finalize the value for all options. Do not attempt to use an option before
# this point, and do not attempt to change any option after this point.
HBDINETD_OPTION_END()

