# Vowifi diameter extension
PROJECT("Vowifi extension")

SET( VOWIFI_SRC
        vowifi_main.c
        fini.c
        der_handler.c
        mar_handler.c
        maa_handler.c
        sar_handler.c
        utils.c
        log_utils.c
        eap_aka.c
        sip_auth.c
        rest_api.c
        process_maa.c
        process_saa.c
        vowifi_hook.c
        test_pool.c
        config_loader.c
)
SET( VOWIFI_HEADERS
  vowifi.h
)

# Compile as a module
FD_ADD_EXTENSION(app_vowifi ${VOWIFI_SRC} ${VOWIFI_HEADERS})
TARGET_LINK_LIBRARIES(app_vowifi curl pthread odpic)


INSTALL(TARGETS app_vowifi
 	LIBRARY DESTINATION ${INSTALL_EXTENSIONS_SUFFIX}
 	COMPONENT freeDiameter-app_vowifi)
