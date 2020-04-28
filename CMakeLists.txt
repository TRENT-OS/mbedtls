#
# We have two build targets:
#
# 1. 3rdparty_mbedtls_with_crypto_only:
#    Build mbedtls with dependencies for ONLY the CryptoLib
# 2. 3rdparty_mbedtls
#    Build mbedtls with all dependencies for TlsLib (which includes CryptoLib
#    dependencies)
#

# Sources for only CRYPTO builds
set(SOURCES_CRYPTO
    # UTILS ----------------------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/platform_util.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/bignum.c"
    # DIGEST ---------------------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md5.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/sha1.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/sha256.c"
    # RNG ------------------------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ctr_drbg.c"
    # CIPHER ---------------------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/cipher.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/cipher_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/aes.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/gcm.c"
    # AGREEMENT ------------------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/dhm.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecdh.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecp_curves.c"
    # SIGNATURE ------------------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/oid.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/rsa.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/rsa_internal.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pem.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/base64.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/asn1parse.c"
)

# Sources for TLS+CRYPTO builds
set(SOURCES_TLS
    # Need all the CRYPTO sources and a few extra --------------------------
    ${SOURCES_CRYPTO}
    # DEBUG TLS ------------------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/debug.c"
    # PK ABSTRACTION -------------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pk.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pk_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pkparse.c"
    # TLS PROTOCOL ---------------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ssl_ciphersuites.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ssl_cli.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ssl_tls.c"
    # TLS X509 CERT --------------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/x509.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/x509_crt.c"
    # Use TRENTOS-M CRYPTO -------------------------------------------------
    "${CMAKE_CURRENT_SOURCE_DIR}/library/crypto.c"
)

#------------------------------------------------------------------------------

project(3rdparty_mbedtls_with_crypto_only C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES_CRYPTO}
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/config-trentos-m.h"
)

#------------------------------------------------------------------------------

project(3rdparty_mbedtls C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES_TLS}
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/config-trentos-m.h"
)