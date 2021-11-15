#
# Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
#

#
# mbedTLS library is used for various parts of TRENTOS.
#
# We have these build targets:
# - 3rdparty_mbedtls_for_crypto
# - 3rdparty_mbedtls_for_cert
# - 3rdparty_mbedtls_for_tls_client
# - 3rdparty_mbedtls_for_tls_server
#

# Sources for Crypto builds
set(SOURCES_CRYPTO
    "${CMAKE_CURRENT_SOURCE_DIR}/library/error.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/platform.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/platform_util.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/bignum.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md5.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/sha1.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/sha256.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ctr_drbg.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/cipher.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/cipher_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/aes.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/gcm.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/dhm.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecdh.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecp_curves.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/oid.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/rsa.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/rsa_internal.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pem.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/base64.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/asn1parse.c"
)

# Sources for Cert builds
set(SOURCES_CERT
    "${CMAKE_CURRENT_SOURCE_DIR}/library/error.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/platform.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/platform_util.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/bignum.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md5.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/sha256.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/cipher.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/cipher_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/aes.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/gcm.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecp_curves.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/oid.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/rsa.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/rsa_internal.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pem.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/base64.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/asn1parse.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pk.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pk_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pkparse.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/x509.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/x509_crt.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/trentos_ssl_cli.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/trentos_x509_crt.c"
)

# Sources for TLS client builds
# NOTE: For TLS client builds the files 'trentos_*.c' are included. These files
# implement all crypto logic using OS_Crypto.
set(SOURCES_TLS_CLIENT
    "${CMAKE_CURRENT_SOURCE_DIR}/library/error.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/platform.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/debug.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pk.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pk_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pkparse.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ssl_ciphersuites.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ssl_cli.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/trentos_ssl_cli.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ssl_tls.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/trentos_ssl_tls.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/x509.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/x509_crt.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/trentos_x509_crt.c"
)

# Sources for TLS server builds
# NOTE: For TLS server builds the files 'trentos_*.c' are NOT included because
# mbedTLS is used directly for crypto functionality.
set(SOURCES_TLS_SERVER
    "${CMAKE_CURRENT_SOURCE_DIR}/library/aes.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/asn1parse.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/base64.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/bignum.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/cipher_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/cipher.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ctr_drbg.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/debug.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/dhm.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecdh.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecp_curves.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ecp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/error.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/gcm.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/md5.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/oid.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pem.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pk_wrap.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pk.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/pkparse.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/platform_util.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/platform.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/rsa_internal.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/rsa.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/sha1.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/sha256.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ssl_ciphersuites.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ssl_srv.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/ssl_tls.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/x509_crt.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/library/x509.c"
)

#-------------------------------------------------------------------------------

set(COMPILE_OPTIONS
    -Wall
)

#-------------------------------------------------------------------------------

project(3rdparty_mbedtls_for_crypto C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES_CRYPTO}
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_OPTIONS}
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/config-trentos.h"
)

#-------------------------------------------------------------------------------

project(3rdparty_mbedtls_for_cert C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES_CERT}
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
       ${COMPILE_OPTIONS}
       -DUSE_OS_CRYPTO # Use modified mbedTLS via OS_Crypto
       -DMBEDTLS_SSL_CLI_C # Activate TLS client functionality because it is
                           # required for signature verification.
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/config-trentos.h"
)

#-------------------------------------------------------------------------------

project(3rdparty_mbedtls_for_tls_client C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES_TLS_CLIENT}
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
       ${COMPILE_OPTIONS}
       -DUSE_OS_CRYPTO # Use modified mbedTLS via OS_Crypto
       -DMBEDTLS_SSL_CLI_C # Activate TLS client functionality
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/config-trentos.h"
)

#-------------------------------------------------------------------------------

project(3rdparty_mbedtls_for_tls_server C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES_TLS_SERVER}
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_OPTIONS}
        # Use mbedTLS directly and not OS_Crypto
        -DMBEDTLS_SSL_SRV_C # Activate TLS server functionality
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/config-trentos.h"
)
