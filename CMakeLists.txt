#
# Copyright (C) 2020, HENSOLDT Cyber GmbH
#

#
# mbedTLS library used for various parts of TRENTOS-M
#
# We have these build targets:
#
# 1. 3rdparty_mbedtls_for_crypto: Required when building CryptoLib as part of
#    the Crypto API
# 2. 3rdparty_mbedtls_for_tls: Required when building TlsLib as part of
#    the TLS API
# 3. 3rdparty_mbedtls_for_cert: Required when building CertParser lib
#

# Sources for only CRYPTO builds
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

# Sources for TLS builds (note that only here we include the crypto.c, which is
# where we implement all the crypto logic which uses OS_Crypto!)
set(SOURCES_TLS
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

# Sources for CERT builds
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

set(COMPILE_OTIONS
    -Wall
)

#------------------------------------------------------------------------------

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
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/config-trentos-m.h"
)

#------------------------------------------------------------------------------

project(3rdparty_mbedtls_for_tls C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES_TLS}
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
       ${COMPILE_OPTIONS}
       # We need to use the modified version of mbedTLS functions which delegates
       # all cryptographic operations to the TRENTOS-M crypto
       -DUSE_OS_CRYPTO
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/config-trentos-m.h"
)

#------------------------------------------------------------------------------

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
       # We need to use the modified x509 routines so we can verify certs with
       # the TRENTOS-M crypto
       -DUSE_OS_CRYPTO
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/config-trentos-m.h"
)