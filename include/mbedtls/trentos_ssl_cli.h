/*
 * Copyright (C) 2020, HENSOLDT Cyber GmbH
 */

#ifndef MBEDTLS_TRENTOS_SSL_CLI_H
#define MBEDTLS_TRENTOS_SSL_CLI_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(USE_OS_CRYPTO)

#include "mbedtls/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

int
trentos_ssl_cli_parse_server_ecdh_params(
    mbedtls_ssl_context* ssl,
    unsigned char**      p,
    unsigned char*       end);

int
trentos_ssl_cli_parse_server_dh_params(
    mbedtls_ssl_context* ssl,
    unsigned char**      p,
    unsigned char*       end);

int
trentos_ssl_cli_exchange_key(
    mbedtls_ssl_context*        ssl,
    mbedtls_key_exchange_type_t ex_type,
    size_t*                     i,
    size_t*                     n);

#endif /* USE_OS_CRYPTO */
#endif /* MBEDTLS_TRENTOS_SSL_CLI_H */
