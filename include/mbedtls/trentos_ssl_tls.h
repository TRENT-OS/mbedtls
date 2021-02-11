/*
 * Copyright (C) 2020, HENSOLDT Cyber GmbH
 */

#ifndef MBEDTLS_TRENTOS_SSL_TLS_H
#define MBEDTLS_TRENTOS_SSL_TLS_H

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
trentos_ssl_tls_tls_prf(
    mbedtls_ssl_context* ssl,
    const unsigned char* secret,
    size_t               slen,
    const char*          label,
    const unsigned char* random,
    size_t               rlen,
    unsigned char*       dstbuf,
    size_t               dlen);

void
trentos_ssl_tls_calc_verify(
    mbedtls_ssl_context* ssl,
    unsigned char        hash[32]);

void
trentos_ssl_tls_update_checksum(
    mbedtls_ssl_context* ssl,
    const unsigned char* buf,
    size_t               len);

void
trentos_ssl_tls_calc_finished(
    mbedtls_ssl_context* ssl,
    unsigned char*       buf,
    int                  from);

int
trentos_ssl_tls_import_aes_keys(
    OS_Crypto_Handle_t     hCrypto,
    OS_CryptoKey_Handle_t* hEncKey,
    OS_CryptoKey_Handle_t* hDecKey,
    const void*            enc_bytes,
    const void*            dec_bytes,
    size_t                 key_len);

int
trentos_ssl_tls_decrypt_buf(
    mbedtls_ssl_context* ssl);

int
trentos_ssl_tls_encrypt_buf(
    mbedtls_ssl_context* ssl);

#ifdef __cplusplus
}
#endif

#endif /* USE_OS_CRYPTO */
#endif /* MBEDTLS_TRENTOS_SSL_TLS_H */
