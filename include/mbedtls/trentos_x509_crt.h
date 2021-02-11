/*
 * Copyright (C) 2020, HENSOLDT Cyber GmbH
 */

#ifndef MBEDTLS_TRENTOS_X509_CRT_H
#define MBEDTLS_TRENTOS_X509_CRT_H

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
trentos_ssl_cli_export_cert_key(
    mbedtls_pk_type_t    sig_alg,
    void*                pk_ctx,
    OS_CryptoKey_Data_t* keyData);

int
trentos_x509_crt_verify_signature(
    OS_Crypto_Handle_t hCrypto,
    void*              pk_ctx,
    mbedtls_pk_type_t  sig_type,
    mbedtls_md_type_t  hash_type,
    const void*        cert,
    size_t             cert_len,
    const void*        sig,
    size_t             sig_len);


#ifdef __cplusplus
}
#endif

#endif /* USE_OS_CRYPTO */
#endif /* MBEDTLS_TRENTOS_X509_CRT_H */
