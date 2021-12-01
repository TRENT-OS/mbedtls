/*
 * Copyright (C) 2021, HENSOLDT Cyber GmbH
 */

#ifndef MBEDTLS_TRENTOS_PK_H
#define MBEDTLS_TRENTOS_PK_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(USE_OS_CRYPTO)

#include "OS_Crypto.h"

#include "mbedtls/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

int
trentos_pk_verify_signature(
    OS_Crypto_Handle_t hCrypto,
    void*              pk_ctx,
    mbedtls_pk_type_t  sig_type,
    mbedtls_md_type_t  hash_type,
    const void*        hash,
    size_t             hash_len,
    const void*        sig,
    size_t             sig_len);

#endif /* USE_OS_CRYPTO */
#endif /* MBEDTLS_TRENTOS_PK_H */
