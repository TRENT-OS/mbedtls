/*
 * Copyright (C) 2021, HENSOLDT Cyber GmbH
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(USE_OS_CRYPTO)

#include "lib_debug/Debug.h"

#include "mbedtls/trentos_pk.h"
#include "mbedtls/trentos_x509_crt.h"

int
trentos_pk_verify_signature(
    OS_Crypto_Handle_t hCrypto,
    void*              pk_ctx,
    mbedtls_pk_type_t  sig_type,
    mbedtls_md_type_t  hash_type,
    const void*        hash,
    size_t             hash_len,
    const void*        sig,
    size_t             sig_len)
{
    int ret;
    OS_Error_t err;
    OS_CryptoKey_Data_t keyData;
    OS_CryptoKey_Handle_t hPubKey;
    OS_CryptoSignature_Handle_t hSig;

    if ((ret = trentos_x509_crt_export_cert_key(sig_type, pk_ctx, &keyData)) != 0)
    {
        Debug_LOG_ERROR("trentos_x509_crt_export_cert_key() failed with %d", ret );
        return ret;
    }

    if ((err = OS_CryptoKey_import(&hPubKey, hCrypto,
                                   &keyData)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_import() failed with %d", err);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    switch (keyData.type)
    {
    case OS_CryptoKey_TYPE_RSA_PUB:
        if ((err = OS_CryptoSignature_init(&hSig, hCrypto, NULL, hPubKey,
                                           OS_CryptoSignature_ALG_RSA_PKCS1_V15,
                                           hash_type)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoSignature_init() failed with %d", err);
            goto err0;
        }
        break;
    default:
        Debug_LOG_DEBUG("Unsupported key extracted from cert: %i",
                        keyData.type);
        goto err0;
    }

    if ((err = OS_CryptoSignature_verify(hSig, hash, hash_len, sig,
                                         sig_len)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoSignature_verify() failed with %d", err);
        goto err1;
    }

    // No error, but still clean up signature and key!
    ret = 0;

err1:
    if ((err = OS_CryptoSignature_free(hSig)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoSignature_init() failed with %d", err);
    }
err0:
    if ((err = OS_CryptoKey_free(hPubKey)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_free() failed with %d", err);
    }

    return ret;
}

#endif /* USE_OS_CRYPTO */
