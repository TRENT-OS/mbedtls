/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(USE_OS_CRYPTO)

#include "OS_Crypto.h"

#include "lib_debug/Debug.h"

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/trentos_ssl_cli.h"
#include "mbedtls/trentos_x509_crt.h"

#include <string.h>

static int
hash_cert(
    OS_Crypto_Handle_t hCrypto,
    mbedtls_md_type_t  hash_alg,
    const void*        cert,
    const size_t       cert_len,
    void*              hash,
    size_t*            hash_len)
{
    int ret;
    OS_Error_t err;
    OS_CryptoDigest_Handle_t hDigest;
    size_t cert_offs, cert_left, next_len;

    switch (hash_alg)
    {
    // The mbedTLS hash identifiers and the OS_CryptoDigest_Algs are
    // identical so we can simply use those
    case MBEDTLS_MD_MD5:
    case MBEDTLS_MD_SHA256:
        break;
    default:
        Debug_LOG_ERROR("Unsupported digest algorithm for cert: %i", hash_alg);
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = OS_CryptoDigest_init(&hDigest, hCrypto, hash_alg)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_init() failed with %d", err);
        goto err0;
    }

    // We may need to process the certificate in blocks, as it may be too big for the
    // current limitation of the crypto api...
    cert_offs = 0;
    cert_left = cert_len;
    next_len  = cert_left > OS_DATAPORT_DEFAULT_SIZE ? OS_DATAPORT_DEFAULT_SIZE :
                cert_left;
    while (cert_left > 0)
    {
        if ((err = OS_CryptoDigest_process(hDigest, cert + cert_offs,
                                           next_len)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoDigest_process() failed with %d", err);
            goto err1;
        }
        cert_left -= next_len;
        cert_offs += next_len;
        next_len   = cert_left > OS_DATAPORT_DEFAULT_SIZE ? OS_DATAPORT_DEFAULT_SIZE :
                     cert_left;
    }

    if ((err = OS_CryptoDigest_finalize(hDigest, hash,
                                        hash_len)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_finalize() failed with %d", err);
        goto err1;
    }

    // It went all OK, so no error needed -- still we want to free the digest
    ret = 0;

err1:
    if ((err = OS_CryptoDigest_free(hDigest)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_free() failed with %d", err);
    }
err0:
    return ret;
}

int
trentos_x509_crt_verify_signature(
    OS_Crypto_Handle_t hCrypto,
    void*              pk_ctx,
    mbedtls_pk_type_t  sig_type,
    mbedtls_md_type_t  hash_type,
    const void*        cert,
    size_t             cert_len,
    const void*        sig,
    size_t             sig_len)
{
    int ret;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    size_t hash_size = sizeof(hash);

    if ((ret = hash_cert(hCrypto, hash_type, cert, cert_len, hash,
                         &hash_size)) != 0)
    {
        Debug_LOG_ERROR("hash_cert() failed with %d", ret );
        return ret;
    }

    Debug_LOG_DEBUG("Hash of certificate");
    Debug_DUMP_DEBUG(hash, hash_size);

    return trentos_ssl_cli_verify_signature(hCrypto, pk_ctx, sig_type, hash_type,
                                            hash, hash_size, sig, sig_len);
}

#endif /* USE_OS_CRYPTO */