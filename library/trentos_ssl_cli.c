/*
 * Copyright (C) 2020, HENSOLDT Cyber GmbH
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

#include <string.h>

static uint16_t
read_curve_id(
    unsigned char** p,
    unsigned char*  end)
{
    uint8_t type;
    uint16_t id;

    if ((size_t)(end - *p) < 3)
    {
        return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    // First byte is curve_type; only named_curve is handled
    type = **p;
    (*p) += 1;
    if (type != MBEDTLS_ECP_TLS_NAMED_CURVE )
    {
        return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    // Name of the curve
    id = ((*p)[0] << 8) | (*p)[1];
    (*p) += 2;

    return id;
}

static int
read_curve_point(
    unsigned char** p,
    unsigned char*  end,
    size_t          pLen,
    void*           xBytes,
    size_t*         xLen,
    void*           yBytes,
    size_t*         yLen)
{
    size_t n;
    int ret;

    // We must have at least two bytes (1 for length, at least one for data)
    if ( end - *p < 2 )
    {
        return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    n = **p;
    (*p) += 1;

    if (n < 1 || n > (size_t)(end - *p))
    {
        return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    ret = 0;
    switch (**p)
    {
    case 0x00:
        // This marks a point with ALL ZERO coordinates
        if (n != 1)
        {
            ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            goto out;
        }
        // Zero out the whole array
        memset(xBytes, 0, *xLen);
        memset(yBytes, 0, *yLen);
        *xLen = *yLen = 0;
        break;
    case 0x04:
        if (n != (2 * pLen) + 1)
        {
            ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            goto out;
        }
        // Both coords need to be as long as the prime of the curve
        *xLen = *yLen = pLen;
        memcpy(xBytes, *p + 1, *xLen);
        memcpy(yBytes, *p + 1 + pLen, *yLen);
        break;
    default:
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

out:
    (*p) += n;

    return ret;
}

int
trentos_ssl_cli_parse_server_ecdh_params(
    mbedtls_ssl_context* ssl,
    unsigned char**      p,
    unsigned char*       end)
{
    OS_Error_t err;
    OS_CryptoKey_Data_t keyData =
    {
        .type = OS_CryptoKey_TYPE_SECP256R1_PUB,
        .attribs.keepLocal = true
    };
    OS_CryptoKey_Secp256r1Pub_t* ecPub = &keyData.data.secp256r1.pub;

    /*
     * Ephemeral ECDH parameters:
     *
     * struct {
     *     ECParameters curve_params;
     *     ECPoint      public;
     * } ServerECDHParams;
     */
    if ((ssl->handshake->ecdh.curveId = read_curve_id(p, end)) < 0)
    {
        Debug_LOG_ERROR("Could not parse server ECDH curve id param");
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
    }

    Debug_LOG_DEBUG("ECDH curve ID: %i", ssl->handshake->ecdh.curveId);

    // Based on the curve_id, determine the size of the underlying prime. At this
    // point we only support one curve.
    switch (ssl->handshake->ecdh.curveId)
    {
    case 23: // secp256r1
        ssl->handshake->ecdh.primeLen = 32;
        break;
    default:
        Debug_LOG_ERROR("Curve is not supported: %i", ssl->handshake->ecdh.curveId);
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    ecPub->qxLen = OS_CryptoKey_SIZE_ECC;
    ecPub->qyLen = OS_CryptoKey_SIZE_ECC;
    if (ecPub->qyLen < ssl->handshake->ecdh.primeLen
        || ecPub->qxLen < ssl->handshake->ecdh.primeLen)
    {
        Debug_LOG_DEBUG("Buffer too small for ECDH curve point");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if (read_curve_point(p, end, ssl->handshake->ecdh.primeLen, ecPub->qxBytes,
                         &ecPub->qxLen, ecPub->qyBytes, &ecPub->qyLen))
    {
        Debug_LOG_ERROR("Could not parse server ECDH point param");
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
    }

    Debug_LOG_DEBUG("ECDH: x coord of server's point");
    Debug_DUMP_DEBUG(ecPub->qxBytes, ecPub->qxLen);

    Debug_LOG_DEBUG("ECDH: y coord of server's point");
    Debug_DUMP_DEBUG(ecPub->qyBytes, ecPub->qyLen);

    if ((err = OS_CryptoKey_import(&ssl->handshake->hPubKey, ssl->hCrypto,
                                   &keyData)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_import() failed with %d", err);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    return 0;
}

static int
write_ecdh_public_key(
    OS_CryptoKey_Data_t* keyData,
    uint8_t              pointFormat,
    unsigned char*       out_msg,
    size_t*              i,
    size_t*              n)
{
    size_t plen;
    OS_CryptoKey_Secp256r1Pub_t* ecPub = &keyData->data.secp256r1.pub;

    if (pointFormat == MBEDTLS_ECP_PF_UNCOMPRESSED)
    {
        out_msg[5] = 0x04;
        memcpy(&out_msg[6], ecPub->qxBytes, ecPub->qxLen);
        memcpy(&out_msg[6 + ecPub->qxLen], ecPub->qyBytes, ecPub->qyLen);

        plen = ecPub->qxLen + ecPub->qyLen + 1;

        Debug_LOG_DEBUG("ECDH: x coord of client's public point");
        Debug_DUMP_DEBUG(ecPub->qxBytes, ecPub->qxLen);

        Debug_LOG_DEBUG("ECDH: y coord of client's public point");
        Debug_DUMP_DEBUG(ecPub->qyBytes, ecPub->qyLen);
    }
    else if (pointFormat == MBEDTLS_ECP_PF_COMPRESSED)
    {
        // Compressed representation just needs the X coordinate and the SIGN
        // bit of the Y coord, so it can be recomputed from X via the curve
        // equation..
        out_msg[5] = 0x02 | (ecPub->qyBytes[0] & 0x01);
        memcpy(&out_msg[6], ecPub->qxBytes, ecPub->qxLen);

        plen = ecPub->qxLen + 1;

        Debug_LOG_DEBUG("ECDH: x coord of client's public point (compressed)");
        Debug_DUMP_DEBUG(ecPub->qxBytes, ecPub->qxLen);
    }
    else
    {
        Debug_LOG_ERROR("Unsupported ECDH point format: %02x", pointFormat);
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    out_msg[4] = plen;
    *i = 4;
    *n = plen + 1;

    return 0;
}

static int
write_dh_public_key(
    OS_CryptoKey_Data_t* keyData,
    unsigned char*       out_msg,
    size_t*              i,
    size_t*              n)
{
    OS_CryptoKey_DhPub_t* dhPub = &keyData->data.dh.pub;

    Debug_LOG_DEBUG("DH: client's public G*x value");
    Debug_DUMP_DEBUG(dhPub->gxBytes, dhPub->gxLen);

    // Write public param back to server
    out_msg[4] = (unsigned char)( dhPub->params.pLen >> 8 );
    out_msg[5] = (unsigned char)( dhPub->params.pLen      );
    memcpy(&out_msg[6], dhPub->gxBytes, dhPub->params.pLen);

    *n = dhPub->params.pLen;
    *i = 6;

    return 0;
}

int
trentos_ssl_cli_exchange_key(
    mbedtls_ssl_context*        ssl,
    mbedtls_key_exchange_type_t ex_type,
    size_t*                     i,
    size_t*                     n)
{
    int ret;
    OS_Error_t err;
    OS_CryptoKey_Handle_t hPrvKey, hPubKey;
    OS_CryptoAgreement_Handle_t hAgree;
    OS_CryptoAgreement_Alg_t algEx;
    // We have a stack limit of 4k, so we use this little trick so we can have
    // a spec and a key data on the stack, which together probably exceed the
    // current limit..
    union
    {
        OS_CryptoKey_Data_t data;
        OS_CryptoKey_Spec_t spec;
    } key;

    // Set up the key generation spec for our private key
    key.spec.key.attribs.keepLocal = true;
    if (MBEDTLS_KEY_EXCHANGE_DHE_RSA == ex_type)
    {
        // Extract public server params (P,G) from public key into generator spec
        size_t sz = sizeof(OS_CryptoKey_DhParams_t);
        if ((err = OS_CryptoKey_getParams(ssl->handshake->hPubKey,
                                          &key.spec.key.params.dh, &sz)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoKey_getParams() failed with %d", err);
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        key.spec.type     = OS_CryptoKey_SPECTYPE_PARAMS;
        key.spec.key.type = OS_CryptoKey_TYPE_DH_PRV;
        algEx             = OS_CryptoAgreement_ALG_DH;
    }
    else if (MBEDTLS_KEY_EXCHANGE_ECDHE_RSA == ex_type)
    {
        // We only support one curve right now, so there is no need to extract
        // any params or anything of that sort..
        key.spec.type     = OS_CryptoKey_SPECTYPE_BITS;
        key.spec.key.type = OS_CryptoKey_TYPE_SECP256R1_PRV;
        algEx             = OS_CryptoAgreement_ALG_ECDH;
    }

    // Generate private key and make public key from it
    if ((err = OS_CryptoKey_generate(&hPrvKey, ssl->hCrypto,
                                     &key.spec)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_generate() failed with %d", err);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = OS_CryptoKey_makePublic(&hPubKey, ssl->hCrypto, hPrvKey,
                                       &key.spec.key.attribs)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_makePublic() failed with %d", err);
        goto err0;
    }
    // Export public key
    if ((err = OS_CryptoKey_export(hPubKey, &key.data)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_export() failed with %d", err);
        goto err1;
    }

    // Write exported key data to TLS buffer
    if ( ( (MBEDTLS_KEY_EXCHANGE_DHE_RSA == ex_type) &&
           (ret = write_dh_public_key(&key.data, ssl->out_msg, i, n)) ) ||
         ( (MBEDTLS_KEY_EXCHANGE_ECDHE_RSA == ex_type) &&
           (ret = write_ecdh_public_key(&key.data, ssl->handshake->ecdh.pointFormat,
                                        ssl->out_msg, i, n))))
    {
        goto err1;
    }

    // Based on the newly derived private key of the CLIENT and the public key
    // of the server agree on a shared secret!
    ssl->handshake->pmslen = MBEDTLS_PREMASTER_SIZE;
    if ((err = OS_CryptoAgreement_init(&hAgree, ssl->hCrypto, hPrvKey,
                                       algEx)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoAgreement_init() failed with %d", err);
        goto err1;
    }
    if ((err = OS_CryptoAgreement_agree(hAgree, ssl->handshake->hPubKey,
                                        ssl->handshake->premaster, &ssl->handshake->pmslen)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoAgreement_agree() failed with %d", err);
    }

    ret = 0;

    if ((err = OS_CryptoAgreement_free(hAgree)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoAgreement_free() failed with %d", err);
    }
err1:
    if ((err = OS_CryptoKey_free(hPubKey)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_free() failed with %d", err);
    }
err0:
    if ((err = OS_CryptoKey_free(hPrvKey)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_free() failed with %d", err);
    }
    return ret;
}

static size_t
read_bignum(
    unsigned char** p,
    unsigned char*  end,
    void*           buf,
    size_t          sz)
{
    size_t n;

    if ( end - *p < 2 )
    {
        return ( MBEDTLS_ERR_DHM_BAD_INPUT_DATA );
    }

    // First two bytes are length of big num
    n = ( (*p)[0] << 8 ) | (*p)[1];
    (*p) += 2;

    if (n > sz || n > (size_t)( end - *p ))
    {
        return ( MBEDTLS_ERR_DHM_BAD_INPUT_DATA );
    }

    if (n > 0)
    {
        memcpy(buf, *p, n);
        (*p) += n;
    }

    return n;
}

int
trentos_ssl_cli_parse_server_dh_params(
    mbedtls_ssl_context* ssl,
    unsigned char**      p,
    unsigned char*       end)
{
    OS_Error_t err;
    OS_CryptoKey_Data_t keyData =
    {
        .type = OS_CryptoKey_TYPE_DH_PUB,
        .attribs.keepLocal = true
    };
    OS_CryptoKey_DhPub_t* dhPub = &keyData.data.dh.pub;

    /*
     * Ephemeral DH parameters:
     *
     * struct {
     *     opaque dh_p<1..2^16-1>;
     *     opaque dh_g<1..2^16-1>;
     *     opaque dh_Ys<1..2^16-1>;
     * } ServerDHParams;
     */
    if ( (dhPub->params.pLen = read_bignum(p, end, dhPub->params.pBytes,
                                           OS_CryptoKey_SIZE_DH_MAX)) <= 0 ||
         (dhPub->params.gLen = read_bignum(p, end, dhPub->params.gBytes,
                                           OS_CryptoKey_SIZE_DH_MAX)) <= 0 ||
         (dhPub->gxLen       = read_bignum(p, end, dhPub->gxBytes,
                                           OS_CryptoKey_SIZE_DH_MAX)) <= 0 )
    {
        Debug_LOG_ERROR("Could not parse server DHM params");
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
    }

    if (dhPub->params.pLen * 8 < ssl->conf->dhm_min_bitlen)
    {
        Debug_LOG_ERROR("DHM prime too short: %d < %d",
                        dhPub->params.pLen * 8, ssl->conf->dhm_min_bitlen);
        return MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE;
    }

    if ((err = OS_CryptoKey_import(&ssl->handshake->hPubKey, ssl->hCrypto,
                                   &keyData)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_import() failed with %d", err);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    Debug_LOG_DEBUG("DH: shared P value");
    Debug_DUMP_DEBUG(dhPub->params.pBytes, dhPub->params.pLen);

    Debug_LOG_DEBUG("DH: shared G value");
    Debug_DUMP_DEBUG(dhPub->params.gBytes, dhPub->params.gLen);

    // Note: The view here is that the public param is "theirs", that is why here it
    // is called GY. We only have "our" keys (public / private), where we have the
    // secret param X and thus GX as name for the public value!
    Debug_LOG_DEBUG("DH: server's public G*y value");
    Debug_DUMP_DEBUG(dhPub->gxBytes, dhPub->gxLen);

    return ( 0 );
}

int
trentos_ssl_cli_export_cert_key(
    mbedtls_pk_type_t    sig_alg,
    void*                pk_ctx,
    OS_CryptoKey_Data_t* keyData)
{
    int ret;

    memset(keyData, 0, sizeof(OS_CryptoKey_Data_t));

    keyData->attribs.keepLocal = true;
    switch (sig_alg)
    {
    case MBEDTLS_PK_RSA:
    {
        mbedtls_rsa_context* rsa_ctx = (mbedtls_rsa_context*) pk_ctx;
        OS_CryptoKey_RsaRub_t* hPubKey = &keyData->data.rsa.pub;
        // Make sure we can actually handle the key
        if (rsa_ctx->len > OS_CryptoKey_SIZE_RSA_MAX)
        {
            Debug_LOG_ERROR("RSA key size not supported: %i", rsa_ctx->len);
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        }
        // Transform the public key into a OS_CryptoKey_Data_t so we can use it
        // for our own purposes.
        keyData->type = OS_CryptoKey_TYPE_RSA_PUB;
        hPubKey->nLen = rsa_ctx->len;
        hPubKey->eLen = rsa_ctx->len;
        if ((ret = mbedtls_rsa_export_raw(pk_ctx,
                                          hPubKey->nBytes, hPubKey->nLen,
                                          NULL, 0,
                                          NULL, 0,
                                          NULL, 0,
                                          hPubKey->eBytes, hPubKey->eLen)) != 0)
        {
            Debug_LOG_ERROR("mbedtls_rsa_export_raw() failed with %d", ret );
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        break;
    }
    default:
        Debug_LOG_ERROR("Unsupported signature algorithm for cert: %i",
                        sig_alg);
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    return 0;
}

int
trentos_ssl_cli_verify_signature(
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

    if ((ret = trentos_ssl_cli_export_cert_key(sig_type, pk_ctx, &keyData)) != 0)
    {
        Debug_LOG_ERROR("trentos_ssl_cli_export_cert_key() failed with %d", ret );
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