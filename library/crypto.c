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

#include "LibDebug/Debug.h"

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"

#include <string.h>

// ------------------------------- ssl_cli.c ----------------------------------

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
crypto_parse_server_ecdh_params(
    mbedtls_ssl_context* ssl,
    unsigned char**      p,
    unsigned char*       end)
{
    seos_err_t err;
    OS_CryptoKey_Data_t keyData =
    {
        .type = OS_CryptoKey_TYPE_SECP256R1_PUB,
        .attribs.exportable = true
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
    Debug_hexDump(Debug_LOG_LEVEL_DEBUG, ecPub->qxBytes, ecPub->qxLen);

    Debug_LOG_DEBUG("ECDH: y coord of server's point");
    Debug_hexDump(Debug_LOG_LEVEL_DEBUG, ecPub->qyBytes, ecPub->qyLen);

    if ((err = OS_CryptoKey_import(&ssl->handshake->hPubKey, ssl->hCrypto,
                                   &keyData)) != SEOS_SUCCESS)
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
        Debug_hexDump(Debug_LOG_LEVEL_DEBUG, ecPub->qxBytes, ecPub->qxLen);

        Debug_LOG_DEBUG("ECDH: y coord of client's public point");
        Debug_hexDump(Debug_LOG_LEVEL_DEBUG, ecPub->qyBytes, ecPub->qyLen);
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
        Debug_hexDump(Debug_LOG_LEVEL_DEBUG, ecPub->qxBytes, ecPub->qxLen);
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
    Debug_hexDump(Debug_LOG_LEVEL_DEBUG, dhPub->gxBytes, dhPub->gxLen);

    // Write public param back to server
    out_msg[4] = (unsigned char)( dhPub->params.pLen >> 8 );
    out_msg[5] = (unsigned char)( dhPub->params.pLen      );
    memcpy(&out_msg[6], dhPub->gxBytes, dhPub->params.pLen);

    *n = dhPub->params.pLen;
    *i = 6;

    return 0;
}

int
crypto_exchange_key(
    mbedtls_ssl_context*        ssl,
    mbedtls_key_exchange_type_t ex_type,
    size_t*                     i,
    size_t*                     n)
{
    int ret;
    seos_err_t err;
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
    key.spec.key.attribs.exportable = true;
    if (MBEDTLS_KEY_EXCHANGE_DHE_RSA == ex_type)
    {
        // Extract public server params (P,G) from public key into generator spec
        size_t sz = sizeof(OS_CryptoKey_DhParams_t);
        if ((err = OS_CryptoKey_getParams(ssl->handshake->hPubKey,
                                          &key.spec.key.params.dh, &sz)) != SEOS_SUCCESS)
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
                                     &key.spec)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_generate() failed with %d", err);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = OS_CryptoKey_makePublic(&hPubKey, ssl->hCrypto, hPrvKey,
                                       &key.spec.key.attribs)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_makePublic() failed with %d", err);
        goto err0;
    }
    // Export public key
    if ((err = OS_CryptoKey_export(hPubKey, &key.data)) != SEOS_SUCCESS)
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
                                       algEx)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoAgreement_init() failed with %d", err);
        goto err1;
    }
    if ((err = OS_CryptoAgreement_agree(hAgree, ssl->handshake->hPubKey,
                                        ssl->handshake->premaster, &ssl->handshake->pmslen)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoAgreement_agree() failed with %d", err);
    }

    ret = 0;

    if ((err = OS_CryptoAgreement_free(hAgree)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoAgreement_free() failed with %d", err);
    }
err1:
    if ((err = OS_CryptoKey_free(hPubKey)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_free() failed with %d", err);
    }
err0:
    if ((err = OS_CryptoKey_free(hPrvKey)) != SEOS_SUCCESS)
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
crypto_parse_server_dh_params(
    mbedtls_ssl_context* ssl,
    unsigned char**      p,
    unsigned char*       end)
{
    seos_err_t err;
    OS_CryptoKey_Data_t keyData =
    {
        .type = OS_CryptoKey_TYPE_DH_PUB,
        .attribs.exportable = true
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
                                   &keyData)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_import() failed with %d", err);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    Debug_LOG_DEBUG("DH: shared P value");
    Debug_hexDump(Debug_LOG_LEVEL_DEBUG, dhPub->params.pBytes, dhPub->params.pLen );

    Debug_LOG_DEBUG("DH: shared G value");
    Debug_hexDump(Debug_LOG_LEVEL_DEBUG, dhPub->params.gBytes, dhPub->params.gLen );

    // Note: The view here is that the public param is "theirs", that is why here it
    // is called GY. We only have "our" keys (public / private), where we have the
    // secret param X and thus GX as name for the public value!
    Debug_LOG_DEBUG("DH: server's public G*y value");
    Debug_hexDump(Debug_LOG_LEVEL_DEBUG, dhPub->gxBytes, dhPub->gxLen );

    return ( 0 );
}

static int
export_key(
    mbedtls_pk_type_t    sig_alg,
    void*                pk_ctx,
    OS_CryptoKey_Data_t* keyData)
{
    int ret;

    keyData->attribs.exportable = true;
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
crypto_verify_hash_signature(
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
    seos_err_t err;
    OS_CryptoKey_Data_t keyData;
    OS_CryptoKey_Handle_t hPubKey;
    OS_CryptoSignature_Handle_t hSig;

    if ((ret = export_key(sig_type, pk_ctx, &keyData)) != 0)
    {
        Debug_LOG_ERROR("export_key() failed with %d", ret );
        return ret;
    }

    if ((err = OS_CryptoKey_import(&hPubKey, hCrypto,
                                   &keyData)) != SEOS_SUCCESS)
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
                                           hash_type)) != SEOS_SUCCESS)
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
                                         sig_len)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoSignature_verify() failed with %d", err);
        goto err1;
    }

    // No error, but still clean up signature and key!
    ret = 0;

err1:
    if ((err = OS_CryptoSignature_free(hSig)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoSignature_init() failed with %d", err);
    }
err0:
    if ((err = OS_CryptoKey_free(hPubKey)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_free() failed with %d", err);
    }

    return ret;
}

// ------------------------------- x509_crt.c ----------------------------------

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
    seos_err_t err;
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
    if ((err = OS_CryptoDigest_init(&hDigest, hCrypto, hash_alg)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_init() failed with %d", err);
        goto err0;
    }

    // We may need to process the certificate in blocks, as it may be too big for the
    // current limitation of the crypto api...
    cert_offs = 0;
    cert_left = cert_len;
    next_len  = cert_left > OS_Crypto_SIZE_DATAPORT ?
                OS_Crypto_SIZE_DATAPORT : cert_left;
    while (cert_left > 0)
    {
        if ((err = OS_CryptoDigest_process(hDigest, cert + cert_offs,
                                           next_len)) != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoDigest_process() failed with %d", err);
            goto err1;
        }
        cert_left -= next_len;
        cert_offs += next_len;
        next_len   = cert_left > OS_Crypto_SIZE_DATAPORT ?
                     OS_Crypto_SIZE_DATAPORT : cert_left;
    }

    if ((err = OS_CryptoDigest_finalize(hDigest, hash,
                                        hash_len)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_finalize() failed with %d", err);
        goto err1;
    }

    // It went all OK, so no error needed -- still we want to free the digest
    ret = 0;

err1:
    if ((err = OS_CryptoDigest_free(hDigest)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_free() failed with %d", err);
    }
err0:
    return ret;
}

int
crypto_verify_cert_signature(
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
    Debug_hexDump(Debug_LOG_LEVEL_DEBUG, hash, hash_size );

    return crypto_verify_hash_signature(hCrypto, pk_ctx, sig_type, hash_type,
                                        hash, hash_size, sig, sig_len);
}

// -------------------------------- ssl_tls.c ----------------------------------

int
crypto_tls_prf(
    mbedtls_ssl_context* ssl,
    const unsigned char* secret,
    size_t               slen,
    const char*          label,
    const unsigned char* random,
    size_t               rlen,
    unsigned char*       dstbuf,
    size_t               dlen)
{
    size_t nb, len;
    size_t i, j, k, md_len;
    unsigned char tmp[128];
    unsigned char h_i[MBEDTLS_MD_MAX_SIZE];
    seos_err_t err;
    OS_CryptoMac_Handle_t hMac;

    md_len = OS_CryptoMac_SIZE_HMAC_SHA256;
    if ( sizeof( tmp ) < md_len + strlen( label ) + rlen )
    {
        return ( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    nb = strlen( label );
    memcpy( tmp + md_len, label, nb );
    memcpy( tmp + md_len + nb, random, rlen );
    nb += rlen;

    /*
     * Compute P_<hash>(secret, label + random)[0..dlen]
     */
    if ((err = OS_CryptoMac_init(&hMac, ssl->hCrypto,
                                 OS_CryptoMac_ALG_HMAC_SHA256)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoMac_init() failed with %d", err);
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    len = sizeof(tmp);
    if ((err = OS_CryptoMac_start(hMac, secret, slen)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoMac_init() failed with %d", err);
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    if ((err = OS_CryptoMac_process(hMac, tmp + md_len,
                                    nb )) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoMac_init() failed with %d", err);
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    if ((err = OS_CryptoMac_finalize(hMac, tmp, &len )) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoMac_init() failed with %d", err);
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    for ( i = 0; i < dlen; i += md_len )
    {
        if ((err = OS_CryptoMac_start(hMac, secret, slen)) != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoMac_start() failed with %d", err);
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        if ((err = OS_CryptoMac_process(hMac, tmp,
                                        md_len + nb )) != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoMac_process() failed with %d", err);
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        if ((err = OS_CryptoMac_finalize(hMac, h_i, &len )) != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoMac_finalize() failed with %d", err);
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        if ((err = OS_CryptoMac_start(hMac, secret, slen)) != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoMac_init() failed with %d", err);
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        if ((err = OS_CryptoMac_process(hMac, tmp, md_len )) != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoMac_process() failed with %d", err);
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        if ((err = OS_CryptoMac_finalize(hMac, tmp, &len )) != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoMac_finalize() failed with %d", err);
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        k = ( i + md_len > dlen ) ? dlen % md_len : md_len;

        for ( j = 0; j < k; j++ )
        {
            dstbuf[i + j]  = h_i[j];
        }
    }

    mbedtls_platform_zeroize( tmp, sizeof( tmp ) );
    mbedtls_platform_zeroize( h_i, sizeof( h_i ) );

    OS_CryptoMac_free(hMac);

    return ( 0 );
}

void
crypto_calc_verify(
    mbedtls_ssl_context* ssl,
    unsigned char        hash[32])
{
    size_t len = 32;
    seos_err_t err;
    OS_CryptoDigest_Handle_t hDigest;

    if ((err = OS_CryptoDigest_init(&hDigest, ssl->hCrypto,
                                    OS_CryptoDigest_ALG_SHA256)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_init() failed with %d", err);
        return;
    }

    Debug_LOG_DEBUG("=> calc verify sha256");

    if ((err = OS_CryptoDigest_clone(hDigest,
                                     ssl->handshake->hSessHash)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_clone() failed with %d", err);
        goto out;
    }
    if ((err = OS_CryptoDigest_finalize(hDigest, hash,
                                        &len)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_finalize() failed with %d", err);
        goto out;
    }

    Debug_LOG_DEBUG("calculated verify result");
    Debug_hexDump(Debug_LOG_LEVEL_DEBUG, hash, 32 );

    Debug_LOG_DEBUG("<= calc verify");

out:
    if ((err = OS_CryptoDigest_free(hDigest)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_free() failed with %d", err);
    }
}

void
crypto_update_checksum(
    mbedtls_ssl_context* ssl,
    const unsigned char* buf,
    size_t               len)
{
    seos_err_t err;
    if ((err = OS_CryptoDigest_process(ssl->handshake->hSessHash,
                                       buf, len)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_process() failed with %d", err);
    }
}

void
crypto_calc_finished(
    mbedtls_ssl_context* ssl,
    unsigned char*       buf,
    int                  from)
{
    int len = 12;
    const char* sender;
    seos_err_t err;
    OS_CryptoDigest_Handle_t hDigest;
    unsigned char padbuf[32];
    size_t hashLen = sizeof(padbuf);

    mbedtls_ssl_session* session = ssl->session_negotiate;
    if ( !session )
    {
        session = ssl->session;
    }

    if ((err = OS_CryptoDigest_init(&hDigest, ssl->hCrypto,
                                    OS_CryptoDigest_ALG_SHA256)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_init() failed with %d", err);
        return;
    }

    Debug_LOG_DEBUG("=> calc finished tls sha256");

    if ((err = OS_CryptoDigest_clone(hDigest,
                                     ssl->handshake->hSessHash)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_clone() failed with %d", err);
        goto out;
    }

    sender = ( from == MBEDTLS_SSL_IS_CLIENT )
             ? "client finished"
             : "server finished";

    if ((err = OS_CryptoDigest_finalize(hDigest, padbuf,
                                        &hashLen)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_finalize() failed with %d", err);
        goto out;
    }

    ssl->handshake->tls_prf( ssl, session->master, 48, sender,
                             padbuf, 32, buf, len );

    Debug_LOG_DEBUG("calculated finished result");
    Debug_hexDump(Debug_LOG_LEVEL_DEBUG,  buf, len );

out:
    if ((err = OS_CryptoDigest_free(hDigest)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_free() failed with %d", err);
    }

    mbedtls_platform_zeroize(  padbuf, sizeof(  padbuf ) );

    Debug_LOG_DEBUG("<= calc finished");
}

static int
auth_encrypt(
    OS_Crypto_Handle_t    hCrypto,
    OS_CryptoKey_Handle_t hEncKey,
    const unsigned char*  iv,
    size_t                iv_len,
    const unsigned char*  ad,
    size_t                ad_len,
    const unsigned char*  input,
    size_t                ilen,
    unsigned char*        output,
    size_t*               olen,
    unsigned char*        tag,
    size_t                tag_len)
{
    seos_err_t err;
    int ret;
    OS_CryptoCipher_Handle_t hCipher;
    size_t tlen = tag_len;

    if ((err = OS_CryptoCipher_init(&hCipher, hCrypto, hEncKey,
                                    OS_CryptoCipher_ALG_AES_GCM_ENC,
                                    iv, iv_len)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_init() failed with %d", err);
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = OS_CryptoCipher_start(hCipher, ad,
                                     ad_len)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_start() failed with %d", err);
        goto err0;
    }

    if ((err = OS_CryptoCipher_process(hCipher, input, ilen, output,
                                       olen)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_process() failed with %d", err);
        goto err0;
    }

    if ((err = OS_CryptoCipher_finalize(hCipher, tag,
                                        &tlen)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_finalize() failed with %d", err);
        goto err0;
    }

    ret = 0;

err0:
    if ((err = OS_CryptoCipher_free(hCipher)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_free() failed with %d", err);
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return ret;
}

static int
auth_decrypt(
    OS_Crypto_Handle_t    hCrypto,
    OS_CryptoKey_Handle_t hDecKey,
    const unsigned char*  iv,
    size_t                iv_len,
    const unsigned char*  ad,
    size_t                ad_len,
    const unsigned char*  input,
    size_t                ilen,
    unsigned char*        output,
    size_t*               olen,
    unsigned char*        tag,
    size_t                tag_len)
{
    int ret;
    seos_err_t err;
    OS_CryptoCipher_Handle_t hCipher;
    size_t tlen = tag_len;

    if ((err = OS_CryptoCipher_init(&hCipher, hCrypto, hDecKey,
                                    OS_CryptoCipher_ALG_AES_GCM_DEC,
                                    iv, iv_len)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_init() failed with %d", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = OS_CryptoCipher_start(hCipher, ad, ad_len)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_start() failed with %d", err );
        goto err0;
    }

    if ((err = OS_CryptoCipher_process(hCipher, input, ilen, output,
                                       olen)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_process() failed with %d", err );
        goto err0;
    }

    if ((err = OS_CryptoCipher_finalize(hCipher, tag,
                                        &tlen)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_finalize() failed with %d", err );
        goto err0;
    }

    ret = 0;

err0:
    if ((err = OS_CryptoCipher_free(hCipher)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_free() failed with %d", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return ret;
}

int
crypto_import_aes_keys(
    OS_Crypto_Handle_t     hCrypto,
    OS_CryptoKey_Handle_t* hEncKey,
    OS_CryptoKey_Handle_t* hDecKey,
    const void*            enc_bytes,
    const void*            dec_bytes,
    size_t                 key_len)
{
    int ret;
    seos_err_t err;
    OS_CryptoKey_Data_t keyData =
    {
        .type               = OS_CryptoKey_TYPE_AES,
        .attribs.exportable = false,
        .data.aes.len       = key_len,
    };

    memcpy(keyData.data.aes.bytes, enc_bytes, key_len);
    if ((err = OS_CryptoKey_import(hEncKey, hCrypto, &keyData)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_import() failed with %d", err );
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;

    memcpy(keyData.data.aes.bytes, dec_bytes, key_len);
    if ((err = OS_CryptoKey_import(hDecKey, hCrypto, &keyData)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_import() failed with %d", err);
        goto err0;
    }

    return 0;

err0:
    if ((err = OS_CryptoKey_free(*hEncKey)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_free() failed with %d", err );
    }

    return ret;
}

inline static int
ssl_ep_len(
    void* x)
{
    // Only non-zero for DTLS
    return 0;
}

int
crypto_encrypt_buf(
    mbedtls_ssl_context* ssl)
{
    mbedtls_cipher_mode_t mode;

    Debug_LOG_DEBUG("=> encrypt buf");

    if ( ssl->session_out == NULL || ssl->transform_out == NULL )
    {
        Debug_LOG_ERROR("should never happen");
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_out->cipher_ctx_enc );

    Debug_LOG_DEBUG("before encrypt: output payload");
    Debug_hexDump(Debug_LOG_LEVEL_DEBUG,  ssl->out_msg, ssl->out_msglen );

    /*
     * Encrypt
     */
    if (mode == MBEDTLS_MODE_GCM )
    {
        int ret;
        size_t enc_msglen, olen;
        unsigned char* enc_msg;
        unsigned char add_data[13];
        unsigned char iv[12];
        mbedtls_ssl_transform* transform = ssl->transform_out;
        unsigned char taglen = transform->ciphersuite_info->flags &
                               MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;
        size_t explicit_ivlen = transform->ivlen - transform->fixed_ivlen;

        /*
         * Prepare additional authenticated data
         */
        memcpy( add_data, ssl->out_ctr, 8 );
        add_data[8]  = ssl->out_msgtype;
        mbedtls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                                   ssl->conf->transport, add_data + 9 );
        add_data[11] = ( ssl->out_msglen >> 8 ) & 0xFF;
        add_data[12] = ssl->out_msglen & 0xFF;

        Debug_LOG_DEBUG("additional data for AEAD");
        Debug_hexDump(Debug_LOG_LEVEL_DEBUG, add_data, 13 );

        /*
         * Generate IV
         */
        if ( transform->ivlen == 12 && transform->fixed_ivlen == 4 )
        {
            /* GCM and CCM: fixed || explicit (=seqnum) */
            memcpy( iv, transform->iv_enc, transform->fixed_ivlen );
            memcpy( iv + transform->fixed_ivlen, ssl->out_ctr, 8 );
            memcpy( ssl->out_iv, ssl->out_ctr, 8 );

        }
        else
        {
            Debug_LOG_ERROR("Invalid IV length");
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        Debug_LOG_DEBUG("IV used (internal)");
        Debug_hexDump(Debug_LOG_LEVEL_DEBUG, iv, transform->ivlen );

        Debug_LOG_DEBUG("IV used (transmitted)");
        Debug_hexDump(Debug_LOG_LEVEL_DEBUG, ssl->out_iv, explicit_ivlen );

        /*
         * Fix message length with added IV
         */
        enc_msg = ssl->out_msg;
        enc_msglen = ssl->out_msglen;
        ssl->out_msglen += explicit_ivlen;

        Debug_LOG_DEBUG("before encrypt: msglen = %d, "
                        "including 0 bytes of padding",
                        ssl->out_msglen);

        /*
         * Encrypt and authenticate
         */
        olen = enc_msglen;
        if ((ret = auth_encrypt(ssl->hCrypto, transform->hEncKey,
                                iv, transform->ivlen,
                                add_data, 13,
                                enc_msg, enc_msglen,
                                enc_msg, &olen,
                                enc_msg + enc_msglen, taglen ) ) != 0 )

        {
            Debug_LOG_ERROR("auth_encrypt() wailed with %d", ret );
            return ( ret );
        }

        if ( olen != enc_msglen )
        {
            Debug_LOG_ERROR("should never happen");
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        ssl->out_msglen += taglen;

        Debug_LOG_DEBUG("after encrypt: tag");
        Debug_hexDump(Debug_LOG_LEVEL_DEBUG, enc_msg + enc_msglen, taglen );
    }
    else
    {
        Debug_LOG_ERROR("Cipher mode not supported");
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    Debug_LOG_DEBUG("<= encrypt buf");

    return ( 0 );
}

int
crypto_decrypt_buf(
    mbedtls_ssl_context* ssl)
{
    mbedtls_cipher_mode_t mode;

    Debug_LOG_DEBUG("=> decrypt buf");

    if ( ssl->session_in == NULL || ssl->transform_in == NULL )
    {
        Debug_LOG_ERROR("should never happen");
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_in->cipher_ctx_dec );

    if ( ssl->in_msglen < ssl->transform_in->minlen )
    {
        Debug_LOG_ERROR("in_msglen (%d) < minlen (%d)",
                        ssl->in_msglen, ssl->transform_in->minlen);
        return ( MBEDTLS_ERR_SSL_INVALID_MAC );
    }

    if ( mode == MBEDTLS_MODE_GCM)
    {
        int ret;
        size_t dec_msglen, olen;
        unsigned char* dec_msg;
        unsigned char* dec_msg_result;
        unsigned char add_data[13];
        unsigned char iv[12];
        mbedtls_ssl_transform* transform = ssl->transform_in;
        unsigned char taglen = transform->ciphersuite_info->flags &
                               MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;
        size_t explicit_iv_len = transform->ivlen - transform->fixed_ivlen;

        /*
         * Compute and update sizes
         */
        if ( ssl->in_msglen < explicit_iv_len + taglen )
        {
            Debug_LOG_ERROR("msglen (%d) < explicit_iv_len (%d) + taglen (%d)",
                            ssl->in_msglen, explicit_iv_len, taglen);
            return ( MBEDTLS_ERR_SSL_INVALID_MAC );
        }
        dec_msglen = ssl->in_msglen - explicit_iv_len - taglen;

        dec_msg = ssl->in_msg;
        dec_msg_result = ssl->in_msg;
        ssl->in_msglen = dec_msglen;

        /*
         * Prepare additional authenticated data
         */
        memcpy( add_data, ssl->in_ctr, 8 );
        add_data[8]  = ssl->in_msgtype;
        mbedtls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                                   ssl->conf->transport, add_data + 9 );
        add_data[11] = ( ssl->in_msglen >> 8 ) & 0xFF;
        add_data[12] = ssl->in_msglen & 0xFF;

        Debug_LOG_DEBUG("additional data for AEAD");
        Debug_hexDump(Debug_LOG_LEVEL_DEBUG,  add_data, 13 );

        /*
         * Prepare IV
         */
        if ( transform->ivlen == 12 && transform->fixed_ivlen == 4 )
        {
            /* GCM and CCM: fixed || explicit (transmitted) */
            memcpy( iv, transform->iv_dec, transform->fixed_ivlen );
            memcpy( iv + transform->fixed_ivlen, ssl->in_iv, 8 );

        }
        else
        {
            Debug_LOG_ERROR("Invalid IV length");
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        Debug_LOG_DEBUG("IV used");
        Debug_hexDump(Debug_LOG_LEVEL_DEBUG, iv, transform->ivlen );

        Debug_LOG_DEBUG("TAG used");
        Debug_hexDump(Debug_LOG_LEVEL_DEBUG, dec_msg + dec_msglen, taglen );

        /*
         * Decrypt and authenticate
         */
        olen = dec_msglen;
        if ((ret = auth_decrypt(ssl->hCrypto, transform->hDecKey,
                                iv, transform->ivlen,
                                add_data, 13,
                                dec_msg, dec_msglen,
                                dec_msg_result, &olen,
                                dec_msg + dec_msglen, taglen ) ) != 0 )
        {
            Debug_LOG_ERROR( "auth_decrypt() failed with %d", ret );
            return ( ret );
        }

        if ( olen != dec_msglen )
        {
            Debug_LOG_ERROR("should never happen");
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
    {
        Debug_LOG_ERROR("Cipher mode not supported");
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if ( ssl->in_msglen == 0 )
    {
        if ( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3
             && ssl->in_msgtype != MBEDTLS_SSL_MSG_APPLICATION_DATA )
        {
            /* TLS v1.2 explicitly disallows zero-length messages which are not application data */
            Debug_LOG_ERROR("invalid zero-length message type: %d",
                            ssl->in_msgtype);
            return ( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

        ssl->nb_zero++;

        /*
         * Three or more empty messages may be a DoS attack
         * (excessive CPU consumption).
         */
        if ( ssl->nb_zero > 3 )
        {
            Debug_LOG_ERROR("received four consecutive empty "
                            "messages, possible DoS attack");
            return ( MBEDTLS_ERR_SSL_INVALID_MAC );
        }
    }
    else
    {
        ssl->nb_zero = 0;
    }

    unsigned char i;
    for ( i = 8; i > ssl_ep_len( ssl ); i-- )
        if ( ++ssl->in_ctr[i - 1] != 0 )
        {
            break;
        }

    /* The loop goes to its end iff the counter is wrapping */
    if ( i == ssl_ep_len( ssl ) )
    {
        Debug_LOG_ERROR("incoming message counter would wrap");
        return ( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
    }

    Debug_LOG_DEBUG("<= decrypt buf");

    return ( 0 );
}

#endif /* USE_OS_CRYPTO */