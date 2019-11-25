/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(USE_SEOS_CRYPTO)

#include "SeosCryptoApi.h"

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"

#include <string.h>

// ------------------------------- ssl_cli.c ----------------------------------

static uint16_t
read_curve_id(unsigned char**   p,
              unsigned char*    end)
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
read_curve_point(unsigned char**    p,
                 unsigned char*     end,
                 size_t             pLen,
                 void*              xBytes,
                 size_t*            xLen,
                 void*              yBytes,
                 size_t*            yLen)
{
    size_t n;
    int ret;

    // We must have at least two bytes (1 for length, at least one for data)
    if ( end - *p < 2 )
    {
        return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    n = ** p;
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
seos_parse_server_ecdh_params(mbedtls_ssl_context*  ssl,
                              unsigned char**       p,
                              unsigned char*        end)
{
    seos_err_t err;
    static SeosCryptoKey_Data keyData =
    {
        .type = SeosCryptoKey_Type_SECP256R1_PUB,
        .attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW
    };
    SeosCryptoKey_SECP256r1Pub* ecPub = &keyData.data.secp256r1.pub;

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
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Could not parse server ECDH curve id param") );
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA ;
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ECDH curve ID: %i",
                                ssl->handshake->ecdh.curveId ) );

    // Based on the curve_id, determine the size of the underlying prime. At this
    // point we only support one curve.
    switch (ssl->handshake->ecdh.curveId)
    {
    case 23: // secp256r1
        ssl->handshake->ecdh.primeLen = 32;
        break;
    default:
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Curve is not supported: %i",
                                    ssl->handshake->ecdh.curveId) );
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE ;
    }

    ecPub->qxLen = SeosCryptoKey_Size_ECC_MAX;
    ecPub->qyLen = SeosCryptoKey_Size_ECC_MAX;
    if (ecPub->qyLen < ssl->handshake->ecdh.primeLen
        || ecPub->qxLen < ssl->handshake->ecdh.primeLen)
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ("Buffer too small for ECDH curve point") );
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if (read_curve_point(p, end, ssl->handshake->ecdh.primeLen, ecPub->qxBytes,
                         &ecPub->qxLen, ecPub->qyBytes, &ecPub->qyLen))
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Could not parse server ECDH point param") );
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA ;
    }

    MBEDTLS_SSL_DEBUG_BUF(3, "ECDH x coord of server's point", ecPub->qxBytes,
                          ecPub->qxLen);
    MBEDTLS_SSL_DEBUG_BUF(3, "ECDH y coord of server's point", ecPub->qyBytes,
                          ecPub->qyLen);

    if ((err = SeosCryptoApi_keyImport(ssl->cryptoCtx, &ssl->handshake->pubKey,
                                       NULL, &keyData)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_keyImport" ), err );
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    return 0;
}

static int
write_ecdh_public_key(mbedtls_ssl_context*    ssl,
                      SeosCryptoKey_Data*     keyData,
                      unsigned char*          out_msg,
                      size_t*                 i,
                      size_t*                 n)
{
    size_t plen;
    SeosCryptoKey_SECP256r1Pub* ecPub = &keyData->data.secp256r1.pub;

    if (ssl->handshake->ecdh.pointFormat == MBEDTLS_ECP_PF_UNCOMPRESSED)
    {
        out_msg[5] = 0x04;
        memcpy(&out_msg[6], ecPub->qxBytes, ecPub->qxLen);
        memcpy(&out_msg[6 + ecPub->qxLen], ecPub->qyBytes, ecPub->qyLen);

        plen = ecPub->qxLen + ecPub->qyLen + 1;

        MBEDTLS_SSL_DEBUG_BUF(3, "ECDH: x coord of client's public point",
                              ecPub->qxBytes, ecPub->qxLen);
        MBEDTLS_SSL_DEBUG_BUF(3, "ECDH: y coord of client's public point",
                              ecPub->qyBytes, ecPub->qyLen);
    }
    else if (ssl->handshake->ecdh.pointFormat == MBEDTLS_ECP_PF_COMPRESSED)
    {
        // Compressed representation just needs the X coordinate and the SIGN
        // bit of the Y coord, so it can be recomputed from X via the curve
        // equation..
        out_msg[5] = 0x02 | (ecPub->qyBytes[0] & 0x01);
        memcpy(&out_msg[6], ecPub->qxBytes, ecPub->qxLen);

        plen = ecPub->qxLen + 1;

        MBEDTLS_SSL_DEBUG_BUF(3, "ECDH: x coord of client's public point (compressed)",
                              ecPub->qxBytes, ecPub->qxLen);
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported ECDH point format: %02x",
                                    ssl->handshake->ecdh.pointFormat ) );
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    out_msg[4] = plen;
    *i = 4;
    *n = plen + 1;

    return 0;
}

static int
write_dh_public_key(mbedtls_ssl_context*    ssl,
                    SeosCryptoKey_Data*     keyData,
                    unsigned char*          out_msg,
                    size_t*                 i,
                    size_t*                 n)
{
    SeosCryptoKey_DHPub* dhPub = &keyData->data.dh.pub;

    MBEDTLS_SSL_DEBUG_BUF(3, "DHM: GX ", dhPub->gxBytes, dhPub->gxLen);

    // Write public param back to server
    out_msg[4] = (unsigned char)( dhPub->params.pLen >> 8 );
    out_msg[5] = (unsigned char)( dhPub->params.pLen      );
    memcpy(&out_msg[6], dhPub->gxBytes, dhPub->params.pLen);

    *n = dhPub->params.pLen;
    *i = 6;

    return 0;
}

int
seos_exchange_key(mbedtls_ssl_context*          ssl,
                  mbedtls_key_exchange_type_t   ex_type,
                  size_t*                       i,
                  size_t*                       n)
{
    int ret;
    seos_err_t err;
    SeosCrypto_KeyHandle prvKey, pubKey;
    SeosCrypto_AgreementHandle keyEx;
    SeosCryptoAgreement_Algorithm algEx;
    static SeosCryptoKey_Data keyData;
    static SeosCryptoKey_Spec keySpec =
    {
        .key.attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW
    };

    // Set up the key generation spec for our private key
    if (MBEDTLS_KEY_EXCHANGE_DHE_RSA == ex_type)
    {
        // Extract public server params (P,G) from public key into generator spec
        size_t sz = sizeof(SeosCryptoKey_DHParams);
        if ((err = SeosCryptoApi_keyGetParams(ssl->cryptoCtx, ssl->handshake->pubKey,
                                              &keySpec.key.params.dh, &sz)) != SEOS_SUCCESS)
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_keyGetParams" ), err );
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        keySpec.type        = SeosCryptoKey_SpecType_PARAMS;
        keySpec.key.type    = SeosCryptoKey_Type_DH_PRV;
        algEx               = SeosCryptoAgreement_Algorithm_DH;
    }
    else if (MBEDTLS_KEY_EXCHANGE_ECDHE_RSA == ex_type)
    {
        // We only support one curve right now, so there is no need to extract
        // any params or anything of that sort..
        keySpec.type        = SeosCryptoKey_SpecType_BITS;
        keySpec.key.type    = SeosCryptoKey_Type_SECP256R1_PRV;
        algEx               = SeosCryptoAgreement_Algorithm_ECDH;
    }

    // Generate private key and make public key from it
    if ((err = SeosCryptoApi_keyGenerate(ssl->cryptoCtx, &prvKey,
                                         &keySpec)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_keyGenerate" ), err );
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = SeosCryptoApi_keyMakePublic(ssl->cryptoCtx, &pubKey, prvKey,
                                           &keySpec.key.attribs)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_keyMakePublic" ), err );
        goto err0;
    }
    // Export public key
    if ((err = SeosCryptoApi_keyExport(ssl->cryptoCtx, pubKey, NULL,
                                       &keyData)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_keyExport" ), err );
        goto err1;
    }

    // Write exported key data to TLS buffer
    if ( ( (MBEDTLS_KEY_EXCHANGE_DHE_RSA == ex_type) &&
           (ret = write_dh_public_key(ssl, &keyData, ssl->out_msg, i, n)) ) ||
         ( (MBEDTLS_KEY_EXCHANGE_ECDHE_RSA == ex_type) &&
           (ret = write_ecdh_public_key(ssl, &keyData, ssl->out_msg, i, n)) ) )
    {
        goto err1;
    }

    // Based on the newly derived private key of the CLIENT and the public key
    // of the server agree on a shared secret!
    ssl->handshake->pmslen = MBEDTLS_PREMASTER_SIZE;
    if ((err = SeosCryptoApi_agreementInit(ssl->cryptoCtx, &keyEx, algEx,
                                           prvKey)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_agreementInit" ), err );
        goto err1;
    }
    if ((err = SeosCryptoApi_agreementAgree(ssl->cryptoCtx, keyEx,
                                            ssl->handshake->pubKey,
                                            ssl->handshake->premaster, &ssl->handshake->pmslen)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_agreementAgree" ), err );
    }

    ret = 0;

    if ((err = SeosCryptoApi_agreementFree(ssl->cryptoCtx, keyEx)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_agreementFree" ), err );
    }
err1:
    if ((err = SeosCryptoApi_keyFree(ssl->cryptoCtx, pubKey)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_keyFree" ), err );
    }
err0:
    if ((err = SeosCryptoApi_keyFree(ssl->cryptoCtx, prvKey)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_keyFree" ), err );
    }
    return ret;
}

static size_t
read_bignum(unsigned char** p,
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
seos_parse_server_dh_params(mbedtls_ssl_context*    ssl,
                            unsigned char**         p,
                            unsigned char*          end)
{
    seos_err_t err;
    static SeosCryptoKey_Data keyData =
    {
        .type = SeosCryptoKey_Type_DH_PUB,
        .attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW
    };
    SeosCryptoKey_DHPub* dhPub = &keyData.data.dh.pub;

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
                                           SeosCryptoKey_Size_DH_MAX)) <= 0 ||
         (dhPub->params.gLen = read_bignum(p, end, dhPub->params.gBytes,
                                           SeosCryptoKey_Size_DH_MAX)) <= 0 ||
         (dhPub->gxLen       = read_bignum(p, end, dhPub->gxBytes,
                                           SeosCryptoKey_Size_DH_MAX)) <= 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Could not parse server DHM params") );
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA ;
    }

    if (dhPub->params.pLen * 8 < ssl->conf->dhm_min_bitlen)
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "DHM prime too short: %d < %d",
                                    dhPub->params.pLen * 8,
                                    ssl->conf->dhm_min_bitlen ) );
        return MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE;
    }

    if ((err = SeosCryptoApi_keyImport(ssl->cryptoCtx, &ssl->handshake->pubKey,
                                       NULL, &keyData)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "SeosCryptoApi_keyImport" ), err );
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "DHM: P ", dhPub->params.pBytes, dhPub->params.pLen );
    MBEDTLS_SSL_DEBUG_BUF( 3, "DHM: G ", dhPub->params.gBytes, dhPub->params.gLen );
    // Note: The view here is that the public param is "theirs", that is why here it
    // is called GY. We only have "our" keys (public / private), where we have the
    // secret param X and thus GX as name for the public value!
    MBEDTLS_SSL_DEBUG_BUF( 3, "DHM: GY", dhPub->gxBytes, dhPub->gxLen );

    return ( 0 );
}

static int
export_key(mbedtls_ssl_context*     ssl,
           mbedtls_pk_type_t        sig_alg,
           void*                    pk_ctx,
           SeosCryptoKey_Data*      keyData)
{
    int ret;

    keyData->attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW;
    switch (sig_alg)
    {
    case MBEDTLS_PK_RSA:
    {
        mbedtls_rsa_context* rsa_ctx = (mbedtls_rsa_context*) pk_ctx;
        SeosCryptoKey_RSAPub* pubKey = &keyData->data.rsa.pub;
        // Make sure we can actually handle the key
        if (rsa_ctx->len > SeosCryptoKey_Size_RSA_MAX)
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "RSA key size not supported: %i", rsa_ctx->len ) );
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        }
        // Transform the public key into a SeosCryptoKey_Data so we can use it
        // for our own purposes.
        keyData->type = SeosCryptoKey_Type_RSA_PUB;
        pubKey->nLen = rsa_ctx->len;
        pubKey->eLen = rsa_ctx->len;
        if ((ret = mbedtls_rsa_export_raw(pk_ctx, pubKey->nBytes, pubKey->nLen, NULL, 0,
                                          NULL, 0, NULL, 0, pubKey->eBytes, pubKey->eLen)) != 0)
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_rsa_export_raw", ret );
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        break;
    }
    default:
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported signature algorithm for cert: %i",
                                    sig_alg ) );
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    return 0;
}

int
seos_verify_hash_signature(mbedtls_ssl_context*     ssl,
                           void*                    pk_ctx,
                           mbedtls_pk_type_t        sig_type,
                           mbedtls_md_type_t        hash_type,
                           const void*              hash,
                           size_t                   hash_len,
                           const void*              sig,
                           size_t                   sig_len)
{
    int ret;
    seos_err_t err;
    SeosCryptoKey_Data keyData;
    SeosCrypto_KeyHandle pubKey;
    SeosCrypto_SignatureHandle sigHandle;

    if ((ret = export_key(ssl, sig_type, pk_ctx, &keyData)) != 0)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "export_key", ret );
        return ret;
    }

    if ((err = SeosCryptoApi_keyImport(ssl->cryptoCtx, &pubKey, NULL,
                                       &keyData)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_keyImport", err );
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    switch (keyData.type)
    {
    case SeosCryptoKey_Type_RSA_PUB:
        if ((err = SeosCryptoApi_signatureInit(ssl->cryptoCtx, &sigHandle,
                                               SeosCryptoSignature_Algorithm_RSA_PKCS1_V15,
                                               hash_type, NULL, pubKey)) != SEOS_SUCCESS)
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_signatureInit", err );
            goto err0;
        }
        break;
    default:
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported key extracted from cert: %i",
                                    keyData.type ) );
        goto err0;
    }

    if ((err = SeosCryptoApi_signatureVerify(ssl->cryptoCtx, sigHandle, hash,
                                             hash_len, sig, sig_len)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_signatureVerify", err );
        goto err1;
    }

    // No error, but still clean up signature and key!
    ret = 0;

err1:
    if ((err = SeosCryptoApi_signatureFree(ssl->cryptoCtx,
                                           sigHandle)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_signatureInit", err );
    }
err0:
    if ((err = SeosCryptoApi_keyFree(ssl->cryptoCtx, pubKey)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_keyFree", err );
    }

    return ret;
}

// ------------------------------- x509_crt.c ----------------------------------

static int
hash_cert(mbedtls_ssl_context*  ssl,
          mbedtls_md_type_t     hash_alg,
          const void*           cert,
          const size_t          cert_len,
          void*                 hash,
          size_t*               hash_len)
{
    int ret;
    seos_err_t err;
    SeosCrypto_DigestHandle digHandle;
    size_t cert_offs, cert_left, next_len;

    switch (hash_alg)
    {
    // The mbedTLS hash identifiers and the SeosCryptoDigest_Algorithms are
    // identical so we can simply use those
    case MBEDTLS_MD_MD5:
    case MBEDTLS_MD_SHA256:
        break;
    default:
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported digest algorithm for cert: %i",
                                    hash_alg ) );
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = SeosCryptoApi_digestInit(ssl->cryptoCtx, &digHandle,
                                        hash_alg)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestInit", err );
        goto err0;
    }

    // We may need to process the certificate in blocks, as it may be too big for the
    // current limitation of the crypto api...
    cert_offs = 0;
    cert_left = cert_len;
    next_len  = cert_left > SeosCrypto_Size_DATAPORT ?
                SeosCrypto_Size_DATAPORT : cert_left;
    while (cert_left > 0)
    {
        if ((err = SeosCryptoApi_digestProcess(ssl->cryptoCtx, digHandle,
                                               cert + cert_offs, next_len)) != SEOS_SUCCESS)
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestProcess", err );
            goto err1;
        }
        cert_left -= next_len;
        cert_offs += next_len;
        next_len   = cert_left > SeosCrypto_Size_DATAPORT ?
                     SeosCrypto_Size_DATAPORT : cert_left;
    }

    if ((err = SeosCryptoApi_digestFinalize(ssl->cryptoCtx, digHandle, hash,
                                            hash_len)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestFinalize", err );
        goto err1;
    }

    // It went all OK, so no error needed -- still we want to free the digest
    ret = 0;

err1:
    if ((err = SeosCryptoApi_digestFree(ssl->cryptoCtx,
                                        digHandle)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestFree", err );
    }
err0:
    return ret;
}

int
seos_verify_cert_signature(mbedtls_ssl_context*   ssl,
                           void*                  pk_ctx,
                           mbedtls_pk_type_t      sig_type,
                           mbedtls_md_type_t      hash_type,
                           const void*            cert,
                           size_t                 cert_len,
                           const void*            sig,
                           size_t                 sig_len)
{
    int ret;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    size_t hash_size = sizeof(hash);

    if ((ret = hash_cert(ssl, hash_type, cert, cert_len, hash, &hash_size)) != 0)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "hash_cert", ret );
        return ret;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "hash of cert", hash, hash_size );

    return seos_verify_hash_signature(ssl, pk_ctx, sig_type, hash_type, hash,
                                      hash_size, sig, sig_len);
}

// -------------------------------- ssl_tls.c ----------------------------------

int
seos_tls_prf(mbedtls_ssl_context*       ssl,
             const unsigned char*       secret,
             size_t                     slen,
             const char*                label,
             const unsigned char*       random,
             size_t                     rlen,
             unsigned char*             dstbuf,
             size_t                     dlen)
{
    size_t nb, len;
    size_t i, j, k, md_len;
    unsigned char tmp[128];
    unsigned char h_i[MBEDTLS_MD_MAX_SIZE];
    seos_err_t err;
    SeosCrypto_MacHandle macHandle;

    md_len = SeosCryptoMac_Size_HMAC_SHA256;
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
    if ((err = SeosCryptoApi_macInit(ssl->cryptoCtx, &macHandle,
                                     SeosCryptoMac_Algorithm_HMAC_SHA256)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_macInit", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    len = sizeof(tmp);
    if ((err = SeosCryptoApi_macStart(ssl->cryptoCtx, macHandle, secret,
                                      slen)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_macInit", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    if ((err = SeosCryptoApi_macProcess(ssl->cryptoCtx, macHandle, tmp + md_len,
                                        nb )) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_macInit", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    if ((err = SeosCryptoApi_macFinalize(ssl->cryptoCtx, macHandle, tmp,
                                         &len )) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_macInit", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    for ( i = 0; i < dlen; i += md_len )
    {
        if ((err = SeosCryptoApi_macStart(ssl->cryptoCtx, macHandle, secret,
                                          slen)) != SEOS_SUCCESS)
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_macStart", err );
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        if ((err = SeosCryptoApi_macProcess(ssl->cryptoCtx, macHandle, tmp,
                                            md_len + nb )) != SEOS_SUCCESS)
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_macProcess", err );
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        if ((err = SeosCryptoApi_macFinalize(ssl->cryptoCtx, macHandle, h_i,
                                             &len )) != SEOS_SUCCESS)
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_macFinalize", err );
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        if ((err = SeosCryptoApi_macStart(ssl->cryptoCtx, macHandle, secret,
                                          slen)) != SEOS_SUCCESS)
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_macInit", err );
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        if ((err = SeosCryptoApi_macProcess(ssl->cryptoCtx, macHandle, tmp,
                                            md_len )) != SEOS_SUCCESS)
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_macProcess", err );
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        if ((err = SeosCryptoApi_macFinalize(ssl->cryptoCtx, macHandle, tmp,
                                             &len )) != SEOS_SUCCESS)
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_macFinalize", err );
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

    SeosCryptoApi_macFree(ssl->cryptoCtx, macHandle);

    return ( 0 );
}

void
seos_calc_verify(mbedtls_ssl_context*   ssl,
                 unsigned char          hash[32])
{
    size_t len = 32;
    seos_err_t err;
    SeosCrypto_DigestHandle sha256Handle;

    if ((err = SeosCryptoApi_digestInit(ssl->cryptoCtx, &sha256Handle,
                                        SeosCryptoDigest_Algorithm_SHA256)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestInit", err );
        return;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> calc verify sha256" ) );

    if ((err = SeosCryptoApi_digestClone(ssl->cryptoCtx, sha256Handle,
                                         ssl->handshake->sessionHash)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestClone", err );
        goto out;
    }
    if ((err = SeosCryptoApi_digestFinalize(ssl->cryptoCtx, sha256Handle, hash,
                                            &len)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestFinalize", err );
        goto out;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "calculated verify result", hash, 32 );
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= calc verify" ) );

out:
    if ((err = SeosCryptoApi_digestFree(ssl->cryptoCtx,
                                        sha256Handle)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestFree", err );
    }
}

void
seos_update_checksum(mbedtls_ssl_context*   ssl,
                     const unsigned char*   buf,
                     size_t                 len)
{
    seos_err_t err;
    if ((err = SeosCryptoApi_digestProcess(ssl->cryptoCtx,
                                           ssl->handshake->sessionHash,
                                           buf, len)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestProcess", err );
    }
}

void
seos_calc_finished(mbedtls_ssl_context*    ssl,
                   unsigned char*          buf,
                   int                     from)
{
    int len = 12;
    const char* sender;
    seos_err_t err;
    SeosCrypto_DigestHandle sha256Handle;
    unsigned char padbuf[32];
    size_t hashLen = sizeof(padbuf);

    mbedtls_ssl_session* session = ssl->session_negotiate;
    if ( !session )
    {
        session = ssl->session;
    }

    if ((err = SeosCryptoApi_digestInit(ssl->cryptoCtx, &sha256Handle,
                                        SeosCryptoDigest_Algorithm_SHA256)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestInit", err );
        return;
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> calc finished tls sha256" ) );

    if ((err = SeosCryptoApi_digestClone(ssl->cryptoCtx, sha256Handle,
                                         ssl->handshake->sessionHash)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestClone", err );
        goto out;
    }

    sender = ( from == MBEDTLS_SSL_IS_CLIENT )
             ? "client finished"
             : "server finished";

    if ((err = SeosCryptoApi_digestFinalize(ssl->cryptoCtx, sha256Handle, padbuf,
                                            &hashLen)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestFinalize", err );
        goto out;
    }

    ssl->handshake->tls_prf( ssl, session->master, 48, sender,
                             padbuf, 32, buf, len );

    MBEDTLS_SSL_DEBUG_BUF( 3, "calc finished result", buf, len );

out:
    if ((err = SeosCryptoApi_digestFree(ssl->cryptoCtx,
                                        sha256Handle)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_digestFree", err );
    }

    mbedtls_platform_zeroize(  padbuf, sizeof(  padbuf ) );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= calc finished" ) );
}

static int
auth_encrypt(mbedtls_ssl_context*      ssl,
             SeosCrypto_KeyHandle      encKey,
             const unsigned char*      iv,
             size_t                    iv_len,
             const unsigned char*      ad,
             size_t                    ad_len,
             const unsigned char*      input,
             size_t                    ilen,
             unsigned char*            output,
             size_t*                   olen,
             unsigned char*            tag,
             size_t                    tag_len)
{
    seos_err_t err;
    int ret;
    SeosCrypto_CipherHandle seosCipher;
    size_t tlen = tag_len;

    if ((err = SeosCryptoApi_cipherInit(ssl->cryptoCtx, &seosCipher,
                                        SeosCryptoCipher_Algorithm_AES_GCM_ENC, encKey,
                                        iv, iv_len)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_cipherInit", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = SeosCryptoApi_cipherStart(ssl->cryptoCtx, seosCipher,
                                         ad, ad_len)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_cipherStart", err );
        goto err0;
    }

    if ((err = SeosCryptoApi_cipherProcess(ssl->cryptoCtx, seosCipher,
                                           input, ilen, output, olen)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_cipherProcess", err );
        goto err0;
    }

    if ((err = SeosCryptoApi_cipherFinalize(ssl->cryptoCtx, seosCipher,
                                            tag, &tlen)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_cipherFinalize", err );
        goto err0;
    }

    ret = 0;

err0:
    if ((err = SeosCryptoApi_cipherFree(ssl->cryptoCtx,
                                        seosCipher)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_cipherFree", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return ret;
}

static int
auth_decrypt(mbedtls_ssl_context*      ssl,
             SeosCrypto_KeyHandle      decKey,
             const unsigned char*      iv,
             size_t                    iv_len,
             const unsigned char*      ad,
             size_t                    ad_len,
             const unsigned char*      input,
             size_t                    ilen,
             unsigned char*            output,
             size_t*                   olen,
             unsigned char*            tag,
             size_t                    tag_len)
{
    int ret;
    seos_err_t err;
    SeosCrypto_CipherHandle seosCipher;
    size_t tlen = tag_len;

    if ((err = SeosCryptoApi_cipherInit(ssl->cryptoCtx, &seosCipher,
                                        SeosCryptoCipher_Algorithm_AES_GCM_DEC, decKey,
                                        iv, iv_len)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_cipherInit", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = SeosCryptoApi_cipherStart(ssl->cryptoCtx, seosCipher,
                                         ad, ad_len)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_cipherStart", err );
        goto err0;
    }

    if ((err = SeosCryptoApi_cipherProcess(ssl->cryptoCtx, seosCipher,
                                           input, ilen, output, olen)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_cipherProcess", err );
        goto err0;
    }

    if ((err = SeosCryptoApi_cipherFinalize(ssl->cryptoCtx, seosCipher,
                                            tag, &tlen)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_cipherFinalize", err );
        goto err0;
    }

    ret = 0;

err0:
    if ((err = SeosCryptoApi_cipherFree(ssl->cryptoCtx,
                                        seosCipher)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_cipherFree", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return ret;
}

int
seos_import_aes_keys(mbedtls_ssl_context*       ssl,
                     SeosCrypto_KeyHandle*      encKey,
                     SeosCrypto_KeyHandle*      decKey,
                     const void*                enc_bytes,
                     const void*                dec_bytes,
                     size_t                     key_len)
{
    int ret;
    seos_err_t err;
    SeosCryptoKey_Data keyData =
    {
        .type           = SeosCryptoKey_Type_AES,
        .attribs.flags  = SeosCryptoKey_Flags_NONE,
        .data.aes.len   = key_len,
    };

    memcpy(keyData.data.aes.bytes, enc_bytes, key_len);
    if ((err = SeosCryptoApi_keyImport(ssl->cryptoCtx, encKey, NULL,
                                       &keyData)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_keyImport", err );
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;

    memcpy(keyData.data.aes.bytes, dec_bytes, key_len);
    if ((err = SeosCryptoApi_keyImport(ssl->cryptoCtx, decKey, NULL,
                                       &keyData)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_keyImport", err );
        goto err0;
    }

    return 0;

err0:
    if ((err = SeosCryptoApi_keyFree(ssl->cryptoCtx, *encKey)) != SEOS_SUCCESS)
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "SeosCryptoApi_keyFree", err );
    }
    *encKey = NULL;
    *decKey = NULL;

    return ret;
}

inline static int
ssl_ep_len(void* x)
{
    // Only non-zero for DTLS
    return 0;
}

int
seos_encrypt_buf(mbedtls_ssl_context* ssl)
{
    mbedtls_cipher_mode_t mode;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> encrypt buf" ) );

    if ( ssl->session_out == NULL || ssl->transform_out == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_out->cipher_ctx_enc );

    MBEDTLS_SSL_DEBUG_BUF( 4, "before encrypt: output payload",
                           ssl->out_msg, ssl->out_msglen );

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

        MBEDTLS_SSL_DEBUG_BUF( 4, "additional data for AEAD", add_data, 13 );

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
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Invalid IV length" ) );
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "IV used (internal)",
                               iv, transform->ivlen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "IV used (transmitted)",
                               ssl->out_iv, explicit_ivlen );

        /*
         * Fix message length with added IV
         */
        enc_msg = ssl->out_msg;
        enc_msglen = ssl->out_msglen;
        ssl->out_msglen += explicit_ivlen;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                                    "including 0 bytes of padding",
                                    ssl->out_msglen ) );

        /*
         * Encrypt and authenticate
         */
        olen = enc_msglen;
        if ((ret = auth_encrypt(ssl, transform->encKey,
                                iv, transform->ivlen,
                                add_data, 13,
                                enc_msg, enc_msglen,
                                enc_msg, &olen,
                                enc_msg + enc_msglen, taglen ) ) != 0 )

        {
            MBEDTLS_SSL_DEBUG_RET( 1, "auth_encrypt", ret );
            return ( ret );
        }

        if ( olen != enc_msglen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        ssl->out_msglen += taglen;

        MBEDTLS_SSL_DEBUG_BUF( 4, "after encrypt: tag", enc_msg + enc_msglen, taglen );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Cipher mode not supported" ) );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= encrypt buf" ) );

    return ( 0 );
}

int
seos_decrypt_buf(mbedtls_ssl_context* ssl)
{
    mbedtls_cipher_mode_t mode;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> decrypt buf" ) );

    if ( ssl->session_in == NULL || ssl->transform_in == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_in->cipher_ctx_dec );

    if ( ssl->in_msglen < ssl->transform_in->minlen )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "in_msglen (%d) < minlen (%d)",
                                    ssl->in_msglen, ssl->transform_in->minlen ) );
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
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < explicit_iv_len (%d) "
                                        "+ taglen (%d)", ssl->in_msglen,
                                        explicit_iv_len, taglen ) );
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

        MBEDTLS_SSL_DEBUG_BUF( 4, "additional data for AEAD", add_data, 13 );

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
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Invalid IV length" ) );
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "IV used", iv, transform->ivlen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "TAG used", dec_msg + dec_msglen, taglen );

        /*
         * Decrypt and authenticate
         */
        olen = dec_msglen;
        if ((ret = auth_decrypt(ssl, transform->decKey,
                                iv, transform->ivlen,
                                add_data, 13,
                                dec_msg, dec_msglen,
                                dec_msg_result, &olen,
                                dec_msg + dec_msglen, taglen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "auth_decrypt", ret );
            return ( ret );
        }

        if ( olen != dec_msglen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Cipher mode not supported" ) );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if ( ssl->in_msglen == 0 )
    {
        if ( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3
             && ssl->in_msgtype != MBEDTLS_SSL_MSG_APPLICATION_DATA )
        {
            /* TLS v1.2 explicitly disallows zero-length messages which are not application data */
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid zero-length message type: %d",
                                        ssl->in_msgtype ) );
            return ( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

        ssl->nb_zero++;

        /*
         * Three or more empty messages may be a DoS attack
         * (excessive CPU consumption).
         */
        if ( ssl->nb_zero > 3 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "received four consecutive empty "
                                        "messages, possible DoS attack" ) );
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
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "incoming message counter would wrap" ) );
        return ( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= decrypt buf" ) );

    return ( 0 );
}

#endif /* USE_SEOS_CRYPTO */