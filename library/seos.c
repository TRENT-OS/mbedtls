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
#include "mbedtls/platform_util.h"

#include <string.h>

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