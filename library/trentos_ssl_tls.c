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
#include "mbedtls/trentos_ssl_tls.h"

#include <string.h>

int
trentos_ssl_tls_tls_prf(
    mbedtls_ssl_context* ssl,
    const unsigned char* secret,
    size_t               slen,
    const char*          label,
    const unsigned char* random,
    size_t               rlen,
    unsigned char*       dstbuf,
    size_t               dlen)
{
    int rc;
    size_t nb, len;
    size_t i, j, k, md_len;
    unsigned char tmp[128];
    unsigned char h_i[MBEDTLS_MD_MAX_SIZE];
    OS_Error_t err;
    OS_CryptoMac_Handle_t hMac;
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoKey_Data_t macKey =
    {
        .type = OS_CryptoKey_TYPE_MAC,
        .attribs.keepLocal = true
    };

    md_len = OS_CryptoMac_SIZE_HMAC_SHA256;
    if ( sizeof( tmp ) < md_len + strlen( label ) + rlen )
    {
        return ( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    nb = strlen( label );
    memcpy( tmp + md_len, label, nb );
    memcpy( tmp + md_len + nb, random, rlen );
    nb += rlen;

    // Create MAC key
    memcpy(macKey.data.mac.bytes, secret, slen);
    macKey.data.mac.len = slen;
    if ((err = OS_CryptoKey_import(&hKey, ssl->hCrypto, &macKey)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_import() failed with %d", err);
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    rc = MBEDTLS_ERR_SSL_INTERNAL_ERROR;

    /*
     * Compute P_<hash>(secret, label + random)[0..dlen]
     */
    if ((err = OS_CryptoMac_init(&hMac, ssl->hCrypto, hKey,
                                 OS_CryptoMac_ALG_HMAC_SHA256)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoMac_init() failed with %d", err);
        goto err0;
    }

    len = sizeof(tmp);
    if ((err = OS_CryptoMac_process(hMac, tmp + md_len,
                                    nb )) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoMac_process() failed with %d", err);
        goto err1;
    }
    if ((err = OS_CryptoMac_finalize(hMac, tmp, &len )) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoMac_finalize() failed with %d", err);
        goto err1;
    }

    for ( i = 0; i < dlen; i += md_len )
    {
        if ((err = OS_CryptoMac_process(hMac, tmp,
                                        md_len + nb )) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoMac_process() failed with %d", err);
            goto err1;
        }
        if ((err = OS_CryptoMac_finalize(hMac, h_i, &len )) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoMac_finalize() failed with %d", err);
            goto err1;
        }

        if ((err = OS_CryptoMac_process(hMac, tmp, md_len )) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoMac_process() failed with %d", err);
            goto err1;
        }
        if ((err = OS_CryptoMac_finalize(hMac, tmp, &len )) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_CryptoMac_finalize() failed with %d", err);
            goto err1;
        }

        k = ( i + md_len > dlen ) ? dlen % md_len : md_len;

        for ( j = 0; j < k; j++ )
        {
            dstbuf[i + j]  = h_i[j];
        }
    }

    // We left the loop properly, so all is good.
    rc = 0;

err1:
    if ((err = OS_CryptoMac_free(hMac)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoMac_free() failed with %d", err);
    }
err0:
    if ((err = OS_CryptoKey_free(hKey)) != OS_SUCCESS)
{
    Debug_LOG_ERROR("OS_CryptoKey_free() failed with %d", err);
    }

    mbedtls_platform_zeroize( tmp, sizeof( tmp ) );
    mbedtls_platform_zeroize( h_i, sizeof( h_i ) );

    return rc;
}

void
trentos_ssl_tls_calc_verify(
    mbedtls_ssl_context* ssl,
    unsigned char        hash[32])
{
    size_t len = 32;
    OS_Error_t err;
    OS_CryptoDigest_Handle_t hDigest;

    Debug_LOG_DEBUG("=> calc verify sha256");

    if ((err = OS_CryptoDigest_clone(&hDigest, ssl->hCrypto,
                                     ssl->handshake->hSessHash)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_clone() failed with %d", err);
        return;
    }
    if ((err = OS_CryptoDigest_finalize(hDigest, hash,
                                        &len)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_finalize() failed with %d", err);
        goto out;
    }

    Debug_LOG_DEBUG("calculated verify result");
    Debug_DUMP_DEBUG(hash, 32);

    Debug_LOG_DEBUG("<= calc verify");

out:
    if ((err = OS_CryptoDigest_free(hDigest)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_free() failed with %d", err);
    }
}

void
trentos_ssl_tls_update_checksum(
    mbedtls_ssl_context* ssl,
    const unsigned char* buf,
    size_t               len)
{
    OS_Error_t err;
    if ((err = OS_CryptoDigest_process(ssl->handshake->hSessHash,
                                       buf, len)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_process() failed with %d", err);
    }
}

void
trentos_ssl_tls_calc_finished(
    mbedtls_ssl_context* ssl,
    unsigned char*       buf,
    int                  from)
{
    int len = 12;
    const char* sender;
    OS_Error_t err;
    OS_CryptoDigest_Handle_t hDigest;
    unsigned char padbuf[32];
    size_t hashLen = sizeof(padbuf);

    mbedtls_ssl_session* session = ssl->session_negotiate;
    if ( !session )
    {
        session = ssl->session;
    }

    Debug_LOG_DEBUG("=> calc finished tls sha256");

    if ((err = OS_CryptoDigest_clone(&hDigest, ssl->hCrypto,
                                     ssl->handshake->hSessHash)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_clone() failed with %d", err);
        return;
    }

    sender = ( from == MBEDTLS_SSL_IS_CLIENT )
             ? "client finished"
             : "server finished";

    if ((err = OS_CryptoDigest_finalize(hDigest, padbuf,
                                        &hashLen)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoDigest_finalize() failed with %d", err);
        goto out;
    }

    ssl->handshake->tls_prf( ssl, session->master, 48, sender,
                             padbuf, 32, buf, len );

    Debug_LOG_DEBUG("calculated finished result");
    Debug_DUMP_DEBUG(buf, len);

out:
    if ((err = OS_CryptoDigest_free(hDigest)) != OS_SUCCESS)
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
    OS_Error_t err;
    int ret;
    OS_CryptoCipher_Handle_t hCipher;
    size_t tlen = tag_len;

    if ((err = OS_CryptoCipher_init(&hCipher, hCrypto, hEncKey,
                                    OS_CryptoCipher_ALG_AES_GCM_ENC,
                                    iv, iv_len)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_init() failed with %d", err);
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = OS_CryptoCipher_start(hCipher, ad,
                                     ad_len)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_start() failed with %d", err);
        goto err0;
    }

    if ((err = OS_CryptoCipher_process(hCipher, input, ilen, output,
                                       olen)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_process() failed with %d", err);
        goto err0;
    }

    if ((err = OS_CryptoCipher_finalize(hCipher, tag,
                                        &tlen)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_finalize() failed with %d", err);
        goto err0;
    }

    ret = 0;

err0:
    if ((err = OS_CryptoCipher_free(hCipher)) != OS_SUCCESS)
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
    OS_Error_t err;
    OS_CryptoCipher_Handle_t hCipher;
    size_t tlen = tag_len;

    if ((err = OS_CryptoCipher_init(&hCipher, hCrypto, hDecKey,
                                    OS_CryptoCipher_ALG_AES_GCM_DEC,
                                    iv, iv_len)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_init() failed with %d", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((err = OS_CryptoCipher_start(hCipher, ad, ad_len)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_start() failed with %d", err );
        goto err0;
    }

    if ((err = OS_CryptoCipher_process(hCipher, input, ilen, output,
                                       olen)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_process() failed with %d", err );
        goto err0;
    }

    if ((err = OS_CryptoCipher_finalize(hCipher, tag,
                                        &tlen)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_finalize() failed with %d", err );
        goto err0;
    }

    ret = 0;

err0:
    if ((err = OS_CryptoCipher_free(hCipher)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoCipher_free() failed with %d", err );
        return ( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return ret;
}

int
trentos_ssl_tls_import_aes_keys(
    OS_Crypto_Handle_t     hCrypto,
    OS_CryptoKey_Handle_t* hEncKey,
    OS_CryptoKey_Handle_t* hDecKey,
    const void*            enc_bytes,
    const void*            dec_bytes,
    size_t                 key_len)
{
    int ret;
    OS_Error_t err;
    OS_CryptoKey_Data_t keyData =
    {
        .type               = OS_CryptoKey_TYPE_AES,
        .attribs.keepLocal  = false,
        .data.aes.len       = key_len,
    };

    memcpy(keyData.data.aes.bytes, enc_bytes, key_len);
    if ((err = OS_CryptoKey_import(hEncKey, hCrypto, &keyData)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_import() failed with %d", err );
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;

    memcpy(keyData.data.aes.bytes, dec_bytes, key_len);
    if ((err = OS_CryptoKey_import(hDecKey, hCrypto, &keyData)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_import() failed with %d", err);
        goto err0;
    }

    return 0;

err0:
    if ((err = OS_CryptoKey_free(*hEncKey)) != OS_SUCCESS)
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
trentos_ssl_tls_encrypt_buf(
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
    Debug_DUMP_DEBUG(ssl->out_msg, ssl->out_msglen);

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
        Debug_DUMP_DEBUG(add_data, 13);

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
        Debug_DUMP_DEBUG(iv, transform->ivlen);

        Debug_LOG_DEBUG("IV used (transmitted)");
        Debug_DUMP_DEBUG(ssl->out_iv, explicit_ivlen);

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
        Debug_DUMP_DEBUG(enc_msg + enc_msglen, taglen);
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
trentos_ssl_tls_decrypt_buf(
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
        Debug_DUMP_DEBUG(add_data, 13);

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
        Debug_DUMP_DEBUG(iv, transform->ivlen);

        Debug_LOG_DEBUG("TAG used");
        Debug_DUMP_DEBUG(dec_msg + dec_msglen, taglen);

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