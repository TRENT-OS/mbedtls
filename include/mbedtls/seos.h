/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#ifndef MBEDTLS_SEOS_H
#define MBEDTLS_SEOS_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(USE_SEOS_CRYPTO)

#include "mbedtls/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

// ------------------------------- ssl_cli.c ----------------------------------

int
seos_parse_server_ecdh_params(mbedtls_ssl_context*  ssl,
                              unsigned char**       p,
                              unsigned char*        end);

int
seos_parse_server_dh_params(mbedtls_ssl_context*    ssl,
                            unsigned char**         p,
                            unsigned char*          end);

int
seos_exchange_key(mbedtls_ssl_context*          ssl,
                  mbedtls_key_exchange_type_t   ex_type,
                  size_t*                       i,
                  size_t*                       n);

// ------------------------------- x509_crt.c ----------------------------------

int
seos_check_signature(mbedtls_ssl_context*   ssl,
                     void*                  pk_ctx,
                     mbedtls_pk_type_t      sig_type,
                     mbedtls_md_type_t      hash_type,
                     const void*            cert,
                     size_t                 cert_len,
                     const void*            sig,
                     size_t                 sig_len);

// -------------------------------- ssl_tls.c ----------------------------------

int
seos_tls_prf(mbedtls_ssl_context*       ssl,
             const unsigned char*       secret,
             size_t                     slen,
             const char*                label,
             const unsigned char*       random,
             size_t                     rlen,
             unsigned char*             dstbuf,
             size_t                     dlen);

void
seos_calc_verify(mbedtls_ssl_context*   ssl,
                 unsigned char          hash[32]);

void
seos_update_checksum(mbedtls_ssl_context*   ssl,
                     const unsigned char*   buf,
                     size_t                 len);

void
seos_calc_finished(mbedtls_ssl_context*    ssl,
                   unsigned char*          buf,
                   int                     from);

int
seos_import_aes_keys(mbedtls_ssl_context*       ssl,
                     SeosCrypto_KeyHandle*      encKey,
                     SeosCrypto_KeyHandle*      decKey,
                     const void*                enc_bytes,
                     const void*                dec_bytes,
                     size_t                     key_len);

int
seos_decrypt_buf(mbedtls_ssl_context* ssl);

int
seos_encrypt_buf(mbedtls_ssl_context* ssl);

#ifdef __cplusplus
}
#endif

#endif /* USE_SEOS_CRYPTO */
#endif /* MBEDTLS_SEOS_H */
