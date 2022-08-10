#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/kdf.h>
#include <openssl/x509.h>
#include <openssl/core.h>
#include <openssl/core_names.h>

#include "tls.h"
#include "buffer.h"
#include "util.h"

int
tls_pseudo_random_func(const unsigned char *sec, size_t slen,
                       const void *seed1, size_t seed1_len,
                       const void *seed2, size_t seed2_len,
                       const void *seed3, size_t seed3_len,
                       const void *seed4, size_t seed4_len,
                       const void *seed5, size_t seed5_len,
                       unsigned char *out, size_t olen)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[8];

    kdf = EVP_KDF_fetch(NULL, "TLS1-PRF", NULL);
    if (!kdf) {
        return -1;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        return -1;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA2-256", strlen("SHA2-256"));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (unsigned char *)sec, slen);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)seed1, seed1_len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)seed2, seed2_len);
    params[4] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)seed3, seed3_len);
    params[5] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)seed4, seed4_len);
    params[6] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)seed5, seed5_len);
    params[7] = OSSL_PARAM_construct_end();
    if (!EVP_KDF_derive(kctx, out, olen, params)) {
        fprintf(stderr, "EVP_KDF_derive: failure\n");
        EVP_KDF_CTX_free(kctx);
        return -1;
    }
    EVP_KDF_CTX_free(kctx);
    return 0;
}

ssize_t
tls_encrypted_pre_master_secret(struct tls_context *ctx, uint8_t *dst, size_t size)
{
    struct tls_cert_entry *cert;
    const unsigned char *p;
    X509 *x;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx;
    size_t outlen;
    
    cert = ctx->certs;
    p = cert->data;

    x = d2i_X509(NULL, &p, cert->len);
    if (!x) {
        return -1;
    }
    if (X509_check_purpose(x, X509_PURPOSE_SSL_SERVER, 0) <= 0) {
        return -1;
    }
    pkey = X509_get0_pubkey(x);
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (EVP_PKEY_encrypt_init(pctx) <= 0) {
        return -1;
    }
    if (EVP_PKEY_encrypt(pctx, NULL, &outlen, ctx->rsa_pre_master_secret, sizeof(ctx->rsa_pre_master_secret)) <= 0) {
        fprintf(stderr, "err2\n");
        return -1;
    }
    if (size < outlen) {
        fprintf(stderr, "too short\n");
        return -1;
    }
    if (EVP_PKEY_encrypt(pctx, dst, &outlen, ctx->rsa_pre_master_secret, sizeof(ctx->rsa_pre_master_secret)) <= 0) {
        fprintf(stderr, "err3\n");
        return -1;
    }
    fprintf(stderr, "encrypted pre master secret: %lu\n", outlen);
    hexdump(stderr, dst, outlen);

    X509_free(x);

    return outlen;
}

int
tls_extract_key_block(struct tls_context *ctx)
{
    char *label;

    fprintf(stderr, "client random: \n");
    hexdump(stderr, ctx->data[CLIENT].random, sizeof(ctx->data[CLIENT].random));
    fprintf(stderr, "server random: \n");
    hexdump(stderr, ctx->data[SERVER].random, sizeof(ctx->data[SERVER].random));

    label = "master secret";
    tls_pseudo_random_func(ctx->rsa_pre_master_secret, sizeof(ctx->rsa_pre_master_secret),
                           label, strlen(label),
                           ctx->data[CLIENT].random, sizeof(ctx->data[CLIENT].random),
                           ctx->data[SERVER].random, sizeof(ctx->data[SERVER].random),
                           NULL, 0,
                           NULL, 0,
                           ctx->rsa_master_secret, sizeof(ctx->rsa_master_secret));
    fprintf(stderr, "rsa_master_secret: \n");
    hexdump(stderr, ctx->rsa_master_secret, sizeof(ctx->rsa_master_secret));

    // generate key block
    uint8_t key_block[40];
    label = "key expansion";
    tls_pseudo_random_func(ctx->rsa_master_secret, sizeof(ctx->rsa_master_secret),
                           label, strlen(label),
                           ctx->data[SERVER].random, sizeof(ctx->data[SERVER].random),
                           ctx->data[CLIENT].random, sizeof(ctx->data[CLIENT].random),
                           NULL, 0,
                           NULL, 0,
                           key_block, sizeof(key_block));
    fprintf(stderr, "key_block: \n");
    hexdump(stderr, key_block, sizeof(key_block));

    // extract keys
    struct buffer *tmp = buffer_create(key_block, sizeof(key_block), 0);
    buffer_read(tmp, ctx->data[CLIENT].write_key, sizeof(ctx->data[CLIENT].write_key));
    buffer_read(tmp, ctx->data[SERVER].write_key, sizeof(ctx->data[SERVER].write_key));
    buffer_read(tmp, ctx->data[CLIENT].write_iv, sizeof(ctx->data[CLIENT].write_iv));
    buffer_read(tmp, ctx->data[SERVER].write_iv, sizeof(ctx->data[SERVER].write_iv));

    fprintf(stderr, "client write_iv: \n");
    hexdump(stderr, ctx->data[CLIENT].write_iv, sizeof(ctx->data[CLIENT].write_iv));
    fprintf(stderr, "server write_iv: \n");
    hexdump(stderr, ctx->data[SERVER].write_iv, sizeof(ctx->data[SERVER].write_iv));

    return 0;
}