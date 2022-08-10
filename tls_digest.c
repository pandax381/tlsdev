#include <stdio.h>

#include <openssl/evp.h>

#include "tls.h"

int
tls_digest_init(struct tls_digest *digest)
{
    digest->ctx = EVP_MD_CTX_new();
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    EVP_DigestInit_ex(digest->ctx, md, NULL);
    return 0;
}

int
tls_digest_update(struct tls_digest *digest, const void *data, size_t len)
{
    return EVP_DigestUpdate(digest->ctx, data, len);
}

int
tls_digest_calc(struct tls_digest *digest, unsigned char *dst, unsigned int *len)
{
    EVP_MD_CTX *tmp = EVP_MD_CTX_new();
    EVP_MD_CTX_copy_ex(tmp, digest->ctx);
    EVP_DigestFinal_ex(tmp, dst, len);
    EVP_MD_CTX_destroy(tmp);
    return 0;
}

int
tls_digest_final(struct tls_digest *digest, unsigned char *dst, unsigned int *len)
{
    EVP_DigestFinal_ex(digest->ctx, dst, len);
    EVP_MD_CTX_destroy(digest->ctx);
    digest->ctx = NULL;
    return 0;
}

int
tls_digest_is_available(struct tls_digest *digest)
{
    return digest->ctx ? 1 : 0;
}