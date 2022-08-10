#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core.h>
#include <openssl/core_names.h>

#include "tls.h"
#include "buffer.h"
#include "util.h"

int
tls_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *aad, int aad_len,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    /* Get the tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int
tls_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int success;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) ) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    success = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (!success) {
        return -1;
    }
    plaintext_len += len;
    return plaintext_len;
}

int
tls_encrypt_record(struct tls_context *ctx, uint8_t type, const uint8_t *data, size_t len, uint8_t *nonce, uint8_t *encrypted, uint8_t *tag)
{
    uint8_t iv[12];
    struct buffer *aad;
    int encrypted_len;

    fprintf(stderr, "in: %lu bytes\n", len);
    hexdump(stderr, data, len);
    memcpy(iv, ctx->data[CLIENT].write_iv, sizeof(ctx->data[CLIENT].write_iv));
    memcpy(iv + sizeof(ctx->data[CLIENT].write_iv), nonce, sizeof(nonce));
    fprintf(stderr, "iv: %lu bytes\n", sizeof(iv));
    hexdump(stderr, iv, sizeof(iv));
    aad = buffer_create(NULL, 0, 128);
    if (!aad) {
        return -1;
    }
    buffer_write_be64(aad, ctx->data[CLIENT].seq++);
    buffer_write_u8(aad, type);
    buffer_write_be16(aad, ctx->version);
    buffer_write_be16(aad, len);
    fprintf(stderr, "aad: %lu bytes\n", buffer_remain(aad));
    hexdump(stderr, buffer_head(aad), buffer_remain(aad));
    encrypted_len = tls_gcm_encrypt(data, len, buffer_head(aad), buffer_remain(aad), ctx->data[CLIENT].write_key, iv, sizeof(iv), encrypted, tag);
    if (encrypted_len == -1) {
        return -1;
    }
    buffer_destroy(aad);
    fprintf(stderr, "encrypted: %u bytes\n", encrypted_len);
    hexdump(stderr, encrypted, encrypted_len);
    fprintf(stderr, "tag: %lu bytes\n", sizeof(tag));
    hexdump(stderr, tag, sizeof(tag));
    return encrypted_len;
}

int
tls_decrypt_record(struct tls_context *ctx, uint8_t type, uint16_t version, uint16_t length, struct buffer *buf, uint8_t *plaintext)
{
    uint8_t nonce[8];
    uint8_t tag[16];
    uint8_t encrypted[65536];
    size_t encrypted_len = length - sizeof(nonce) - sizeof(tag);
    uint8_t iv[12];
    struct buffer *aad;
    int plaintext_len;

    if (buffer_read(buf, nonce, sizeof(nonce)) == -1) {
        return -1;
    }
    fprintf(stderr, "nonce: %lu bytes\n", sizeof(nonce));
    hexdump(stderr, nonce, sizeof(nonce));
    if (buffer_read(buf, encrypted, encrypted_len) == -1) {
        return -1;
    }
    fprintf(stderr, "in: %lu bytes\n", encrypted_len);
    hexdump(stderr, encrypted, encrypted_len);
    if (buffer_read(buf, tag, sizeof(tag)) == -1) {
        return -1;
    }
    fprintf(stderr, "tag: %lu bytes\n", sizeof(tag));
    hexdump(stderr, tag, sizeof(tag));
    memcpy(iv, ctx->data[SERVER].write_iv, sizeof(ctx->data[SERVER].write_iv));
    memcpy(iv + sizeof(ctx->data[SERVER].write_iv), nonce, sizeof(nonce));
    fprintf(stderr, "iv: %lu bytes\n", sizeof(iv));
    hexdump(stderr, iv, sizeof(iv));
    aad = buffer_create(NULL, 0, 128);
    if (!aad) {
        return -1;
    }
    buffer_write_be64(aad, ctx->data[SERVER].seq++);
    buffer_write_u8(aad, type);
    buffer_write_be16(aad, version);
    buffer_write_be16(aad, encrypted_len);
    fprintf(stderr, "aad: %lu bytes\n", buffer_remain(aad));
    hexdump(stderr, buffer_head(aad), buffer_remain(aad));
    plaintext_len = tls_gcm_decrypt(encrypted, encrypted_len, buffer_head(aad), buffer_remain(aad), tag, ctx->data[SERVER].write_key, iv, sizeof(iv), plaintext);
    buffer_destroy(aad);
    if (plaintext_len == -1) {
        return -1;
    }
    return plaintext_len;
}
