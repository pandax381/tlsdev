#ifndef TLS_H
#define TLS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum TLS_VERSION {
    TLS_V10 = 0x0301,
    TLS_V11 = 0x0302,
    TLS_V12 = 0x0303,
    TLS_V13 = 0x0304,
};

typedef enum {
    HANDSHAKE_TYPE_HELLO_REQUEST = 0,
    HANDSHAKE_TYPE_CLIENT_HELLO = 1,
    HANDSHAKE_TYPE_SERVER_HELLO = 2,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8,
    HANDSHAKE_TYPE_CERTIFICATE = 11,
    HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12,
    HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13,
    HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14,
    HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15,
    HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE =16,
    HANDSHAKE_TYPE_FINISHED = 20,
} HandshakeType;

#define TLS_RSA_WITH_AES_128_GCM_SHA256 0x009c

typedef enum {
    CIPHER_KX_RSA,
} CipherKx;

typedef enum {
    CIPHER_AU_RSA,
} CipherAu;

typedef enum {
    CIPHER_ENC_AESGCM128,
} CipherEnc;

typedef enum {
    CIPHER_MAC_AEAD,
} CipherMac;

struct cipher_spec {
    uint16_t id;
    uint16_t version;
    CipherKx kx;
    CipherAu au;
    CipherEnc enc;
    CipherMac mac;
};

extern struct cipher_spec ciphers[];

typedef enum {
    CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20,
    CONTENT_TYPE_ALERT = 21,
    CONTENT_TYPE_HANDSHAKE = 22,
    CONTENT_TYPE_APPLICATION_DATA = 23,
} ContentType;

enum connection_end {
    CLIENT = 0,
    SERVER = 1,
};

struct tls_cert_entry {
    struct tls_cert_entry *next;
    size_t len;
    uint8_t data[0];
};

#include <openssl/evp.h>

struct tls_digest {
    EVP_MD_CTX *ctx;
};

struct tls_data {
    uint64_t seq;
    uint8_t random[32];
    uint8_t write_key[16];
    uint8_t write_iv[4];
    uint8_t verify_data[12];
    uint8_t cipher_spec;
    uint8_t state;
};

struct tls_context {
    int soc;
    uint16_t version;
    enum connection_end entity;
    struct {
        uint8_t len;
        uint8_t data[32];
    } session_id;
    struct tls_cert_entry *certs;
    uint8_t rsa_pre_master_secret[48];
    uint8_t rsa_master_secret[48];
    struct tls_digest handshake_hash;
    struct buffer *rbuf;
    struct tls_data data[2];
};

extern struct tls_context *
tls_context_create(int soc, uint16_t version, enum connection_end entity);
extern int
tls_connect(struct tls_context *ctx);
extern ssize_t
tls_recv(struct tls_context *ctx, uint8_t *buf, size_t size);
extern ssize_t
tls_send(struct tls_context *ctx, const uint8_t *buf, size_t len);
extern int
tls_close(struct tls_context *ctx);

// tls_crypto.c
extern int
tls_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *aad, int aad_len,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);
extern int
tls_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);
extern int
tls_encrypt_record(struct tls_context *ctx, uint8_t type, const uint8_t *data, size_t len, uint8_t *nonce, uint8_t *encrypted, uint8_t *tag);
extern int
tls_decrypt_record(struct tls_context *ctx, uint8_t type, uint16_t version, uint16_t length, struct buffer *buf, uint8_t *plaintext);

// tls_digest.c
extern int
tls_digest_init(struct tls_digest *digest);
extern int
tls_digest_update(struct tls_digest *digest, const void *data, size_t len);
extern int
tls_digest_calc(struct tls_digest *digest, unsigned char *dst, unsigned int *len);
extern int
tls_digest_final(struct tls_digest *digest, unsigned char *dst, unsigned int *len);
extern int
tls_digest_is_available(struct tls_digest *digest);

// tls_key.c
extern int
tls_pseudo_random_func(const unsigned char *sec, size_t slen,
                       const void *seed1, size_t seed1_len,
                       const void *seed2, size_t seed2_len,
                       const void *seed3, size_t seed3_len,
                       const void *seed4, size_t seed4_len,
                       const void *seed5, size_t seed5_len,
                       unsigned char *out, size_t olen);
extern ssize_t
tls_encrypted_pre_master_secret(struct tls_context *ctx, uint8_t *dst, size_t size);
extern int
tls_extract_key_block(struct tls_context *ctx);

#endif