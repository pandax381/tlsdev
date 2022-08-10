#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "tls.h"
#include "buffer.h"
#include "util.h"

struct cipher_spec ciphers[] = {
    {TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_V12, CIPHER_KX_RSA, CIPHER_AU_RSA, CIPHER_ENC_AESGCM128, CIPHER_MAC_AEAD},
};

/*
 * Build TLS Record
 */

static ssize_t
tls_build_client_hello(struct tls_context *ctx, uint8_t *buf, size_t size)
{
    struct buffer *rec;

    // TLS Record Layer

    rec = buffer_create(buf, 0, size);
    if (!rec) {
        return -1;
    }
    // 1byte: type
    buffer_write_u8(rec, CONTENT_TYPE_HANDSHAKE);
    // 2byte: protocol version
    buffer_write_be16(rec, TLS_V10);
    // 2byte: length
    buffer_var_enter(rec, 2);

    // Hnadshake (ClientHello)

    // 1byte: type
    buffer_write_u8(rec, HANDSHAKE_TYPE_CLIENT_HELLO);
    // 3byte: length
    buffer_var_enter(rec, 3);

    // Body
    
    // 2byte: client version
    buffer_write_be16(rec, ctx->version);
    // 32byte: random
    uint32_t timestamp = htonl((uint32_t)time(NULL));
    memcpy(ctx->data[CLIENT].random, &timestamp, sizeof(timestamp));
    buffer_write(rec, ctx->data[CLIENT].random, sizeof(ctx->data[CLIENT].random));
    // variable(<=32): session id
    buffer_var_enter(rec, 1);
      buffer_write(rec, ctx->session_id.data, ctx->session_id.len);
    buffer_var_done_be(rec);
    // variable: chiper suite
    buffer_var_enter(rec, 2);
    switch(ctx->version) {
    case TLS_V12:
        buffer_write_be16(rec, TLS_RSA_WITH_AES_128_GCM_SHA256);
        break;
    case TLS_V13:
        // not implement
    default:
        fprintf(stderr, "unsupported version\n");
        return -1;
    }
    buffer_var_done_be(rec);
    // variable: compression
    buffer_var_enter(rec, 1);
      buffer_write_u8(rec, 0x00); // CompressionMethod: null
    buffer_var_done_be(rec);
    // valiable: extention
    buffer_var_enter(rec, 2);
    switch(ctx->version) {
    case TLS_V12:
        // valiable: signature_algorithms
        buffer_write_be16(rec, 0x000d);
        buffer_var_enter(rec, 2);
          buffer_var_enter(rec, 2);
            buffer_write_be16(rec, 0x0401); // rsa_pkcs1_sha256
          buffer_var_done_be(rec);
        buffer_var_done_be(rec);
        break;
    case TLS_V13:
        // not implement
    default:
        fprintf(stderr, "unsupported version\n");
        return -1;
    }
    fprintf(stderr, "extension: %lu bytes\n", buffer_var_len(rec));
    buffer_var_done_be(rec); // extension

    buffer_var_done_be(rec); // handshake
    tls_digest_update(&ctx->handshake_hash, buffer_var_ptr(rec), buffer_var_len(rec)); // Save Handshake message HASH
    cdump(stderr, buffer_var_ptr(rec), buffer_var_len(rec), "client_hello");

    buffer_var_done_be(rec); // redord
    ssize_t ret = buffer_remain(rec);
    buffer_destroy(rec);
    return ret;
}

static ssize_t
tls_build_client_key_exchange(struct tls_context *ctx, uint8_t *buf, size_t size)
{
    ssize_t encrypted_len;
    struct buffer *rec;
    ssize_t ret;

    ctx->rsa_pre_master_secret[0] = 0x03;
    ctx->rsa_pre_master_secret[1] = 0x03;
    fprintf(stderr, "pre master secret: %lu\n", sizeof(ctx->rsa_pre_master_secret));
    hexdump(stderr, ctx->rsa_pre_master_secret, sizeof(ctx->rsa_pre_master_secret));

    tls_extract_key_block(ctx);

    // TLS Record Layer

    rec = buffer_create(buf, 0, size);
    if (!rec) {
        return -1;
    }
    // 1byte: type
    buffer_write_u8(rec, CONTENT_TYPE_HANDSHAKE);
    // 2byte: protocol version
    buffer_write_be16(rec, ctx->version);
    // 2byte: length
    buffer_var_enter(rec, 2);

    // Hnadshake (ClientKeyExchange)

    // 1byte: type
    buffer_write_u8(rec, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE);
    // 3byte: length
    buffer_var_enter(rec, 3);

    // Body

    // variable: encrypted pre master secret
    buffer_var_enter(rec, 2);
    encrypted_len = tls_encrypted_pre_master_secret(ctx, buffer_tail(rec), buffer_space(rec));
    if (encrypted_len == -1) {
        return -1;
    }
    buffer_consume(rec, encrypted_len);
    buffer_var_done_be(rec); // body

    buffer_var_done_be(rec); // handshake
    tls_digest_update(&ctx->handshake_hash, buffer_var_ptr(rec), buffer_var_len(rec)); // Save Handshake message HASH
    cdump(stderr, buffer_var_ptr(rec), buffer_var_len(rec), "client_key_exchange");
    
    buffer_var_done_be(rec); // record
    ret = buffer_remain(rec);
    buffer_destroy(rec);
    return ret;
}

static ssize_t
tls_build_change_cipher_spec(struct tls_context *ctx, uint8_t *buf, size_t size)
{
    struct buffer *rec;
    ssize_t ret;

    // TLS Record Layer

    rec = buffer_create(buf, 0, size);
    if (!rec) {
        return -1;
    }
    // 1byte: type
    buffer_write_u8(rec, CONTENT_TYPE_CHANGE_CIPHER_SPEC);
    // 2byte: protocol version
    buffer_write_be16(rec, ctx->version);
    // 2byte: length
    buffer_var_enter(rec, 2);

    // ChangeSipherSpec
    
    // 1byte: change cipher spec
    buffer_write_u8(rec, 0x01); // enable

    buffer_var_done_be(rec); // record
    ret = buffer_remain(rec);
    buffer_destroy(rec);
    return ret;
}

static int
tls_verify_data(struct tls_context *ctx, const char *label, const uint8_t *hash, size_t hlen, uint8_t *dst, size_t size)
{
    return tls_pseudo_random_func(ctx->rsa_master_secret, sizeof(ctx->rsa_master_secret), label, strlen(label), hash, hlen, NULL, 0, NULL, 0, NULL, 0, dst, size);
}

static ssize_t
tls_build_finished(struct tls_context *ctx, uint8_t *buf, size_t size)
{
    struct buffer *rec;
    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    uint8_t verify_data[12];
    uint8_t nonce[8] = {0}; // *** random value ****
    uint8_t tag[16];
    uint8_t encrypted[65536];
    int encrypted_len;
    ssize_t ret;

    // TLS Record Layer

    rec = buffer_create(buf, 0, size);
    if (!rec) {
        return -1;
    }
    // 1byte: type
    buffer_write_u8(rec, CONTENT_TYPE_HANDSHAKE);
    // 2byte: protocol version
    buffer_write_be16(rec, ctx->version);
    // 2byte: length
    buffer_var_enter(rec, 2); // Create temporary record

    // Hnadshake (Finished)

    // 1byte: type (0x14)
    buffer_write_u8(rec, HANDSHAKE_TYPE_FINISHED);
    // 3byte: length
    buffer_var_enter(rec, 3);

    // Body

    // generate verify data
    tls_digest_calc(&ctx->handshake_hash, hash, &hash_len);
    if (tls_verify_data(ctx, "client finished", hash, hash_len, ctx->data[CLIENT].verify_data, sizeof(ctx->data[CLIENT].verify_data)) == -1) {
        return -1;
    }

    // 12byte: verify data
    buffer_write(rec, ctx->data[CLIENT].verify_data, sizeof(ctx->data[CLIENT].verify_data));
    buffer_var_done_be(rec); // handshake

    // generate server verify data
    tls_digest_update(&ctx->handshake_hash, buffer_var_ptr(rec), buffer_var_len(rec)); // Save Handshake message HASH
    tls_digest_final(&ctx->handshake_hash, hash, &hash_len);
    if (tls_verify_data(ctx, "server finished", hash, hash_len, ctx->data[SERVER].verify_data, sizeof(ctx->data[SERVER].verify_data)) == -1) {
        return -1;
    }

    encrypted_len = tls_encrypt_record(ctx, CONTENT_TYPE_HANDSHAKE, buffer_var_ptr(rec), buffer_var_len(rec), nonce, encrypted, tag);
    if (encrypted_len == -1) {
        return -1;
    }
    buffer_var_drop(rec); // Drop temporary record

    // Create real record
    buffer_var_enter(rec, 2);
    buffer_write(rec, nonce, sizeof(nonce));
    buffer_write(rec, encrypted, encrypted_len);
    buffer_write(rec, tag, sizeof(tag));
    buffer_var_done_be(rec);
    ret = buffer_remain(rec);
    buffer_destroy(rec);
    return ret;
}

static int
tls_build_application_data(struct tls_context *ctx, const uint8_t *app_data, size_t alen, uint8_t *buf, size_t size)
{
    struct buffer *rec;
    uint8_t nonce[8] = {0}; // *** random value ****
    uint8_t tag[16];
    uint8_t encrypted[65536];
    int encrypted_len;
    ssize_t ret;

    // TLS Record Layer

    rec = buffer_create(buf, 0, size);
    if (!rec) {
        return -1;
    }
    // 1byte: type
    buffer_write_u8(rec, CONTENT_TYPE_APPLICATION_DATA);
    // 2byte: protocol version
    buffer_write_be16(rec, ctx->version);
    // 2byte: length
    buffer_var_enter(rec, 2);

    // Application Data 
    encrypted_len = tls_encrypt_record(ctx, CONTENT_TYPE_APPLICATION_DATA, app_data, alen, nonce, encrypted, tag);
    if (encrypted_len == -1) {
        return -1;
    }
    buffer_write(rec, nonce, sizeof(nonce));
    buffer_write(rec, encrypted, encrypted_len);
    buffer_write(rec, tag, sizeof(tag));

    buffer_var_done_be(rec);
    ret = buffer_remain(rec);
    buffer_destroy(rec);
    return ret;
}

/*
 * Parse TLS Record
 */

static int
tls_handshake_parse_server_hello(struct tls_context *ctx, struct buffer *buf)
{
    uint16_t server_version;
    uint8_t session_id_len;
    uint8_t session_id[32];
    uint16_t cipher_suite;
    uint8_t compression;

    if (buffer_read_be16(buf, &server_version) == -1) {
        return -1;
    }
    fprintf(stderr, "server version: %04x\n", server_version);

    if (buffer_read(buf, ctx->data[SERVER].random, sizeof(ctx->data[SERVER].random)) == -1) {
        return -1;
    }
    fprintf(stderr, "random:\n");
    hexdump(stderr, ctx->data[SERVER].random, sizeof(ctx->data[SERVER].random));

    if (buffer_read(buf, &session_id_len, sizeof(session_id_len)) == -1) {
        return -1;
    }
    if (buffer_read(buf, &session_id, session_id_len) == -1) {
        return -1;
    }
    fprintf(stderr, "session_id: (%u bytes)\n", session_id_len);
    hexdump(stderr, session_id, session_id_len);

    if (buffer_read_be16(buf, &cipher_suite) == -1) {
        return -1;
    }
    fprintf(stderr, "cipher suite: %04x\n", cipher_suite);

    if (buffer_read(buf, &compression, sizeof(compression)) == -1) {
        return -1;
    }
    fprintf(stderr, "compression: %02x\n", compression);

    if (buffer_remain(buf)) {
        uint16_t ext_total;
        if (buffer_read_be16(buf, &ext_total) == -1) {
            return -1;
        }
        while (buffer_remain(buf)) {
            uint16_t ext_type, ext_len;
            buffer_read_be16(buf, &ext_type);
            buffer_read_be16(buf, &ext_len);
            fprintf(stderr, "extension: 0x%04x (%u byte)\n", ext_type, ext_len);
            hexdump(stderr, buffer_head(buf), ext_len);
            switch (ext_type) {
            uint16_t v;
            case 0x002b:
                buffer_read_be16(buf, &v);
                fprintf(stderr, "supported_versions: 0x%04x\n", v);
                break;
            default:
                fprintf(stderr, "unknown extension (skip)\n");
                buffer_seek(buf, ext_len);
                break;
            }
        }
    }

    return 0;
}

static int
tls_handshake_parse_certificate(struct tls_context *ctx, struct buffer *buf)
{
    uint32_t cert_list_len;
    struct buffer *cert_buf;
    uint32_t cert_len;
    struct tls_cert_entry *entry;

    if (buffer_read_be24(buf, &cert_list_len) == -1) {
        return -1;
    }
    fprintf(stderr, "total len: %u \n", cert_list_len);
    if (buffer_remain(buf) < cert_list_len) {
        fprintf(stderr, "too short");
        return -1;
    }
    cert_buf = buffer_create(buf->head, cert_list_len, 0);
    if (!cert_buf) {
        return -1;
    }
    while (buffer_remain(cert_buf)) {
        if (buffer_read_be24(cert_buf, &cert_len) == -1) {
            buffer_destroy(cert_buf);
            return -1;
        }
        fprintf(stderr, "cert len: %u \n", cert_len);
        if (buffer_remain(cert_buf) < cert_len) {
            fprintf(stderr, "too short");
            buffer_destroy(cert_buf);
            return -1;
        }
        entry = malloc(sizeof(*entry) + cert_len);
        if (!entry) {
            buffer_destroy(cert_buf);
            return -1;
        }
        entry->next = ctx->certs;
        entry->len = cert_len;
        if (buffer_read(cert_buf, entry->data, cert_len) == -1) {
            free(entry);
            buffer_destroy(cert_buf);
            return -1;
        }
        ctx->certs = entry;
    }
    buffer_seek(buf, cert_list_len);
    return 0;
}

static int
tls_handshake_parse_server_hello_done(struct tls_context *ctx, struct buffer *buf)
{
    return 0;
}

static int
tls_handshake_parse_finished(struct tls_context *ctx, struct buffer *buf)
{
    uint8_t verify_data[12];

    if (buffer_read(buf, &verify_data, sizeof(verify_data)) == -1) {
        return -1;
    }
    if (memcmp(verify_data, ctx->data[SERVER].verify_data, 12) != 0) {
        return -1;
    }
    fprintf(stderr, "verified!!!\n");
    return 0;
}

static int
tls_handshake_parse(struct tls_context *ctx, uint8_t *data, size_t len)
{
    struct buffer *buf;
    uint8_t msg_type;
    uint32_t msg_len;

    buf = buffer_create(data, len, 0);
    if (!buf) {
        return -1;
    }
    if (buffer_read(buf, &msg_type, sizeof(msg_type)) == -1) {
        goto err;
    }
    if (buffer_read_be24(buf, &msg_len) == -1) {
        goto err;
    }
    fprintf(stderr, "msg type: %02x\n", msg_type);
    fprintf(stderr, "msg len: %u\n", msg_len);
    if (buffer_remain(buf) < msg_len) {
        fprintf(stderr, "too short\n");
        goto err;
    }
    switch (msg_type) {
    case HANDSHAKE_TYPE_SERVER_HELLO:
        fprintf(stderr, "server_hello\n");
        if (tls_handshake_parse_server_hello(ctx, buf) == -1) {
            goto err;
        }
        break;
    case HANDSHAKE_TYPE_CERTIFICATE:
        fprintf(stderr, "certificate\n");
        if (tls_handshake_parse_certificate(ctx, buf) == -1) {
            goto err;
        }
        break;
    case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
        fprintf(stderr, "server_hello_done\n");
        if (tls_handshake_parse_server_hello_done(ctx, buf) == -1) {
            goto err;
        }
        break;
    case HANDSHAKE_TYPE_FINISHED:
        fprintf(stderr, "finished\n");
        if (tls_handshake_parse_finished(ctx, buf) == -1) {
            goto err;
        }
        break;
    default:
        fprintf(stderr, "unknown message type\n");
        goto err;
    }
    ctx->data[SERVER].state = msg_type;
    buffer_destroy(buf);
    return 0;
err:
    buffer_destroy(buf);
    return -1;
}

static int
tls_wait_server_record(struct tls_context *ctx)
{
    struct buffer *buf;
    ssize_t n;
    uint8_t type;
    uint16_t version;
    uint16_t length;
    int need_more_data = 0;
    uint8_t plaintext[65535];

    buf = buffer_create(NULL, 0, 65535);
    if (!buf) {
        return -1;
    }
    do {
        if (buffer_remain(buf) < 5) {
            buffer_gc(buf);
            n = recv(ctx->soc, buffer_tail(buf), buffer_space(buf), 0);
            if (n == -1) {
                perror("recv");
                return -1;
            }
            if (n == 0) {
                fprintf(stderr, "connection closed\n");
                return -1;
            }
            buffer_consume(buf, n);
            if (buffer_remain(buf) < 5) {
                continue;
            }
        }
        if (!need_more_data) {
            if (buffer_read(buf, &type, sizeof(type)) == -1) {
                return -1;
            }
            if (buffer_read_be16(buf, &version) == -1) {
                return -1;
            }
            if (buffer_read_be16(buf, &length) == -1) {
                return -1;
            }
        }
        if (buffer_remain(buf) < length) {
            need_more_data = 1;
            continue;
        }
        need_more_data = 0;

        uint8_t *data = buffer_head(buf);
        size_t data_len = length;

        if (ctx->data[SERVER].cipher_spec) {
            fprintf(stderr, "encrypted message: type=%u, version=%04x, length=%u\n", type, version, length);
            int plaintext_len = tls_decrypt_record(ctx, type, version, length, buf, plaintext);
            if (plaintext_len == -1) {
                fprintf(stderr, "decrypt error\n");
                return -1;
            }
            fprintf(stderr, "plaintext message: %d bytes\n", plaintext_len);
            hexdump(stderr, plaintext, plaintext_len);
            data = plaintext;
            data_len = plaintext_len;
        } else {
            buffer_seek(buf, length);
        }

        switch (type) {
        case CONTENT_TYPE_CHANGE_CIPHER_SPEC:
            fprintf(stderr, "change_ciper_spec\n");
            hexdump(stderr, data, data_len);
            ctx->data[SERVER].cipher_spec = 1;
            break;
        case CONTENT_TYPE_ALERT:
            fprintf(stderr, "alert\n");
            return -1;
        case CONTENT_TYPE_HANDSHAKE:
            fprintf(stderr, "handshake\n");
            if (tls_digest_is_available(&ctx->handshake_hash)) {
                tls_digest_update(&ctx->handshake_hash, data, data_len);
            }
            if (tls_handshake_parse(ctx, data, data_len) == -1) {
                return -1;
            }
            break;
        case CONTENT_TYPE_APPLICATION_DATA:
            fprintf(stderr, "application data\n");
            hexdump(stderr, data, data_len);
            buffer_write(ctx->rbuf, data, data_len);
            break;
        default:
            fprintf(stderr, "unknown type: %u, len: %lu\n", type, data_len);
            return -1;
        }
        type = 0;
        version = 0;
        length = 0;
    } while (buffer_remain(buf) != 0);
    fprintf(stderr, "done\n");
    return 0;
}

static int
tls_handshake(struct tls_context *ctx)
{
    uint8_t sbuf[1024];
    ssize_t len, n;

    len = tls_build_client_hello(ctx, sbuf, sizeof(sbuf));
    if (len == -1) {
        return -1;
    }
    n = send(ctx->soc, sbuf, len, 0);
    if (n == -1) {
        perror("send");
        return -1;
    }
    fprintf(stderr, "%zu bytes sent\n", n);
    hexdump(stderr, sbuf, n);

    while (ctx->data[SERVER].state < HANDSHAKE_TYPE_SERVER_HELLO_DONE) {
        if (tls_wait_server_record(ctx) == -1) {
            return -1;
        }
    }

    len = tls_build_client_key_exchange(ctx, sbuf, sizeof(sbuf));
    if (len == -1) {
        return -1;
    }
    n = send(ctx->soc, sbuf, len, 0);
    if (n == -1) {
        perror("send");
        return -1;
    }
    fprintf(stderr, "%zu bytes sent\n", n);
    hexdump(stderr, sbuf, n);

    len = tls_build_change_cipher_spec(ctx, sbuf, sizeof(sbuf));
    n = send(ctx->soc, sbuf, len, 0);
    if (n == -1) {
        perror("send");
        return -1;
    }
    fprintf(stderr, "%zu bytes sent\n", n);
    hexdump(stderr, sbuf, n);

    len = tls_build_finished(ctx, sbuf, sizeof(sbuf));
    n = send(ctx->soc, sbuf, len, 0);
    if (n == -1) {
        perror("send");
        return -1;
    }
    fprintf(stderr, "%zu bytes sent\n", n);
    hexdump(stderr, sbuf, n);

    while (ctx->data[SERVER].state < HANDSHAKE_TYPE_FINISHED) {
        if (tls_wait_server_record(ctx) == -1) {
            return -1;
        }
    }

    return 0;
}

struct tls_context *
tls_context_create(int soc, uint16_t version, enum connection_end entity)
{
    struct tls_context *ctx;
    
    ctx = calloc(1, sizeof(struct tls_context));
    if (!ctx) {
        fprintf(stderr, "calloc: failure\n");
        return NULL;
    }
    ctx->soc = soc;
    ctx->version = version;
    ctx->entity = entity;
    tls_digest_init(&ctx->handshake_hash);
    ctx->rbuf = buffer_create(NULL, 0, 65536);
    return ctx;
}

int
tls_connect(struct tls_context *ctx)
{
    if (tls_handshake(ctx) == -1) {
        return -1;
    }
    return 0;
}

ssize_t
tls_recv(struct tls_context *ctx, uint8_t *buf, size_t size)
{
    if (!buffer_remain(ctx->rbuf)) {
        if (tls_wait_server_record(ctx) == -1) {
            return -1;
        }
    }
    size_t n = MIN(buffer_remain(ctx->rbuf), size);
    buffer_read(ctx->rbuf, buf, n);
    buffer_gc(ctx->rbuf);
    return n;
}

ssize_t
tls_send(struct tls_context *ctx, const uint8_t *app_data, size_t alen)
{
    uint8_t sbuf[65536];
    ssize_t len, n;

    len = tls_build_application_data(ctx, app_data, alen, sbuf, sizeof(sbuf));
    if (len == -1) {
        return -1;
    }
    n = send(ctx->soc, sbuf, len, 0);
    if (n == -1) {
        perror("send");
        return -1;
    }
    return len;
}

int
tls_close(struct tls_context *ctx)
{
    return -1;
}
