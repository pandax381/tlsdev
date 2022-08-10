#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "buffer.h"
#include "util.h"

#define depth2index(x) ((x)-1)

struct buffer *
buffer_create(uint8_t *base, size_t len, size_t cap)
{
    struct buffer *buf;

    if (!len && !cap) {
        fprintf(stderr, "invalid arguments\n");
        return NULL;
    }
    buf = malloc(sizeof(struct buffer));
    if (!buf) {
        fprintf(stderr, "calloc: failure\n");
        return NULL;
    }
    buf->cap = cap ? cap : len;
    buf->fixed = base ? 1 : 0;
    if (!buf->fixed) {
        base = malloc(buf->cap);
        if (!base) {
            fprintf(stderr, "malloc: failure\n");
            free(buf);
            return NULL;
        }
    }
    buf->base = buf->head = base;
    buf->tail = buf->base + len;
    buf->depth = 0;
    return buf;
}

int
buffer_destroy(struct buffer *buf)
{
    if (!buf->fixed) {
        free(buf->base);
    }
    free(buf);
    return 0;
}

uint8_t *
buffer_head(struct buffer *buf)
{
    return buf->head;
}

uint8_t *
buffer_tail(struct buffer *buf)
{
    return buf->tail;
}

size_t
buffer_remain(struct buffer *buf)
{
    return buf->tail - buf->head;
}

size_t
buffer_space(struct buffer *buf)
{
    return buf->cap - (buf->tail - buf->base);
}

int
buffer_gc(struct buffer *buf)
{
    size_t dist;
    int depth;

    memmove(buf->base, buf->head, buffer_remain(buf));
    dist = buf->head - buf->base;
    buf->head = buf->base;
    buf->tail -= dist;
    for (depth = buf->depth; 0 < depth; depth--) {
        buf->vars[depth2index(depth)].base -= dist;
    }
    return 0;
}

int
buffer_fill(struct buffer *buf, uint8_t c, size_t len)
{
    size_t space;

    space = buffer_space(buf);
    if (!len) {
        len = space;
    }
    else if (space < len) {
        fprintf(stderr, "overflow\n");
        return -1;
    }
    memset(buf->tail, c, len);
    buf->tail += len;
    return 0;
}

int
buffer_var_enter(struct buffer *buf, size_t width)
{
    struct buffer_var *var;

    if (BUFFER_DEPTH_MAX < buf->depth+1) {
        fprintf(stderr, "max depth exceeded.\n");
        return -1;
    }
    if (sizeof(uint32_t) < width) {
        fprintf(stderr, "width is too learge\n");
        return -1;
    }
    if (buffer_space(buf) < width) {
        fprintf(stderr, "overflow\n");
        return -1;
    }
    buf->depth++;
    var = &buf->vars[depth2index(buf->depth)];
    var->base = buf->tail;
    var->width = width;
    buffer_fill(buf, 0, width);
    return 0;
}

static int
buffer_var_done_core(struct buffer *buf, int be)
{
    struct buffer_var *var;
    uint32_t len;

    if (!buf->depth) {
        fprintf(stderr, "not in var mode\n");
        return -1;
    }
    var = &buf->vars[depth2index(buf->depth)];
    len = buf->tail - (var->base + var->width);
    if (be) {
        len = htonl(len);
    }
    memcpy(var->base, (uint8_t *)&len + (sizeof(len) - var->width), var->width);
    var->base = NULL;
    var->width = 0;
    buf->depth--;
    return 0;
}

int
buffer_var_done(struct buffer *buf)
{
    buffer_var_done_core(buf, 0);
}

int
buffer_var_done_be(struct buffer *buf)
{
    buffer_var_done_core(buf, 1);
}

int
buffer_var_drop(struct buffer *buf)
{
    struct buffer_var *var;

    if (!buf->depth) {
        fprintf(stderr, "not in var mode\n");
        return -1;
    }
    var = &buf->vars[depth2index(buf->depth)];
    buf->tail = var->base;
    var->base = NULL;
    var->width = 0;
    buf->depth--;
    return 0;
}

uint8_t *
buffer_var_ptr(struct buffer *buf)
{
    struct buffer_var *var;

    if (!buf->depth) {
        return NULL;
    }
    var = &buf->vars[depth2index(buf->depth)];
    return var->base + var->width;
}

ssize_t
buffer_var_len(struct buffer *buf)
{
    struct buffer_var *var;

    if (!buf->depth) {
        return -1;
    }
    var = &buf->vars[depth2index(buf->depth)];
    return buf->tail - (var->base + var->width);
}

int
buffer_read(struct buffer *buf, void *dst, size_t size)
{
    if (buffer_remain(buf) < size) {
        fprintf(stderr, "overflow\n");
        return -1;
    }
    if (buf->depth) {
        if (buf->vars[0].base < buf->head + size) {
            fprintf(stderr, "access to incomplete var area\n");
            return -1;
        }
    }
    memcpy(dst, buf->head, size);
    buf->head += size;
    return 0;
}

int
buffer_read_be16(struct buffer *buf, uint16_t *dst)
{
    if (buffer_read(buf, dst, sizeof(*dst)) == -1) {
        return -1;
    }
    *dst = ntohs(*dst);
    return 0;
}

int
buffer_read_be24(struct buffer *buf, uint32_t *dst)
{
    if (buffer_read(buf, (uint8_t *)dst + 1, sizeof(*dst) - 1) == -1) {
        return -1;
    }
    *(uint8_t *)dst = 0;
    *dst = ntohl(*dst);
    return 0;
}

int
buffer_read_be32(struct buffer *buf, uint32_t *dst)
{
    if (buffer_read(buf, dst, sizeof(*dst)) == -1) {
        return -1;
    }
    *dst = ntohl(*dst);
    return 0;
}

int
buffer_seek(struct buffer *buf, size_t len)
{
    if (buffer_remain(buf) < len) {
        fprintf(stderr, "overflow\n");
        return -1;
    }
    if (buf->depth) {
        if (buf->vars[0].base < buf->head + len) {
            fprintf(stderr, "access to incomplete var area\n");
            return -1;
        }
    }
    buf->head += len;
    return 0;
}

int
buffer_write(struct buffer *buf, const void *src, size_t len)
{
    if (buffer_space(buf) < len) {
        fprintf(stderr, "overflow\n");
        return -1;
    }
    memcpy(buf->tail, src, len);
    buf->tail += len;
    return 0;
}

int
buffer_write_u8(struct buffer *buf, uint8_t src)
{
    return buffer_write(buf, &src, sizeof(src));
}

int
buffer_write_be16(struct buffer *buf, uint16_t src)
{
    src = htons(src);
    return buffer_write(buf, &src, sizeof(src));
}

int
buffer_write_be24(struct buffer *buf, uint32_t src)
{
    src = htonl(src);
    return buffer_write(buf, (uint8_t *)&src + 1, sizeof(src) - 1);
}

int
buffer_write_be32(struct buffer *buf, uint32_t src)
{
    src = htonl(src);
    return buffer_write(buf, &src, sizeof(src));
}

int
buffer_write_be64(struct buffer *buf, uint64_t src)
{
    src = htonll(src);
    return buffer_write(buf, &src, sizeof(src));
}

int
buffer_consume(struct buffer *buf, size_t len)
{
    if (buffer_space(buf) < len) {
        fprintf(stderr, "overflow\n");
        return -1;
    }
    buf->tail += len;
    return 0;
}

void
buffer_info(struct buffer *buf)
{
    int depth;
    struct buffer_var *var;

    fprintf(stderr, "base: %p\n", buf->base);
    fprintf(stderr, "head: %p\n", buf->head);
    fprintf(stderr, "tail: %p\n", buf->tail);
    fprintf(stderr, "cap: %lu\n", buf->cap);
    fprintf(stderr, "fixed: %s\n", buf->fixed ? "true" : "false");
    fprintf(stderr, "depth: %lu\n", buf->depth);
    for (depth = buf->depth; depth > 0; depth--) {
        var = &buf->vars[depth2index(depth)];
        fprintf(stderr, "var[%d].base: %p\n", depth2index(depth), var->base);
        fprintf(stderr, "var[%d].width: %lu\n", depth2index(depth), var->width);
    }
}