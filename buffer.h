#ifndef BUFFER_H
#define BUFFER_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#define BUFFER_DEPTH_MAX 32

struct buffer_var {
    uint8_t *base;
    size_t width;
};

struct buffer {
    uint8_t *base;
    uint8_t *head;
    uint8_t *tail;
    size_t cap;
    int fixed;
    size_t depth;
    struct buffer_var vars[BUFFER_DEPTH_MAX];
};

extern struct buffer *
buffer_create(uint8_t *base, size_t len, size_t cap);
extern int
buffer_destroy(struct buffer *buf);
extern uint8_t *
buffer_head(struct buffer *buf);
extern uint8_t *
buffer_tail(struct buffer *buf);
extern size_t
buffer_remain(struct buffer *buf);
extern size_t
buffer_space(struct buffer *buf);
extern int
buffer_gc(struct buffer *buf);
extern int
buffer_fill(struct buffer *buf, uint8_t c, size_t len);
extern int
buffer_var_enter(struct buffer *buf, size_t width);
extern int
buffer_var_done(struct buffer *buf);
extern int
buffer_var_done_be(struct buffer *buf);
extern int
buffer_var_drop(struct buffer *buf);
extern uint8_t *
buffer_var_ptr(struct buffer *buf);
extern ssize_t
buffer_var_len(struct buffer *buf);
extern int
buffer_read(struct buffer *buf, void *dst, size_t size);
extern int
buffer_read_be16(struct buffer *buf, uint16_t *dst);
extern int
buffer_read_be24(struct buffer *buf, uint32_t *dst);
extern int
buffer_read_be32(struct buffer *buf, uint32_t *dst);
extern int
buffer_seek(struct buffer *buf, size_t len);
extern int
buffer_write(struct buffer *buf, const void *src, size_t len);
extern int
buffer_write_u8(struct buffer *buf, uint8_t src);
extern int
buffer_write_be16(struct buffer *buf, uint16_t src);
extern int
buffer_write_be24(struct buffer *buf, uint32_t src);
extern int
buffer_write_be32(struct buffer *buf, uint32_t src);
extern int
buffer_write_be64(struct buffer *buf, uint64_t src);
extern int
buffer_consume(struct buffer *buf, size_t len);
extern void
buffer_info(struct buffer *buf);

#endif