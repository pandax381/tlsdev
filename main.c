#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>

#include "tls.h"
#include "util.h"

int
main(void)
{
    int soc;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    OPENSSL_init();

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo("localhost", "4433", &hints, &result);
    if (err) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
    }
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        soc = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (soc == -1) {
            continue;
        }
        if (connect(soc, rp->ai_addr, rp->ai_addrlen) != -1) {
            break;
        }
        close(soc);
    }
    freeaddrinfo(result);
    if (rp == NULL) {
        fprintf(stderr, "Could not connect\n");
        return -1;
    }

    struct tls_context *ctx = tls_context_create(soc, TLS_V12, CLIENT);
    if (!ctx) {
        return -1;
    }
    if (tls_connect(ctx) == -1) {
        return -1;
    }
    fprintf(stderr, "tls connection established\n");
    uint8_t buf[1024];
    ssize_t ret;
    while (1) {
        ret = tls_recv(ctx, buf, sizeof(buf));
        if (ret == -1) {
            return -1;
        }
        fprintf(stderr, "tls_recv: %zu bytes\n", ret);
        hexdump(stderr, buf, ret);
        tls_send(ctx, buf, ret);
    }
    tls_close(ctx);
    return 0;
}