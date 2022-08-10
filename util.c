#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

void
hexdump(FILE *fp, const void *data, size_t size)
{
    unsigned char *src;
    int offset, index;

    flockfile(fp);
    src = (unsigned char *)data;
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
    for(offset = 0; offset < (int)size; offset += 16) {
        fprintf(fp, "| %04x | ", offset);
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                fprintf(fp, "%02x ", 0xff & src[offset + index]);
            } else {
                fprintf(fp, "   ");
            }
        }
        fprintf(fp, "| ");
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                if(isascii(src[offset + index]) && isprint(src[offset + index])) {
                    fprintf(fp, "%c", src[offset + index]);
                } else {
                    fprintf(fp, ".");
                }
            } else {
                fprintf(fp, " ");
            }
        }
        fprintf(fp, " |\n");
    }
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
    funlockfile(fp);
}

void
cdump(FILE *fp, const void *data, size_t size, char *name)
{
    unsigned char *src;
    size_t idx;

    src = (unsigned char *)data;
    fprintf(fp, "uint8_t %s[%lu] = {", name, size);
    for (idx = 0; idx < size; idx++) {
        fprintf(fp, "%s0x%02x", idx ? "," : "", src[idx]);
    }
    fprintf(fp, "};\n");
}