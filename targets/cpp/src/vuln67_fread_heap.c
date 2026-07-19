#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    char header[8];
    fread(header, 1, 8, f);
    long n = strtol(header, 0, 10);
    char *buf = malloc(16);
    // VULN:VULN-67:CWE-122:taint file-controlled length drives an oversized heap copy
    fread(buf, 1, n, f);
    printf("%s\n", buf);
    fclose(f); free(buf);
    return 0;
}
