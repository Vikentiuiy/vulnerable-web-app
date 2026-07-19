#include <string.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 3) return 1;
    char dst[32];
    int n = atoi(argv[2]);
    // VULN:VULN-68:CWE-787:taint negative/large length from argv into memmove
    memmove(dst, argv[1], (size_t) n);
    printf("%zu\n", strlen(dst));
    return 0;
}
