#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    char *p = malloc(32);
    strcpy(p, argc > 1 ? argv[1] : "x");
    free(p);
    // VULN:VULN-53:CWE-416:taint use-after-free — freed memory read back
    printf("uaf: %s\n", p);
    return 0;
}
