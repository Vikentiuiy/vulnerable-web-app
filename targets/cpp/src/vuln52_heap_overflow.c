#include <string.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *buf = malloc(16);
    // VULN:VULN-52:CWE-122:taint heap buffer overflow — memcpy of attacker-sized input
    memcpy(buf, argv[1], strlen(argv[1]));
    printf("%s\n", buf);
    free(buf);
    return 0;
}
