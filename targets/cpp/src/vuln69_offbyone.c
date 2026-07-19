#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char buf[8];
    size_t len = strlen(argv[1]);
    // VULN:VULN-69:CWE-193:taint off-by-one — copies len bytes then writes a NUL at buf[len]
    for (size_t i = 0; i <= len && i < 64; i++) buf[i] = argv[1][i];
    printf("%s\n", buf);
    return 0;
}
