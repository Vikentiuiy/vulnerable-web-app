#include <alloca.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 3) return 1;
    size_t n = (size_t) atoi(argv[1]);
    char *buf = alloca(n);
    // VULN:VULN-70:CWE-787:taint attacker-sized alloca then unbounded copy
    strcpy(buf, argv[2]);
    printf("%s\n", buf);
    return 0;
}
