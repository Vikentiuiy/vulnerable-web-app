#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char buf[16];
    // VULN:VULN-65:CWE-787:taint sprintf of unbounded argv into a fixed buffer
    sprintf(buf, "user=%s", argv[1]);
    printf("%s\n", buf);
    return 0;
}
