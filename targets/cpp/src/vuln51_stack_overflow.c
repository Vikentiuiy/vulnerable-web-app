#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    char buf[16];
    if (argc < 2) return 1;
    // VULN:VULN-51:CWE-121:taint stack buffer overflow via strcpy of unbounded input
    strcpy(buf, argv[1]);
    printf("copied: %s\n", buf);
    return 0;
}
