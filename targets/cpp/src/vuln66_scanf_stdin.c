#include <stdio.h>
int main(void) {
    char buf[16];
    // VULN:VULN-66:CWE-787:taint scanf %s from stdin into a fixed buffer (no width limit)
    scanf("%s", buf);
    printf("%s\n", buf);
    return 0;
}
