#include <string.h>
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    char buf[16] = "pre-";
    const char *e = getenv("PAYLOAD");
    if (!e) return 1;
    // VULN:VULN-64:CWE-120:taint strcat of environment-controlled data into a fixed buffer
    strcat(buf, e);
    printf("%s\n", buf);
    return 0;
}
