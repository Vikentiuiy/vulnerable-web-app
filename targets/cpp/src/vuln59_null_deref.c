#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    const char *p = (argc > 1 && argv[1][0] == 'x') ? NULL : "ok";
    // VULN:VULN-59:CWE-476:logic null pointer dereference
    printf("len=%zu\n", strlen(p));
    return 0;
}
