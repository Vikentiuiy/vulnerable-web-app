#include <stdlib.h>
int main(int argc, char **argv) {
    char *p = malloc(16);
    free(p);
    // VULN:VULN-54:CWE-415:taint double free of the same heap pointer
    if (argc > 1) free(p);
    return 0;
}
