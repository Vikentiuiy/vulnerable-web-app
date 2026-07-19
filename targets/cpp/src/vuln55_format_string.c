#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    // VULN:VULN-55:CWE-134:taint uncontrolled format string — user input as printf format
    printf(argv[1]);
    printf("\n");
    return 0;
}
