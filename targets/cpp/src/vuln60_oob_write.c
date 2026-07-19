#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 3) return 1;
    int arr[10] = {0};
    int i = atoi(argv[1]);
    // VULN:VULN-60:CWE-787:taint out-of-bounds write — array index from untrusted input
    arr[i] = atoi(argv[2]);
    printf("%d\n", arr[i]);
    return 0;
}
