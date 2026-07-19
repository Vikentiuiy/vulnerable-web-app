#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int arr[10];
    for (int k = 0; k < 10; k++) arr[k] = k * k;
    int i = atoi(argv[1]);
    // VULN:VULN-61:CWE-125:taint out-of-bounds read — array index from untrusted input
    printf("%d\n", arr[i]);
    return 0;
}
