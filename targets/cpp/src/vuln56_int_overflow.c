#include <string.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 3) return 1;
    int count = atoi(argv[1]);
    // VULN:VULN-56:CWE-190:taint integer truncation in size calc -> undersized buffer
    short size = (short) count;
    char *buf = malloc(size > 0 ? size : 1);
    memcpy(buf, argv[2], count);
    printf("%s\n", buf);
    return 0;
}
