#include <unistd.h>
#include <stdio.h>
int main(void) {
    char buf[32];
    // VULN:VULN-63:CWE-787:taint unbounded read() from stdin into a 32-byte buffer
    ssize_t n = read(0, buf, 4096);
    if (n < 0) return 1;
    printf("read %zd bytes\n", n);
    return 0;
}
