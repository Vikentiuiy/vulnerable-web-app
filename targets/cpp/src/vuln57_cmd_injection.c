#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", argv[1]);
    // VULN:VULN-57:CWE-78:taint OS command injection via system()
    system(cmd);
    return 0;
}
