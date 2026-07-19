#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char path[256];
    snprintf(path, sizeof(path), "/app/data/%s", argv[1]);
    // VULN:VULN-58:CWE-22:taint path traversal via fopen of user-controlled path
    FILE *f = fopen(path, "r");
    if (!f) { perror("open"); return 1; }
    char b[512];
    while (fgets(b, sizeof b, f)) fputs(b, stdout);
    fclose(f);
    return 0;
}
