#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
static int cb(void *u, int n, char **v, char **c) {
    for (int i = 0; i < n; i++) printf("%s=%s ", c[i], v[i] ? v[i] : "");
    printf("\n");
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db, "CREATE TABLE users(id,name,secret);"
                     "INSERT INTO users VALUES(1,'admin','flag{cpp_sqli}');", 0, 0, 0);
    char q[512];
    // VULN:VULN-62:CWE-89:taint SQL injection — user input formatted into a query string
    snprintf(q, sizeof q, "SELECT name, secret FROM users WHERE name='%s'", argv[1]);
    sqlite3_exec(db, q, cb, 0, 0);
    sqlite3_close(db);
    return 0;
}
