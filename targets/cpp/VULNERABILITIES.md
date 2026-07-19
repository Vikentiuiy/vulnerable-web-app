# Planted vulnerabilities — cpp target

12 distinct, **exploitable** native C memory-safety / injection bugs.
Each is a standalone CLI binary; exploitation is proven by **AddressSanitizer**
(memory bugs) or observable effect (command/path/SQL injection).

Detection classes: taint=11, logic=1. Headline = engine (taint) recall.

Exploit gate runs inside the container: `python3 exploits/exploit_all.py` (needs `vuln-cpp` up).

| ID | CWE | Class | Bug | File | Line |
|----|-----|-------|-----|------|------|
| VULN-51 | CWE-121 | taint | stack buffer overflow via strcpy of unbounded in | `vuln51_stack_overflow.c` | 6 |
| VULN-52 | CWE-122 | taint | heap buffer overflow — memcpy of attacker-sized  | `vuln52_heap_overflow.c` | 7 |
| VULN-53 | CWE-416 | taint | use-after-free — freed memory read back | `vuln53_use_after_free.c` | 8 |
| VULN-54 | CWE-415 | taint | double free of the same heap pointer | `vuln54_double_free.c` | 5 |
| VULN-55 | CWE-134 | taint | uncontrolled format string — user input as print | `vuln55_format_string.c` | 4 |
| VULN-56 | CWE-190 | taint | integer truncation in size calc -> undersized bu | `vuln56_int_overflow.c` | 7 |
| VULN-57 | CWE-78 | taint | OS command injection via system() | `vuln57_cmd_injection.c` | 7 |
| VULN-58 | CWE-22 | taint | path traversal via fopen of user-controlled path | `vuln58_path_traversal.c` | 6 |
| VULN-59 | CWE-476 | logic | null pointer dereference | `vuln59_null_deref.c` | 5 |
| VULN-60 | CWE-787 | taint | out-of-bounds write — array index from untrusted | `vuln60_oob_write.c` | 7 |
| VULN-61 | CWE-125 | taint | out-of-bounds read — array index from untrusted  | `vuln61_oob_read.c` | 8 |
| VULN-62 | CWE-89 | taint | SQL injection — user input formatted into a quer | `vuln62_sqli.c` | 16 |
