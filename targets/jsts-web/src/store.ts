import Database from "better-sqlite3";

export const db = new Database(":memory:");

export function seed(): void {
  // VULN:VULN-19:CWE-256:config passwords stored as unsalted MD5
  // VULN:VULN-20:CWE-312:config secret_answer kept in cleartext
  db.exec(`CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT,
      secret_answer TEXT, role TEXT DEFAULT 'user', bio TEXT, ssn TEXT);
    CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL);`);
  const c = db.prepare("SELECT COUNT(*) AS c FROM users").get() as { c: number };
  if (c.c === 0) {
    const u = db.prepare("INSERT INTO users(username,password,secret_answer,role,bio,ssn) VALUES(?,?,?,?,?,?)");
    u.run("admin", "0192023a7bbd73250516f069df18b500", "my-first-car", "admin", "Site administrator", "111-22-3333");
    u.run("alice", "7c6a180b36896a0a8c02787eeafb0e4c", "fluffy", "user", "Hi, I am Alice", "222-33-4444");
    const p = db.prepare("INSERT INTO products(name,price) VALUES(?,?)");
    p.run("Laptop", 999.0); p.run("Keyboard", 49.0);
  }
}
