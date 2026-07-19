-- Intentionally insecure schema + seed data for the sql target. Local lab only.
CREATE DATABASE IF NOT EXISTS vulnsql;
USE vulnsql;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    -- VULN:VULN-74:CWE-256:config passwords stored as unsalted MD5
    password VARCHAR(64) NOT NULL,
    -- VULN:VULN-75:CWE-312:config secret answer kept in cleartext
    secret_answer VARCHAR(128),
    role VARCHAR(16) NOT NULL DEFAULT 'user',
    ssn VARCHAR(32)
);

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    price DECIMAL(10,2) NOT NULL
);

INSERT INTO users (username, password, secret_answer, role, ssn) VALUES
  ('admin', '0192023a7bbd73250516f069df18b500', 'my-first-car', 'admin', '111-22-3333'),
  ('alice', '7c6a180b36896a0a8c02787eeafb0e4c', 'fluffy',       'user',  '222-33-4444');
INSERT INTO products (name, price) VALUES ('Laptop', 999.00), ('Keyboard', 49.00);

-- VULN:VULN-73:CWE-732:config application DB user granted full privileges on everything
GRANT ALL PRIVILEGES ON *.* TO 'appuser'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
