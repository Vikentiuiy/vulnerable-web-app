-- Intentionally insecure schema + seed data for the vulnerable-web-app lab.
-- DO NOT use as a template for real systems.

CREATE DATABASE IF NOT EXISTS vulnapp;
USE vulnapp;

CREATE TABLE IF NOT EXISTS users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(64) NOT NULL,
    -- VULN:VULN-19:CWE-256 passwords stored as unsalted MD5 (see CryptoUtil.md5)
    password    VARCHAR(64) NOT NULL,
    -- VULN:VULN-20:CWE-312 secret answer kept in cleartext
    secret_answer VARCHAR(128),
    role        VARCHAR(16) NOT NULL DEFAULT 'user',
    bio         TEXT,
    ssn         VARCHAR(32)
);

CREATE TABLE IF NOT EXISTS products (
    id    INT AUTO_INCREMENT PRIMARY KEY,
    name  VARCHAR(128) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    description TEXT
);

-- password values below are MD5(plaintext):
--   admin / admin123   -> 0192023a7bbd73250516f069df18b500
--   alice / password1  -> 7c6a180b36896a0a8c02787eeafb0e4c
--   bob   / qwerty     -> d8578edf8458ce06fbc5bb76a58c5ca4
INSERT INTO users (username, password, secret_answer, role, bio, ssn) VALUES
  ('admin', '0192023a7bbd73250516f069df18b500', 'my-first-car', 'admin', 'Site administrator', '111-22-3333'),
  ('alice', '7c6a180b36896a0a8c02787eeafb0e4c', 'fluffy',       'user',  'Hi, I am Alice',      '222-33-4444'),
  ('bob',   'd8578edf8458ce06fbc5bb76a58c5ca4', 'chicago',      'user',  'Bob here',            '333-44-5555');

INSERT INTO products (name, price, description) VALUES
  ('Laptop',   999.00, 'A fast laptop'),
  ('Keyboard',  49.00, 'Mechanical keyboard'),
  ('Monitor',  199.00, '27 inch display');

-- VULN:VULN-21:CWE-732 application DB user granted full privileges on everything
GRANT ALL PRIVILEGES ON *.* TO 'appuser'@'%';
FLUSH PRIVILEGES;
