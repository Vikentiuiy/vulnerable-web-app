package com.example.vulnapp

import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.jdbc.core.JdbcTemplate

@SpringBootApplication
class VulnApp {
    // Seed the in-memory H2 database with an intentionally-insecure schema + data.
    @Bean
    fun seed(jdbc: JdbcTemplate) = CommandLineRunner {
        jdbc.execute(
            """CREATE TABLE IF NOT EXISTS users (
                 id INT AUTO_INCREMENT PRIMARY KEY,
                 username VARCHAR(64) NOT NULL,
                 password VARCHAR(64) NOT NULL,      -- VULN:VULN-19:CWE-256:config unsalted MD5
                 secret_answer VARCHAR(128),         -- VULN:VULN-20:CWE-312:config cleartext secret
                 role VARCHAR(16) NOT NULL DEFAULT 'user',
                 bio VARCHAR(1024),
                 ssn VARCHAR(32))"""
        )
        jdbc.execute(
            "CREATE TABLE IF NOT EXISTS products (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(128), price DECIMAL(10,2))"
        )
        val users = jdbc.queryForObject("SELECT COUNT(*) FROM users", Int::class.java) ?: 0
        if (users == 0) {
            jdbc.update("INSERT INTO users (username,password,secret_answer,role,bio,ssn) VALUES (?,?,?,?,?,?)",
                "admin", "0192023a7bbd73250516f069df18b500", "my-first-car", "admin", "Site administrator", "111-22-3333")
            jdbc.update("INSERT INTO users (username,password,secret_answer,role,bio,ssn) VALUES (?,?,?,?,?,?)",
                "alice", "7c6a180b36896a0a8c02787eeafb0e4c", "fluffy", "user", "Hi, I am Alice", "222-33-4444")
            jdbc.update("INSERT INTO products (name,price) VALUES ('Laptop',999.00),('Keyboard',49.00)")
        }
    }
}

fun main(args: Array<String>) {
    runApplication<VulnApp>(*args)
}
