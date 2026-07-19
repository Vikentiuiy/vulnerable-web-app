package com.example.vulnapp.model;

/** Simple user record. */
public class User {
    public int id;
    public String username;
    public String role;
    public String bio;
    public String ssn;

    public User() {}

    public User(int id, String username, String role, String bio, String ssn) {
        this.id = id;
        this.username = username;
        this.role = role;
        this.bio = bio;
        this.ssn = ssn;
    }

    public int getId() { return id; }
    public String getUsername() { return username; }
    public String getRole() { return role; }
    public String getBio() { return bio; }
    public String getSsn() { return ssn; }
}
