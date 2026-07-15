package com.example.vulnapp.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * Thin JDBC helper. Exposes the raw {@link Connection} on purpose so the
 * controllers can build SQL by string concatenation (the SQLi sinks).
 */
@Component
public class Db {

    private final DataSource dataSource;
    private final JdbcTemplate jdbc;

    @Autowired
    public Db(DataSource dataSource) {
        this.dataSource = dataSource;
        this.jdbc = new JdbcTemplate(dataSource);
    }

    public Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    public JdbcTemplate jdbc() {
        return jdbc;
    }
}
