package com.example.vulnapp.infra

import org.springframework.stereotype.Component
import javax.sql.DataSource
import java.sql.Connection

/** Exposes raw JDBC connections on purpose so controllers can build SQL by
 *  string concatenation (the SQLi sinks). Plumbing, not a planted vuln. */
@Component
class Db(private val dataSource: DataSource) {
    fun connection(): Connection = dataSource.connection
}
