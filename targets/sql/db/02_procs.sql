USE vulnsql;
DELIMITER $$

-- Product search: dynamic SQL built by string concatenation inside a stored
-- procedure -> injectable via the `term` parameter.
DROP PROCEDURE IF EXISTS search_products $$
CREATE PROCEDURE search_products(IN term VARCHAR(200))
BEGIN
    -- VULN:VULN-71:CWE-89:taint SQL injection — dynamic SQL concatenated in a stored procedure
    SET @q = CONCAT("SELECT id, name, price FROM products WHERE name LIKE '%", term, "%'");
    PREPARE stmt FROM @q;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END $$

-- Authentication: builds the WHERE clause by concatenation -> auth bypass.
DROP PROCEDURE IF EXISTS authenticate $$
CREATE PROCEDURE authenticate(IN user VARCHAR(64), IN pass VARCHAR(64))
BEGIN
    -- VULN:VULN-72:CWE-89:taint SQL injection in authentication procedure (login bypass)
    SET @q = CONCAT("SELECT username, role FROM users WHERE username = '", user,
                    "' AND password = MD5('", pass, "')");
    PREPARE stmt FROM @q;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END $$

-- Report runs with the privileges of its (root) definer, not the caller.
DROP PROCEDURE IF EXISTS admin_report $$
-- VULN:VULN-76:CWE-250:config SQL SECURITY DEFINER runs with definer (root) privileges
CREATE DEFINER='root'@'%' PROCEDURE admin_report()
    SQL SECURITY DEFINER
BEGIN
    SELECT username, password, ssn FROM users;
END $$

-- Dynamic ORDER BY / table name concatenated from caller input.
DROP PROCEDURE IF EXISTS list_table $$
CREATE PROCEDURE list_table(IN tbl VARCHAR(64))
BEGIN
    -- VULN:VULN-78:CWE-89:taint dynamic table name concatenated into a query
    SET @q = CONCAT("SELECT * FROM ", tbl, " LIMIT 5");
    PREPARE stmt FROM @q;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END $$

DELIMITER ;
