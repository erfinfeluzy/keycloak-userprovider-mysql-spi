package com.erfinfeluzy.customkeycloakspi;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.keycloak.component.ComponentModel;
import static com.erfinfeluzy.customkeycloakspi.CustomUserStorageProviderConstants.*;

public class DbUtil {

    public static Connection getConnection(ComponentModel config) throws SQLException{
        String driverClass = config.get(CONFIG_KEY_JDBC_DRIVER);
        // String driverClass = "com.mysql.cj.jdbc.Driver";
        try {
            Class.forName(driverClass);
        }
        catch(ClassNotFoundException nfe) {
            throw new RuntimeException("Invalid JDBC driver: " + driverClass + ". Please check if your driver if properly installed");
        }
        
        // return DriverManager.getConnection(
        //             "jdbc:mysql://127.0.0.1:3306/inventory?useSSL=false&allowPublicKeyRetrieval=true",
        //             "mysqluser",
        //             "mysqlpw");

        return DriverManager.getConnection(
                    config.get(CONFIG_KEY_JDBC_URL),
                    config.get(CONFIG_KEY_DB_USERNAME),
                    config.get(CONFIG_KEY_DB_PASSWORD));
    }
}