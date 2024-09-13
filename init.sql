CREATE DATABASE IF NOT EXISTS login_db;

USE login_db;

CREATE TABLE IF NOT EXISTS users (
    id INT(15) NOT NULL AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL,
    email VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    password_changed TINYINT(1) DEFAULT 0,
    role ENUM('admin', 'usuario', 'invitado') DEFAULT 'usuario',
    PRIMARY KEY (id)
);