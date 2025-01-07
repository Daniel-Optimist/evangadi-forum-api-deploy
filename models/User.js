// `CREATE TABLE users(
//     userid INT(20) NOT NULL AUTO_INCREMENT,
//     username VARCHAR(20) NOT NULL,
//     firstname VARCHAR(20) NOT NULL,
//     lastname VARCHAR(20) NOT NULL,
//     email VARCHAR(40) NOT NULL,
//     password VARCHAR(100) NOT NULL,
//     PRIMARY KEY(userid)
// );`;

`CREATE TABLE users (
    userid INT(20) NOT NULL AUTO_INCREMENT,
    username VARCHAR(20) NOT NULL,
    firstname VARCHAR(20) NOT NULL,
    lastname VARCHAR(20) NOT NULL,
    email VARCHAR(40) NOT NULL,
    password VARCHAR(100) NOT NULL,
    resetPasswordToken VARCHAR(100) DEFAULT NULL,
    resetPasswordExpires BIGINT DEFAULT NULL,
    PRIMARY KEY(userid)
);`