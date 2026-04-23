const mysql = require("mysql2") //import mysql2 package

const db = mysql.createPool({   //Creates a connection pool instead of single connection. Pool is better because it can handle many requests.
    host: process.env.DB_HOST, //Reads database host from .env
    user: process.env.DB_USER, //Reads MySQL username.
    password: process.env.DB_PASSWORD, //Reads MySQL password.
    database: process.env.DB_NAME, //Reads database name.
    waitForConnections:true,  //If all connections are busy, wait for free connection.
    connectionLimit: 10, //Maximum 10 connections at a time.
      queueLimit: 0 //No limit for waiting queue.

})
module.exports = db.promise();