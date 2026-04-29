const mysql = require("mysql2/promise");

const pool = mysql.createPool(process.env.MYSQL_URL);

module.exports = pool;

console.log("Using MYSQL_URL:", !!process.env.MYSQL_URL);