const mysql = require('mysql2/promise');
require('dotenv').config(); // Carga las variables de entorno desde el archivo .env

// Configura la conexión a la base de datos usando variables de entorno
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = db;
