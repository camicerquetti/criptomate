const express = require('express');
const router = express.Router();
const db = require('../config/db'); // Ajusta la ruta según tu estructura de carpetas
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const { generateToken } = require('../utils/jwtUtils'); // Importa la función generateToken
const authMiddleware = require('../middlewares/authMiddleware');
const nodemailer = require('nodemailer');
require('dotenv').config();

// Ruta protegida para pruebas
router.get('/protected-route', authMiddleware, (req, res) => {
  res.status(200).json({ message: 'This is a protected route', user: req.user });
});

// Ruta para obtener el saldo del usuario
router.get('/wallet', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  console.log('User ID:', userId); // Verificar el ID del usuario

  const sql = 'SELECT balance FROM users WHERE id = ?';

  try {
    const [results] = await db.query(sql, [userId]);

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({ balance: results[0].balance });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

// Ruta para manejar el registro
router.post('/register', [
  body('username').notEmpty().withMessage('Username is required'),
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
], async (req, res) => {
  // Validar datos
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, email, password } = req.body;

  try {
    // Verificar si el nombre de usuario o el correo electrónico ya existen
    const userCheckQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';
    const [results] = await db.query(userCheckQuery, [username, email]);

    if (results.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Hash de la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Consulta SQL para insertar un nuevo usuario con saldo inicial de 10 monedas
    const sql = 'INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)';
    await db.query(sql, [username, email, hashedPassword, 10]);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Internal server error:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// Ruta para manejar el login
router.post('/login', [
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  // Validar datos
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    // Consultar usuario por email
    const sql = 'SELECT * FROM users WHERE email = ?';
    const [results] = await db.query(sql, [email]);

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = results[0];

    // Comparar contraseñas
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generar token JWT
    const token = generateToken({ id: user.id, username: user.username });

    res.status(200).json({ message: 'Login successful', token }); // Incluye el token en la respuesta
  } catch (err) {
    console.error('Internal server error:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// Ruta para enviar monedas
router.post('/enviodemonedas', authMiddleware, async (req, res) => {
  const { fromUserId, toUserId, amount } = req.body;

  if (!fromUserId || !toUserId || !amount) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (amount <= 0) {
    return res.status(400).json({ error: 'Amount must be greater than zero' });
  }

  const connection = await db.getConnection();

  try {
    await connection.beginTransaction();

    const query = 'SELECT id, balance, isAdmin FROM users WHERE id IN (?, ?)';
    const [rows] = await connection.query(query, [fromUserId, toUserId]);

    if (rows.length < 2) {
      throw new Error('User not found');
    }

    const fromUser = rows.find(user => user.id === fromUserId);
    const toUser = rows.find(user => user.id === toUserId);

    if (!fromUser || !toUser) {
      throw new Error('User not found');
    }

    if (!fromUser.isAdmin) {
      throw new Error('Unauthorized');
    }

    if (fromUser.balance < amount) {
      throw new Error('Insufficient balance');
    }

    await connection.query('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, fromUserId]);
    await connection.query('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, toUserId]);
    await connection.query('INSERT INTO transactions (fromUserId, toUserId, amount) VALUES (?, ?, ?)', [fromUserId, toUserId, amount]);

    await connection.commit();
    res.status(200).json({ message: 'Transaction successful' });
  } catch (err) {
    console.error('Transaction error:', err);
    await connection.rollback();
    res.status(500).json({ error: 'Transaction error', details: err.message });
  } finally {
    connection.release();
  }
});

// Ruta para manejar la solicitud de monedas
router.post('/requestcoins', authMiddleware, async (req, res) => {
  const { toUserId, amount } = req.body; // `fromUserId` no se requiere aquí

  if (!toUserId || !amount) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (amount <= 0) {
    return res.status(400).json({ error: 'Amount must be greater than zero' });
  }

  try {
    // Verificar que el usuario que solicita monedas no sea administrador
    const requesterId = req.user.id; // Obtener ID del usuario autenticado
    const [requesterResult] = await db.query('SELECT isAdmin FROM users WHERE id = ?', [requesterId]);
    const requester = requesterResult[0];
    if (requester.isAdmin) {
      return res.status(403).json({ error: 'Admin users cannot request coins' });
    }

    // Verificar si el destinatario existe
    const [recipientResult] = await db.query('SELECT id FROM users WHERE id = ?', [toUserId]);
    if (recipientResult.length === 0) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    // Registrar la solicitud de monedas
    const sql = 'INSERT INTO coin_requests (fromUserId, toUserId, amount) VALUES (?, ?, ?)';
    await db.query(sql, [fromUserId, toUserId, amount]);

    // Enviar un mensaje al destinatario
    const message = `You have received a coin request of ${amount} coins from user ${fromUserId}. Please review it.`;
    const messageSql = 'INSERT INTO messages (fromUserId, toUserId, message) VALUES (?, ?, ?)';
    await db.query(messageSql, [fromUserId, toUserId, message]);

    res.status(200).json({ message: 'Request successful' });
  } catch (err) {
    console.error('Internal server error:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});
// Configura tu transporte de correo
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Ruta para manejar el formulario de contacto
router.post('/contact', (req, res) => {
  const { nombre, correo, mensaje } = req.body;

  // Validar los datos
  if (!nombre || !correo || !mensaje) {
    return res.status(400).json({ error: 'Todos los campos son requeridos.' });
  }

  const mailOptions = {
    from: correo,
    to: process.env.EMAIL_USER,
    subject: `Mensaje de contacto de ${nombre}`,
    text: mensaje,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return res.status(500).json({ error: 'Error al enviar el mensaje.' });
    }
    res.status(200).json({ message: 'Mensaje enviado exitosamente.' });
  });
});

module.exports = router;
