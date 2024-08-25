const jwt = require('jsonwebtoken');
const { jwtSecret, jwtExpiresIn } = require('../config/jwtconfig');

/**
 * Genera un token JWT para el usuario
 * @param {Object} payload - Datos a incluir en el token
 * @returns {string} - Token generado
 */
const generateToken = (payload) => {
  return jwt.sign(payload, jwtSecret, { expiresIn: jwtExpiresIn });
};

/**
 * Verifica un token JWT
 * @param {string} token - Token a verificar
 * @returns {Object} - Datos decodificados del token
 */
const verifyToken = (token) => {
  try {
    return jwt.verify(token, jwtSecret);
  } catch (err) {
    throw new Error('Invalid or expired token');
  }
};

module.exports = {
  generateToken,
  verifyToken
};