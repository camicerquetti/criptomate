const { verifyToken } = require('../utils/jwtUtils');

const authMiddleware = (req, res, next) => {
  // Obtener el token del encabezado Authorization
  const token = req.headers['authorization']?.split(' ')[1]; // Asume formato "Bearer TOKEN"

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // Verificar el token
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Failed to authenticate token', details: err.message });
  }
};

module.exports = authMiddleware;
