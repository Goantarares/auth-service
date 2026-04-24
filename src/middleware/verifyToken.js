// Middleware reutilizabil — verifică dacă request-ul are un JWT valid
// Folosit pe rutele protejate și expus ca endpoint pentru Kong

const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  // JWT-ul vine în headerul Authorization: Bearer <token>
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // extragem după "Bearer "

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // jwt.verify aruncă eroare dacă token-ul e invalid sau expirat
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Punem payload-ul decodat pe request pentru rutele de după
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(403).json({ error: 'Invalid token' });
  }
};