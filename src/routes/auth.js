const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const axios    = require('axios');
const verifyToken = require('../middleware/verifyToken');

const IO_URL = process.env.IO_SERVICE_URL;

// ============================================================
// Helper: creează un JWT pentru un user
// Payload-ul conține minimul necesar — id și rol
// ============================================================
const signToken = (user) => {
  return jwt.sign(
    { userId: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
  );
};


// ============================================================
// POST /auth/register
// Înregistrează un user nou
//
// Flow:
//   1. Validare input
//   2. Hash parolă cu bcrypt
//   3. Trimite la IO Service să creeze userul
//   4. Returnează JWT
//
// Body: { email, password }
// ============================================================
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validare de bază
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Hash-uim parola înainte să o trimitem la IO Service
    // Cost factor 10 = balanță bună între securitate și viteză
    const password_hash = await bcrypt.hash(password, 10);

    // Cerem IO Service să creeze userul
    // Dacă emailul există deja, IO Service returnează 409
    const { data: newUser } = await axios.post(`${IO_URL}/users`, {
      email,
      password_hash,
    });

    const token = signToken(newUser);

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: { id: newUser.id, email: newUser.email, role: newUser.role },
    });
  } catch (err) {
    // Propagăm eroarea de la IO Service dacă e 409 (email duplicat)
    if (err.response?.status === 409) {
      return res.status(409).json({ error: 'Email already in use' });
    }
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// ============================================================
// POST /auth/login
// Autentifică un user existent
//
// Flow:
//   1. Validare input
//   2. Cerem IO Service userul după email
//   3. Comparăm parola cu bcrypt
//   4. Returnăm JWT dacă totul e ok
//
// Body: { email, password }
// ============================================================
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Cerem IO Service userul — endpoint-ul acesta returnează și password_hash
    let user;
    try {
      const { data } = await axios.get(`${IO_URL}/users/email/${email}`);
      user = data;
    } catch (err) {
      // IO Service returnează 404 dacă emailul nu există
      // Răspundem cu același mesaj indiferent de motiv (securitate)
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Comparăm parola primită cu hash-ul din DB
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = signToken(user);

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// ============================================================
// GET /auth/verify
// Validează un JWT și returnează payload-ul
//
// Folosit de:
//   - Kong pentru a valida token-ul înainte să ruteze requestul
//   - Alte servicii care vor să știe cine face requestul
//
// Header: Authorization: Bearer <token>
// ============================================================
router.get('/verify', verifyToken, (req, res) => {
  // Dacă middleware-ul a trecut, token-ul e valid
  // req.user conține payload-ul decodat: { userId, role }
  res.json({
    valid: true,
    user: req.user,
  });
});


// ============================================================
// GET /auth/me
// Returnează detaliile userului autentificat curent
//
// Util pentru frontend — după login, poți cere profilul tău
// Header: Authorization: Bearer <token>
// ============================================================
router.get('/me', verifyToken, async (req, res) => {
  try {
    const { data: user } = await axios.get(`${IO_URL}/users/${req.user.userId}`);
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Could not fetch user details' });
  }
});

module.exports = router;