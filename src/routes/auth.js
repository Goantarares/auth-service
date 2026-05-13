const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const axios    = require('axios');
const verifyToken = require('../middleware/verifyToken');

const IO_URL = process.env.IO_SERVICE_URL;

// Header trimis la fiecare request către IO Service
// Verificat de middleware-ul serviceAuth din IO Service
const internalHeaders = {
  'x-internal-secret': process.env.INTERNAL_SECRET
};

const signToken = (user) => {
  return jwt.sign(
    { userId: user.id, role: user.role, iss: 'flights-app' },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
  );
};

router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const password_hash = await bcrypt.hash(password, 10);

    const { data: newUser } = await axios.post(
      `${IO_URL}/users`,
      { email, password_hash },
      { headers: internalHeaders }
    );

    const token = signToken(newUser);

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: { id: newUser.id, email: newUser.email, role: newUser.role },
    });
  } catch (err) {
    if (err.response?.status === 409) {
      return res.status(409).json({ error: 'Email already in use' });
    }
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    let user;
    try {
      const { data } = await axios.get(
        `${IO_URL}/users/email/${email}`,
        { headers: internalHeaders }
      );
      user = data;
    } catch (err) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

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

router.get('/verify', verifyToken, (req, res) => {
  res.json({
    valid: true,
    user: req.user,
  });
});

router.get('/me', verifyToken, async (req, res) => {
  try {
    const { data: user } = await axios.get(
      `${IO_URL}/users/${req.user.userId}`,
      { headers: internalHeaders }
    );
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Could not fetch user details' });
  }
});

module.exports = router;