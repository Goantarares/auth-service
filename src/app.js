require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const logger  = require('./logger');

const authRouter = require('./routes/auth');

const app  = express();
const PORT = process.env.PORT || 3001;

app.use(express.json());
app.use('/auth', authRouter);
// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ============================================================
// Pornire server
// Verificăm că IO Service e accesibil înainte să pornim
// Altfel, register și login ar pica imediat
// ============================================================
const startServer = async () => {
  const IO_URL = process.env.IO_SERVICE_URL;

  // Reîncercăm conexiunea la IO Service de mai multe ori
  // (IO Service poate porni puțin după Auth Service)
  let retries = 10;
  while (retries > 0) {
    try {
      await axios.get(`${IO_URL}/health`);
      logger.info('IO Service is reachable');
      break;
    } catch {
      retries--;
      logger.warn('Waiting for IO Service', { retriesLeft: retries });
      await new Promise(r => setTimeout(r, 3000)); // așteptăm 3 secunde
    }
  }

  if (retries === 0) {
    logger.error('IO Service unreachable. Exiting.');
    process.exit(1);
  }

  app.listen(PORT, () => logger.info('Auth Service running', { port: PORT }));
};

startServer();