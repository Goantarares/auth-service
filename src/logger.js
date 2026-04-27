const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()  // format JSON — ușor de procesat de Prometheus/Grafana
  ),
  transports: [
    new winston.transports.Console()
  ]
});

module.exports = logger;