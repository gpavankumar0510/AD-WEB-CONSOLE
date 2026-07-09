'use strict';
const winston = require('winston');
const fs = require('fs');
if (!fs.existsSync('logs')) fs.mkdirSync('logs', { recursive: true });
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) => `[${timestamp}] ${level.toUpperCase()}: ${message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/console.log', maxsize: 10485760, maxFiles: 5 }),
    new winston.transports.File({ filename: 'logs/audit.log', maxsize: 10485760, maxFiles: 10 }),
  ],
});
module.exports = logger;
