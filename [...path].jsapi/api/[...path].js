// Vercel serverless adapter for the existing Node HTTP application.
// SQLite is copied to /tmp because the deployment filesystem is read-only.
const path = require('node:path');

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET must be configured in Vercel Project Settings.');
}

process.env.DB_FILE = process.env.DB_FILE || path.join('/tmp', 'online-quiz-app.sqlite');

const { server } = require('../server');

module.exports = function handler(req, res) {
  server.emit('request', req, res);
};
