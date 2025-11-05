import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { SiweMessage, generateNonce } from 'siwe';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const rawClientOrigins =
  process.env.CLIENT_ORIGIN ||
  [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:4173',
    'http://127.0.0.1:4173',
  ].join(',');

const allowedOrigins = rawClientOrigins
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      try {
        const parsed = new URL(origin);
        if (['localhost', '127.0.0.1'].includes(parsed.hostname)) {
          return callback(null, true);
        }
      } catch (error) {
        console.warn('Unable to parse request origin for CORS check:', error);
      }

      console.warn(`Blocked CORS origin: ${origin}`);
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
  }),
);
app.use(express.json());
app.use(cookieParser());

// In-memory nonce store keyed by nonce value.
// In production this should be persisted and associated with a specific wallet address and expiration.
const nonces = new Map();

app.get('/api/nonce', (_req, res) => {
  const nonce = generateNonce();
  nonces.set(nonce, { createdAt: Date.now() });
  res.json({ nonce });
});

app.post('/api/verify', async (req, res) => {
  const { message, signature } = req.body ?? {};

  if (!message || !signature) {
    return res.status(400).json({ error: 'Missing SIWE message or signature' });
  }

  let siweMessage;
  try {
    siweMessage = new SiweMessage(message);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid SIWE message', details: err.message });
  }

  const { nonce } = siweMessage;
  const nonceRecord = nonce ? nonces.get(nonce) : undefined;
  if (!nonceRecord) {
    return res.status(400).json({ error: 'Nonce not found or already used' });
  }

  try {
    const result = await siweMessage.verify({ signature });
    if (!result.success) {
      return res.status(400).json({ error: 'Invalid signature' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'Signature verification failed', details: err.message });
  }

  nonces.delete(nonce);

  const token = jwt.sign(
    {
      address: siweMessage.address,
    },
    JWT_SECRET,
    { expiresIn: '1h' },
  );

  res.json({
    token,
    address: siweMessage.address,
  });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1] ?? req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  return next();
}

app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({
    message: 'You have access to a protected resource!',
    address: req.user.address,
  });
});

app.listen(PORT, () => {
  console.log(`Authentication server running on port ${PORT}`);
});
