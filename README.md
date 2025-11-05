# EE4032 Authentication Demo

This repository contains a minimal full-stack example of Sign-In with Ethereum (SIWE) authentication.
It includes:

- **Backend (`server/`)** – Express.js API that issues nonces, verifies SIWE signatures, and returns JWTs.
- **Frontend (`frontend/`)** – Vite + React application that connects a MetaMask (or other injected) wallet with wagmi, signs SIWE messages, and makes authenticated requests.

## Prerequisites

- Node.js 18+
- npm 9+
- A browser wallet such as MetaMask to test the flow.

## Getting started

### Backend

```bash
cd server
npm install
npm start
```

The API runs on [http://localhost:4000](http://localhost:4000) by default. You can set `PORT`, `JWT_SECRET`, and `CLIENT_ORIGIN` environment variables if needed.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server listens on [http://localhost:5173](http://localhost:5173). Update `VITE_API_URL` in `frontend/.env` (or set an environment variable) if your backend runs elsewhere.

## Authentication flow

1. Connect a wallet through wagmi’s injected connector (e.g., MetaMask).
2. Request a nonce from the backend and build a SIWE message.
3. Sign the message in the wallet and send it to the backend.
4. Backend verifies the signature and issues a JWT.
5. Frontend stores the token locally and uses it to access protected API routes.

This setup is designed for local development and demonstration purposes only. For production use, add durable storage for nonces, HTTPS, stricter CORS rules, and persistent session handling.
