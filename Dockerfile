# ── Stage 1: build native modules (node-pty needs python/make/g++) ──────────
FROM node:20-alpine AS builder

RUN apk add --no-cache python3 make g++ bash

WORKDIR /app

COPY package*.json ./
RUN npm install

# ── Stage 2: lean runtime image ─────────────────────────────────────────────
FROM node:20-alpine

# bash + docker CLI (needed to exec into other containers via the socket)
RUN apk add --no-cache bash curl docker-cli

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY server.js      ./
COPY public/        ./public/
COPY package.json   ./

ENV NODE_ENV=production
ENV PORT=3000
ENV SHELL=/bin/bash

EXPOSE 3000

CMD ["node", "server.js"]
