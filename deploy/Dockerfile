# ==============================================================================
# Go Text Intelligence - Production Dockerfile
#
# Multi-stage build:
#   1. Build Go binary
#   2. Build frontend
#   3. Run with Caddy reverse proxy
# ==============================================================================

# Stage 1: Build Go binary
FROM golang:1.23-alpine AS go-build

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY deepgram.toml ./
RUN CGO_ENABLED=0 GOOS=linux go build -o server main.go

# Stage 2: Build frontend
FROM node:24-alpine AS frontend-build

RUN corepack enable && corepack prepare pnpm@10.0.0 --activate
WORKDIR /build/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

# Stage 3: Production image with Caddy
FROM caddy:2-builder AS caddy-build

RUN xcaddy build \
    --with github.com/mholt/caddy-ratelimit

FROM alpine:3.20

# Install ca-certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Copy custom Caddy with rate limiting
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy

WORKDIR /app

# Copy Go binary
COPY --from=go-build /build/server ./server
COPY --from=go-build /build/deepgram.toml ./deepgram.toml

# Copy built frontend
COPY --from=frontend-build /build/frontend/dist ./frontend/dist

# Copy Caddy configuration and start script
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY deploy/start.sh ./start.sh
RUN chmod +x ./start.sh

# Set environment variables
ENV BACKEND_PORT=8081
ENV PORT=8081
ENV HOST=0.0.0.0
ENV BACKEND_CMD="./server"

EXPOSE 8080

CMD ["./start.sh"]
