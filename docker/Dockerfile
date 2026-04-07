# Stage 1: Build
FROM node:22-slim AS build

RUN corepack enable pnpm

WORKDIR /app

# Install dependencies first (layer cache)
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# Copy source and build
COPY src/ src/
COPY tsup.config.ts ./
RUN pnpm build

# Prune dev dependencies
RUN pnpm install --frozen-lockfile --prod

# Stage 2: Runtime
FROM node:22-slim

LABEL org.opencontainers.image.source="https://github.com/jmolz/mcp-guard"
LABEL org.opencontainers.image.description="Security proxy daemon for MCP servers"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user
RUN groupadd --system mcp-guard && useradd --system --gid mcp-guard mcp-guard

WORKDIR /app

# Copy built artifacts and production dependencies
COPY --from=build /app/dist/ dist/
COPY --from=build /app/node_modules/ node_modules/
COPY --from=build /app/package.json package.json
COPY mcp-guard.example.yaml mcp-guard.example.yaml

# Create data directory with correct ownership
RUN mkdir -p /home/mcp-guard/.config/mcp-guard && \
    chown -R mcp-guard:mcp-guard /home/mcp-guard /app

USER mcp-guard

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node dist/cli.js health || exit 1

ENTRYPOINT ["node", "dist/cli.js"]
CMD ["start"]
