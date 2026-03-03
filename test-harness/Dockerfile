FROM node:22-bookworm-slim

# Install dependencies for OpenClaw testing
RUN apt-get update && apt-get install -y \
    curl \
    git \
    jq \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install OpenClaw (will be latest version)
RUN npm install -g openclaw@latest

# Create test user (non-root)
RUN useradd -m -s /bin/bash testuser
USER testuser
WORKDIR /home/testuser

# Copy test harness
COPY --chown=testuser:testuser . /home/testuser/test-harness/

# Default command runs validation
CMD ["node", "/home/testuser/test-harness/validate-config-blocks.js", "/home/testuser/test-harness/guide.md"]
