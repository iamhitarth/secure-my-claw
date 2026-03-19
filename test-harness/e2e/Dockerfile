# Secure-My-Claw E2E Test Container
# Fresh Ubuntu with OpenClaw installed from scratch

FROM ubuntu:24.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    jq \
    sudo \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 22.x (LTS)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs

# Install Bats (Bash Automated Testing System)
RUN git clone https://github.com/bats-core/bats-core.git /tmp/bats \
    && /tmp/bats/install.sh /usr/local \
    && rm -rf /tmp/bats

# Install bats helpers
RUN git clone https://github.com/bats-core/bats-support.git /usr/local/lib/bats-support \
    && git clone https://github.com/bats-core/bats-assert.git /usr/local/lib/bats-assert

# Install OpenClaw fresh (as root, before switching user)
RUN npm install -g openclaw

# Create test user (not root)
RUN useradd -m -s /bin/bash testuser \
    && echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER testuser
WORKDIR /home/testuser

# Copy test files
COPY --chown=testuser:testuser tests/ /home/testuser/tests/
COPY --chown=testuser:testuser run-e2e.sh /home/testuser/

# Entry point
ENTRYPOINT ["/home/testuser/run-e2e.sh"]
