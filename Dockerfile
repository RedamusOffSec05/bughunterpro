FROM ubuntu:24.04

LABEL description="PentestGPT + ROT05 — AI-Powered AD Penetration Testing"
LABEL version="2.0.0"

ENV DEBIAN_FRONTEND=noninteractive

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        # Build essentials
        build-essential \
        software-properties-common \
        ca-certificates \
        gnupg \
        # Python
        python3.12 \
        python3-pip \
        python3-venv \
        python3-dev \
        # Core tools
        nmap \
        netcat-openbsd \
        curl \
        wget \
        git \
        sudo \
        # AD enumeration
        smbclient \
        ldap-utils \
        samba-common-bin \
        enum4linux \
        # Network utilities
        net-tools \
        dnsutils \
        whois \
        iputils-ping \
        # VPN
        openvpn \
        # Password cracking
        hashcat \
        john \
        # Utilities
        jq \
        ripgrep \
        tmux \
        vim \
    && apt-get autoremove -y \
    && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js v20 ───────────────────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# ── Remove EXTERNALLY-MANAGED markers and conflicting system packages ─────────
# FIX: use find instead of glob — glob in RUN doesn't expand reliably
# FIX: || true so the remove doesn't fail if cryptography isn't installed
RUN find /usr/lib/python3* -name EXTERNALLY-MANAGED -delete 2>/dev/null || true && \
    apt-get remove -y python3-cryptography 2>/dev/null || true && \
    apt-get autoremove -y

# ── Install uv system-wide (avoids root/user PATH mismatch later) ─────────────
# FIX: original installed uv as pentester then called it as root using full path;
#      installing system-wide makes it available to both users cleanly.
RUN curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh

# ── Claude Code Router (global npm package) ───────────────────────────────────
RUN npm install -g @musistudio/claude-code-router

# ── Python security / AD stack (system-wide, available to all users) ──────────
RUN pip3 install --break-system-packages \
        colorama>=0.4.6 \
        cryptography>=41.0.0 \
        requests>=2.28.0 \
        impacket \
        certipy-ad

# netexec (successor to crackmapexec) — fall back to cme if netexec unavailable
RUN pip3 install --break-system-packages netexec 2>/dev/null || \
    pip3 install --break-system-packages crackmapexec 2>/dev/null || true

# ── windapsearch ──────────────────────────────────────────────────────────────
RUN git clone --depth=1 https://github.com/ropnop/windapsearch.git /opt/windapsearch && \
    pip3 install --break-system-packages \
        -r /opt/windapsearch/requirements.txt 2>/dev/null || true && \
    ln -s /opt/windapsearch/windapsearch.py /usr/local/bin/windapsearch.py

# ── Responder ─────────────────────────────────────────────────────────────────
RUN git clone --depth=1 https://github.com/lgandx/Responder.git /opt/Responder && \
    ln -s /opt/Responder/Responder.py /usr/local/bin/responder

# ── Non-root pentester user ───────────────────────────────────────────────────
RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN mkdir -p /workspace /app \
        /home/pentester/.claude \
        /home/pentester/.claude-code-router && \
    chown -R pentester:pentester \
        /workspace /app \
        /home/pentester/.claude \
        /home/pentester/.claude-code-router

# ── Switch to pentester user for user-scoped installs ────────────────────────
USER pentester
WORKDIR /app

# Claude Code CLI installs to ~/.local/bin/claude
RUN curl -fsSL https://claude.ai/install.sh | bash

ENV PATH="/home/pentester/.local/bin:$PATH"

# ── Copy project files ────────────────────────────────────────────────────────
# pyproject.toml copied separately so pip cache survives code-only changes
COPY --chown=pentester:pentester requirements.txt /app/requirements.txt

# ROT05 AD pentesting toolkit
COPY --chown=pentester:pentester red_offensive_team_05.py /app/red_offensive_team_05.py
COPY --chown=pentester:pentester tests/ /app/tests/

# PentestGPT project files (copy these last — most likely to change)
COPY --chown=pentester:pentester scripts/entrypoint.sh     /home/pentester/entrypoint.sh
COPY --chown=pentester:pentester scripts/ccr-config-template.json \
                                 /app/scripts/ccr-config-template.json

# ── Finalise permissions and symlinks as root ─────────────────────────────────
USER root
RUN chmod +x /home/pentester/entrypoint.sh && \
    chmod +x /app/red_offensive_team_05.py && \
    ln -s /app/red_offensive_team_05.py /usr/local/bin/rot05

USER pentester

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

WORKDIR /workspace

ENTRYPOINT ["/home/pentester/entrypoint.sh"]
# Default: drop into an interactive shell
# Override with: docker run ... rot05 -t 10.10.10.10 --enum
CMD ["/bin/bash"]
