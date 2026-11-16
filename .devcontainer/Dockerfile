FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libevent-dev \
    libssl-dev \
    libxml2-dev \
    python3 \
    python-is-python3 \
    python3-venv \
    python3-pip \
    sudo \
    git \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash zwave \
    && echo 'zwave ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/zwave \
    && chmod 0440 /etc/sudoers.d/zwave

ENV PATH="/home/zwave/.local/bin:${PATH}"
USER zwave
