FROM mcr.microsoft.com/devcontainers/python:3.11

# Install common system packages useful for security tooling
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     git \
     curl \
     jq \
     build-essential \
     libpcap-dev \
  && apt-get clean && rm -rf /var/lib/apt/lists/*
