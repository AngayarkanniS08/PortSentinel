FROM ubuntu:20.04

# Set non-interactive frontend
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    tcpdump \
    iptables \
    net-tools \
    curl \
    libpcap-dev \
    build-essential \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

RUN useradd -m -s /bin/bash sentinel && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 5000

CMD ["python3", "main.py"]