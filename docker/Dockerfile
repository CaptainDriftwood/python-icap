FROM ubuntu:22.04

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    c-icap \
    libicapapi-dev \
    clamav \
    clamav-daemon \
    libclamav-dev \
    wget \
    curl \
    build-essential \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# Build and install squidclamav from source
RUN curl -L -o /tmp/squidclamav-7.2.tar.gz https://github.com/darold/squidclamav/archive/refs/tags/v7.2.tar.gz && \
    cd /tmp && \
    tar xzf squidclamav-7.2.tar.gz && \
    cd squidclamav-7.2 && \
    ./configure --with-c-icap && \
    make && \
    make install && \
    rm -rf /tmp/squidclamav-7.2 /tmp/squidclamav-7.2.tar.gz && \
    mkdir -p /usr/local/lib/c_icap && \
    ln -sf /usr/lib/$(uname -m)-linux-gnu/c_icap/squidclamav.so /usr/local/lib/c_icap/squidclamav.so

# Configure ClamAV
RUN mkdir -p /var/run/clamav && \
    chown clamav:clamav /var/run/clamav && \
    sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf && \
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf && \
    echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    echo "TCPAddr 127.0.0.1" >> /etc/clamav/clamd.conf && \
    echo "LogFile /var/log/clamav/clamav.log" >> /etc/clamav/clamd.conf && \
    echo "LogTime yes" >> /etc/clamav/clamd.conf && \
    mkdir -p /var/log/clamav && \
    chown -R clamav:clamav /var/log/clamav

# Configure c-icap
RUN mkdir -p /var/run/c-icap /var/log/c-icap && \
    chown -R c-icap:c-icap /var/run/c-icap /var/log/c-icap

# Copy c-icap configuration
COPY c-icap.conf /etc/c-icap/c-icap.conf

# Copy squidclamav configuration
COPY squidclamav.conf /etc/c-icap/squidclamav.conf

# Copy startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Expose ICAP port
EXPOSE 1344

# Start services
CMD ["/start.sh"]
