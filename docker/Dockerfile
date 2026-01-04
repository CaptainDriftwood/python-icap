# Stage 1: Build squidclamav from source
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    c-icap \
    libicapapi-dev \
    libclamav-dev \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Build squidclamav v7.2 from source
RUN curl -L -o /tmp/squidclamav-7.2.tar.gz https://github.com/darold/squidclamav/archive/refs/tags/v7.2.tar.gz && \
    cd /tmp && \
    tar xzf squidclamav-7.2.tar.gz && \
    cd squidclamav-7.2 && \
    ./configure --with-c-icap && \
    make && \
    make install && \
    rm -rf /tmp/squidclamav-7.2 /tmp/squidclamav-7.2.tar.gz

# Stage 2: Runtime image
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    c-icap \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    ca-certificates \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy compiled squidclamav module from builder
COPY --from=builder /usr/lib/*-linux-gnu/c_icap/squidclamav.so /usr/local/lib/c_icap/
COPY --from=builder /usr/share/c_icap/templates/squidclamav /usr/share/c_icap/templates/squidclamav

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

# Copy configuration files
COPY c-icap.conf /etc/c-icap/c-icap.conf
COPY squidclamav.conf /etc/c-icap/squidclamav.conf

# Copy startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 1344 11344

CMD ["/start.sh"]