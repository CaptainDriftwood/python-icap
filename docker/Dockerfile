FROM ubuntu:22.04

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    c-icap \
    c-icap-mod-virus-scan \
    clamav \
    clamav-daemon \
    squidclamav \
    wget \
    && rm -rf /var/lib/apt/lists/*

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
