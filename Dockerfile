FROM python:3.13-slim

# Prevent Python from creating .pyc files and buffer stdout/stderr.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create an unprivileged application user.
RUN groupadd --system honeypot \
    && useradd --system \
       --gid honeypot \
       --home-dir /home/honeypot \
       --create-home \
       --shell /usr/sbin/nologin \
       honeypot

WORKDIR /app/new

# Install Python dependencies first for better Docker layer caching.
COPY new/requirements.txt /tmp/requirements.txt
COPY new/requirements-asyncssh.txt /tmp/requirements-asyncssh.txt

RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir -r /tmp/requirements-asyncssh.txt

# Copy the current honeypot application.
COPY new/ /app/new/

# Create writable runtime directories.
RUN mkdir -p /app/new/logs \
    && chown -R honeypot:honeypot /app/new

# Run as an unprivileged user.
USER honeypot

# SSH and Telnet.
EXPOSE 2222 2323

# Start the honeypot using the AsyncSSH transport.
ENV HONEYPOT_SSH_ADAPTER=asyncssh
CMD ["python", "main.py"]
