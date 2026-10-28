FROM python:3.11-slim

WORKDIR /app

# Add fs.ibae.lab hosts entry at container start so TLS SAN validation
# against AD FS's federation service name works via Tailscale.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 8443

# Use fs.ibae.lab -> AD FS Tailscale IP mapping via /etc/hosts on host,
# passed into container via docker-compose extra_hosts.

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8443"]
