FROM python:3.12-slim

# openssl + easy-rsa's own shell deps -- needed because the container will
# execute easyrsa (via openvpn-install.sh) against the bind-mounted host
# /etc/openvpn directory. bash is already present in this base image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY vpnadmin ./vpnadmin
COPY scripts ./scripts

# The two toolkit scripts are bind-mounted at runtime from the repo root
# (see docker-compose.yml) rather than baked into the image, so the
# container always runs whatever version is checked out on the host --
# no image rebuild needed just to pick up a script change.
RUN mkdir -p /opt/openvpn-toolkit /app/data

EXPOSE 8000

# Runs as root: needed to read/write the bind-mounted /etc/openvpn (root-owned
# on the host) and execute easyrsa. USE_SUDO=false in docker-compose.yml
# reflects that -- sudo isn't installed in this image and isn't needed when
# the process already has the privilege it would otherwise escalate to.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
