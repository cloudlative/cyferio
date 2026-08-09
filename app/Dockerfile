FROM python:3.12-slim

# openssl + easy-rsa's own shell deps -- needed because the container will
# execute easyrsa (via openvpn-install.sh) against the bind-mounted host
# /etc/openvpn directory. bash is already present in this base image.
# `apt-get upgrade` pulls in whatever CVE fixes Debian has already
# published for packages already in the base image (Trivy flags some base-
# image CVEs with no upstream fix at all yet -- those can't be resolved
# here, only by a later base-image rebuild once Debian ships one).
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
# Upgrade pip itself first -- the base image's pinned pip has known CVEs
# (see .github/workflows/build.yml's Trivy scan) with fixes already
# released upstream.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

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
