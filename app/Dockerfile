FROM python:3.12-alpine

# Alpine over python:3.12-slim (Debian) -- verified before switching: every
# native-extension dependency this app pulls in (uvloop, httptools,
# psycopg2-binary, bcrypt) publishes musllinux wheels, so nothing needs a
# compiler/build toolchain here; the full test suite (127+ tests) passes
# unchanged when run inside this image; and a Trivy scan of the built image
# reports ZERO CRITICAL/HIGH findings on the alpine OS layer, vs. a long
# list of unfixed Debian-trixie base-package CVEs (perl-base, util-linux,
# mount, login, ncurses, systemd libs, etc. -- see git history/.trivyignore
# for what those were) that "apt-get upgrade" could never resolve because
# Debian hadn't shipped patches yet. Alpine's minimal base (no perl, no
# systemd, no login/mount tooling) simply doesn't carry that surface.
#
# bash + openssl + ca-certificates -- needed because the container will
# execute easyrsa (via openvpn-install.sh, which is bash, not sh) against
# the bind-mounted host /etc/openvpn directory. Alpine's default shell is
# busybox ash, not bash, so bash has to be installed explicitly (unlike the
# Debian slim image, which included it already).
RUN apk add --no-cache bash openssl ca-certificates

WORKDIR /app

COPY requirements.txt .
# Upgrade pip itself first -- pip versions bundled in base images tend to
# lag behind and pick up known, already-patched CVEs otherwise.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    # The base image also carries a bundled pip wheel under ensurepip/
    # (for `python -m ensurepip`/venv bootstrapping) -- an old pip version
    # with its own vendored, outdated setuptools reference baked into its
    # METADATA. This app never runs ensurepip or creates venvs at runtime
    # (dependencies are all installed above, at build time), so the wheel
    # is dead weight that exists only to trip a vulnerability scanner over
    # code that's never executed. Remove it.
    && rm -rf /usr/local/lib/python3.12/ensurepip/_bundled

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
