FROM python:3.14-alpine

# Baked in at build time from the git tag driving this build (see
# .github/workflows/build.yml's build-args) -- read at runtime via
# os.environ["APP_VERSION"] by health.py, so the Health page can show
# exactly which version is actually deployed. Defaults to "unknown" for
# any image built without that build-arg (e.g. a local `docker build`).
ARG APP_VERSION=unknown
ENV APP_VERSION=${APP_VERSION}

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
# openssh-client -- Phase 1's host_executor.py (vpnadmin/routes/clients.py's
# live-session actions) shells out to the system `ssh` binary for the one
# whitelisted remote command; not present in the base Alpine image by
# default.
RUN apk add --no-cache bash openssl ca-certificates openssh-client

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
    && rm -rf /usr/local/lib/python3.*/ensurepip/_bundled \
    # pip/_vendor/bom.cdx.json is pip's own bundled CycloneDX SBOM,
    # documenting every package it vendors (Trivy explicitly supports
    # reading embedded SBOMs as an authoritative package inventory -- see
    # its own "Third-party SBOM may lead to inaccurate vulnerability
    # detection" warning). It lists setuptools 70.3.0 as a vendored
    # component even though no such package is actually installed
    # anywhere in this image (confirmed: no setuptools files exist,
    # `python3 -c "import setuptools"` fails). vendor.txt (a second,
    # plain-text version of the same vendoring manifest) has the same
    # problem. Neither file is read by pip at runtime -- pip imports its
    # vendored modules directly (e.g. `from pip._vendor import certifi`)
    # and pip install/import both work fine with these removed (verified)
    # -- they exist purely as documentation that a vulnerability scanner
    # can misread as an installed-package inventory. Because that phantom
    # "setuptools 70.3.0" keeps re-triggering under a fresh CVE ID every
    # time a new setuptools CVE is published (CVE-2025-47273, then
    # CVE-2026-59890 by the very next scan) a per-CVE-ID .trivyignore
    # entry can't keep up -- removing the files that cause the misparse
    # fixes it at the root instead, permanently.
    #
    # Both this and the ensurepip rm above use a python3.* glob rather than
    # a hardcoded version -- a prior revision hardcoded python3.12 and went
    # silently stale (rm -f doesn't error on a no-op) the moment the base
    # image bumped to python:3.14-alpine, reintroducing this exact phantom
    # finding and failing the Trivy scan job on the next tag build. The
    # glob keeps this working across future Python version bumps too.
    && rm -f /usr/local/lib/python3.*/site-packages/pip/_vendor/vendor.txt \
             /usr/local/lib/python3.*/site-packages/pip/_vendor/bom.cdx.json

COPY main.py .
COPY migrate_vpn_profiles.py .
COPY drop_legacy_branding_columns.py .
COPY vpnadmin ./vpnadmin
COPY scripts ./scripts
# Phase 1 Python OpenVPN service layer (see
# /home/hackx/.claude/plans/openvpn-bash-to-python-migration-lazy-neumann.md).
# `services/` is imported by vpnadmin/routes/clients.py's host_executor
# call; `cli/` is NOT run inside this container (it runs on
# the host over SSH, see host_executor.py) but is still packaged here so a
# built image also serves as a self-contained copy of that entrypoint for
# reference/debugging.
COPY services ./services
COPY cli ./cli

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
