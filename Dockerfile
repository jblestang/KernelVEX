# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="kernelvex" \
      org.opencontainers.image.description="Industrial Linux kernel CVE triage & OpenVEX 0.2.0 orchestrator" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VENV_DIR=/opt/venv \
    KERNELVEX_CACHE_DIR=/cache

# Pinned upstream OSS dependencies (see PINS.lock)
ARG KERNEL_CVE_TRIAGE_URL=https://gitlab.com/cip-project/cip-kernel/kernel-cve-triage.git
ARG KERNEL_CVE_TRIAGE_COMMIT=3aa04484d7b0e58331d3da4b2aef78376f23de55
ARG KMAX_VERSION=4.10

# Kernel Kbuild + Kmax system dependencies aligned with upstream kernel-cve-triage/Dockerfile.
# Includes cross-compilers and LLVM/lld so x86_64 and arm64 .configs build on either host arch.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    build-essential \
    git \
    clang \
    lld \
    llvm \
    libclang-dev \
    clang-tools \
    gcc-x86-64-linux-gnu \
    gcc-aarch64-linux-gnu \
    flex \
    bison \
    bc \
    libssl-dev \
    libelf-dev \
    python3 \
    python3-dev \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Isolated virtualenv with pinned setuptools<82 build constraint for kmax & cve-triage
RUN python3 -m venv "${VENV_DIR}" \
    && "${VENV_DIR}/bin/pip" install --no-cache-dir -U "pip>=25.1" "setuptools<82" wheel

ENV PATH="${VENV_DIR}/bin:${PATH}"

RUN printf 'setuptools<82\n' > /tmp/build-constraints.txt \
    && pip install --no-cache-dir --build-constraint /tmp/build-constraints.txt \
        "kmax==${KMAX_VERSION}" \
        "git+${KERNEL_CVE_TRIAGE_URL}@${KERNEL_CVE_TRIAGE_COMMIT}" \
    && rm -f /tmp/build-constraints.txt

COPY pyproject.toml LICENSE PINS.lock README.md /tmp/kernelvex/
COPY schemas /tmp/kernelvex/schemas
COPY src /tmp/kernelvex/src

RUN pip install --no-cache-dir /tmp/kernelvex \
    && rm -rf /tmp/kernelvex

# Non-root execution user, persistent /cache mount, and container-safe git configuration.
# Marking all paths safe allows non-root UID 10001 to read host-owned CI bind mounts (/sources:ro).
RUN groupadd --gid 10001 kernelvex \
    && useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash kernelvex \
    && mkdir -p /cache /work \
    && chown -R 10001:10001 /cache /work \
    && git config --system --add safe.directory '*'

VOLUME ["/cache"]
WORKDIR /work
USER 10001:10001

ENTRYPOINT ["kernelvex"]
CMD ["--help"]
