# AEGIS-AC reproduction environment (IMPLEMENTATION.md Section 8 T1.3 / Section 6.5's
# artifact-evaluation requirement).
#
# HONESTY NOTE: this Dockerfile is written against exactly the dependency set verified to work in
# this build's own sandbox (same apt packages, same pip packages, same versions) -- but the
# `docker` CLI itself is not available inside that sandbox, so `docker build` has NOT been run
# against this file. Every individual step (the apt install, the pip installs, the pytest run)
# WAS run for real, just not through Docker's layered build process. Build and report back if
# something doesn't come through cleanly -- most likely candidates for a first-build hiccup are
# apt mirror selection and Python base-image version drift, not anything algorithmic.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# libhyperscan-dev/libhyperscan5 verified installable from Ubuntu 24.04 (noble)'s own repos in
# this build -- no external PPA needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    libhyperscan-dev libhyperscan5 pkg-config build-essential \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /aegis-ac
COPY requirements.txt .
# --break-system-packages matches this build's own pip invocations (Ubuntu 24.04's Python is
# PEP-668 externally-managed by default).
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt \
    && pip3 install --break-system-packages --no-cache-dir hyperscan==0.8.2

COPY . .

RUN chmod +x run_benchmarks.sh

CMD ["./run_benchmarks.sh"]
