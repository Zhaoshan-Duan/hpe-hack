# Local build / grade-parity image for the HPE Build-It "stor" entry.
# Target toolchain: Ubuntu 18.04, 32-bit gcc, executable-stack marking.
# The grader uses its own image; this exists so `cd build && make` can be
# reproduced locally on a matching toolchain.
FROM ubuntu:18.04

# Ubuntu 18.04 is EOL. Mirror availability shifts over time: archive.ubuntu.com
# still served bionic as of this build, so we use it as-is. If `apt-get update`
# starts 404ing, repoint apt at old-releases by uncommenting:
#   RUN sed -i \
#         -e 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' \
#         -e 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' \
#         /etc/apt/sources.list

# i386 arch is needed for the 32-bit libsodium/libssl staged for the crypto pass.
RUN dpkg --add-architecture i386 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      gcc-multilib \
      make \
      execstack \
      libsodium-dev \
      libsodium-dev:i386 \
      libssl-dev:i386 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# COPY is convenient for a one-shot `docker run`; for iterative dev prefer a
# bind mount instead:  docker run --rm -v "$PWD":/src bibifi bash -c 'cd build && make'
COPY . /src

CMD ["bash"]
