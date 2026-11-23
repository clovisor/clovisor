# The integration tests' client image: the tools agent harnesses use.
# Clovisor's own binaries are mounted in, not built here.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git openssh-client python3 python3-requests \
 && rm -rf /var/lib/apt/lists/*
