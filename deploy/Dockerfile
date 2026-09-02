# Minimal image for running Baseline Guard against bind-mounted paths.
#
# A container has no visibility into the host's real filesystem tree,
# process table, or listening sockets unless you explicitly grant it
# (bind mounts, --pid=host, --net=host) -- see docs/INSTALL.md for the
# tradeoffs before using any of those in production.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
COPY baselineguard ./baselineguard
RUN pip install --no-cache-dir .

RUN useradd --system --create-home --home-dir /var/lib/baseline-guard baseline-guard
USER baseline-guard

ENTRYPOINT ["baseline-guard"]
CMD ["--help"]
