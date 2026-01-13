# syntax=docker/dockerfile:1.4

# Sentinel WebSocket Inspector Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-ws-agent /sentinel-ws-agent

LABEL org.opencontainers.image.title="Sentinel WebSocket Inspector Agent" \
      org.opencontainers.image.description="Sentinel WebSocket Inspector Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-websocket-inspector"

ENV RUST_LOG=info,sentinel_ws_agent=debug \
    SOCKET_PATH=/var/run/sentinel/websocket-inspector.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-ws-agent"]
