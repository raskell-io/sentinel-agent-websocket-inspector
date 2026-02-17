# syntax=docker/dockerfile:1.4

# Zentinel WebSocket Inspector Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-ws-agent /zentinel-ws-agent

LABEL org.opencontainers.image.title="Zentinel WebSocket Inspector Agent" \
      org.opencontainers.image.description="Zentinel WebSocket Inspector Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-websocket-inspector"

ENV RUST_LOG=info,zentinel_ws_agent=debug \
    SOCKET_PATH=/var/run/zentinel/websocket-inspector.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-ws-agent"]
