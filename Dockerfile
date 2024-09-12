FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/onestay/cf-dyndns"
LABEL org.opencontainers.image.description="Dynamically update Cloudflare DNS records."
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev

ADD . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT [ "dnsupdate" ]
CMD [ "-c", "/config.toml", "-n" ]