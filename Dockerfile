# syntax=docker/dockerfile:1
# (BuildKit required: the runtime stage installs from a bind-mounted wheel dir.)
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

# Wheels for the package and its runtime deps; the final stage installs from
# here so no raw `src/` ever reaches the runtime image.
RUN pip wheel --no-cache-dir --wheel-dir /wheels .


FROM python:3.12-slim AS base

# Non-root runtime user.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin gateway

WORKDIR /app

RUN --mount=type=bind,from=builder,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index --find-links /wheels ha-rbac-gateway \
    && python -c "import ha_rbac_gateway; print('installed', ha_rbac_gateway.__version__)"

# Runtime dirs (mounted over in production, but exist for a bare run).
RUN mkdir -p /config/policies /data && chown -R gateway:gateway /config /data
USER gateway

EXPOSE 8124
# The listener binds LISTEN_HOST:LISTEN_PORT from the environment (see .env.example).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
url='http://127.0.0.1:%s/healthz'%os.environ.get('LISTEN_PORT','8124'); \
sys.exit(0 if urllib.request.urlopen(url,timeout=3).status==200 else 1)"

CMD ["ha-rbac-gateway"]
