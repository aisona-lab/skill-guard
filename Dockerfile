# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md LICENSE CHANGELOG.md LIMITATIONS.md ./
COPY src ./src

RUN pip install --no-cache-dir .


FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="skill-guard" \
      org.opencontainers.image.description="Audit Agent Skills and packages before they touch your machine. Deterministic checks. Exit codes." \
      org.opencontainers.image.version="0.2.3" \
      org.opencontainers.image.source="https://github.com/aisona-lab/skill-guard" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN groupadd --gid 10001 skillguard \
    && useradd --uid 10001 --gid skillguard --shell /usr/sbin/nologin --create-home skillguard \
    && mkdir -p /scan \
    && chown skillguard:skillguard /scan

COPY --from=builder /opt/venv /opt/venv

WORKDIR /scan
USER skillguard

ENTRYPOINT ["skill-guard"]
CMD ["--help"]
