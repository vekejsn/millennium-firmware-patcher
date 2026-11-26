FROM golang:1.26-bookworm AS emulator-build
ARG EMULATOR_REF=main
WORKDIR /src
ADD https://github.com/vekejsn/millennium-emulator.git#${EMULATOR_REF} /src/
RUN CGO_ENABLED=0 go build -trimpath -o /millennium .

FROM debian:bookworm-slim AS emulator
RUN mkdir /verify && chown 10001:10001 /verify
COPY --from=emulator-build /millennium /usr/local/bin/millennium
COPY --from=emulator-build /src/LICENSE /usr/share/doc/millennium/LICENSE
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/millennium"]

FROM python:3.12-slim AS patcher
LABEL org.opencontainers.image.licenses="GPL-3.0-only"
WORKDIR /app
COPY LICENSE /usr/share/doc/millennium-patcher/LICENSE
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && mkdir /data /verify && chown 10001:10001 /data /verify
COPY *.py /app/firmware_patcher/
ENV FIRMWARE_PATCHER_DB=/data/firmware.sqlite3 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
CMD ["python", "-m", "uvicorn", "firmware_patcher.api:app", "--host", "0.0.0.0", "--port", "8001"]
