# Millennium Firmware Patcher

Upload a Millennium MTR1 or MTR2 control ROM to archive it and build a copy with inbound modem call-in. The service keeps your upload intact. With Docker, a worker can also test the patched ROM against the Go emulator.

## Run it on Linux

From the checkout, with Docker Engine and the Compose plugin installed:

```sh
docker compose up --build -d --wait
```

Open [the API docs](http://127.0.0.1:8001/docs) to upload a ROM and submit a job. The API listens on localhost; the emulator debugger has no published port. If you're running it on a server, use an SSH tunnel or put an authenticated proxy in front of it. The API itself has no user accounts or storage quotas.

Compose builds the upstream emulator from `main` by default. Set `EMULATOR_REF` to a tag or commit to pin it. Run the same Compose command again to rebuild; restarting the containers alone won't fetch newer code.

For uploads and unverified builds without Docker, clone the repository into a directory named `firmware_patcher`, then run these commands from its parent directory with Python 3.11 or newer:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r firmware_patcher/requirements.txt
python -m uvicorn firmware_patcher.api:app --host 127.0.0.1 --port 8001
```

## Upload and patch a ROM

Send a 256 KiB MTR1 control ROM or a merged 1 MiB MTR2 image as `files`. For split MTR2 dumps, repeat the field with flash0/U2 first and flash1/X1 second. Leave out separate voice ROMs. Give Intel HEX files a `.hex` extension.

Using `curl` and `jq`:

```sh
api=http://127.0.0.1:8001
session=$(curl -fsS -F 'files=@/path/to/control-rom.bin' "$api/sessions")
printf '%s\n' "$session" | jq '{firmware, applicable_patches}'
session_id=$(printf '%s\n' "$session" | jq -er '.session_id')

job=$(curl -fsS -H 'Content-Type: application/json' \
  -d '{"patches":["call_in"],"rings":3}' "$api/sessions/$session_id/jobs")
status_url=$(printf '%s\n' "$job" | jq -er '.status_url')
curl -fsS "$api$status_url" | jq .
```

Use `applicable_patches` to populate the patch picker as soon as the upload returns. The API checks the detected board and the ROM's patch signatures before adding a patch to that list. Each entry provides an `id`, `label`, and `platforms` (`mtr1`, `mtr2`, or both). Use the `id` when submitting a build or job.

To refresh the list later, call `GET /sessions/{session_id}/patches`. If it's empty, the `patches` field on the session explains why each patch is unavailable. `GET /patches` lists every registered patch, irrespective of the uploaded ROM.

Poll `status_url` until the job reaches `succeeded` or `failed`. On success, use `build.download_url` to fetch the ROM and `build.manifest.verification` to read the test results. A failed job returns an error and leaves the original in the archive. An interrupted job goes back into the queue when the worker restarts.

The emulator boots the patched ROM, sets up provisioning in RAM, and checks immediate and delayed answer, carrier, and no pickup in modes 0 and 1. It doesn't test physical hardware or perform a full NCC exchange. If you only want to build a patched ROM, post `{"patches":["call_in"]}` to `/sessions/{session_id}/builds` instead.

## Browse the archive

`GET /firmwares` groups saved files by the version and revision in the ROM header. Each group lists a hash once, with a `provenance` value that tells you how the archive got those bytes:

| `provenance` | Meaning |
| --- | --- |
| `source` | Someone uploaded these bytes. They may already contain patches made elsewhere. |
| `patched` | The service produced these bytes as a patch output. |
| `source_and_patched` | The same bytes came from both an upload and a build in this group. |

Provenance doesn't tell you whether a build passed emulator checks; check its verification report for that. Split uploads list the chip files separately. `updated_at` is when the service last saved those bytes, in UTC. Older entries may have no recorded time (`null`), and unidentified uploads have `null` for the version and revision.

```sh
curl -fsS "$api/firmwares" | jq .
sha256=YOUR_CATALOG_HASH
curl -fsS "$api/firmwares/$sha256" -o downloaded-rom
```

Set `sha256` to a `hash` from the catalog. The download contains the exact archived bytes, including the original text for Intel HEX uploads. For a split dump, use the session's `sources` array or its `/originals/0` and `/originals/1` routes to recover the upload order. A merged upload and its split pair have separate session IDs but the same decoded image hash.

## Storage, logs, and email

Compose keeps SQLite in the `archive` named volume. To use a host directory instead, mount the directory, not the database file; SQLite and the worker need space for locks and sidecar files.

```sh
export FIRMWARE_DATA_DIR=/var/lib/millennium-patcher
sudo install -d -m 0750 -o 10001 -g 10001 "$FIRMWARE_DATA_DIR"
docker compose -f compose.yaml -f compose.host.yaml up --build -d --wait
```

Both services use `firmware.sqlite3` in that directory. If you're moving an existing archive, stop the old stack and copy the database into the new directory before starting it. UID/GID `10001` must be able to write to the database and its directory. Without Docker, the default is `data/firmware.sqlite3` inside the checkout; `FIRMWARE_PATCHER_DB` overrides it.

Check service output with `docker compose logs api worker`, using the same Compose files you started with. The `error_log` table keeps patch, verification, mail, and unexpected API failures after a restart. With a host mount, you can read it directly:

```sh
sudo sqlite3 "$FIRMWARE_DATA_DIR/firmware.sqlite3" \
  'SELECT created_at, stage, job_id, message FROM error_log ORDER BY id DESC LIMIT 30;'
```

For email, set `FIRMWARE_EMAIL_ENABLED=1`, `SMTP_HOST`, `SMTP_FROM`, and `SMTP_TO` in the Compose environment, then send `"notify":true` with the job. Set `PUBLIC_API_URL` to the address recipients use to reach the API. The worker uses STARTTLS on port 587 by default; set `SMTP_PORT`, `SMTP_USER`, and `SMTP_PASSWORD` if needed. The recipient comes from server configuration. Delivery appears under `notification` and doesn't change the build result.

## Tests and license

From the parent of a `firmware_patcher` checkout, install `httpx` in the same environment and run `python -m unittest -v firmware_patcher.test_api`. Tests that need local ROM dumps skip if the files aren't available. To try the Docker stack with your own image, run `python firmware_patcher/smoke_jobs.py /path/to/control-rom.bin` from that parent directory.

The patcher and API are [GPL-3.0-only](LICENSE). Firmware dumps and the upstream emulator keep their own terms.
