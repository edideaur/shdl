# site-dl

A standalone Linux/NAS CLI for `https://91.202.233.104/`. Retrieves the complete
catalog, follows the site's proof-of-work and download queue, and downloads each
ready link with **aria2**, preserving subdirectories. Use only for your own data
or files you are authorized to retrieve.

## Install on the NAS

Requires **Python 3.10+**, **aria2c**, and a destination filesystem supporting
Linux advisory file locks. Tested with Python 3.14, websockets 16.0, and aria2 1.37.
Install Python and aria2 using your NAS's package manager, then copy this folder
onto the NAS and run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: -r requirements.txt
```

## Run

Inspect the catalog without starting a transfer:

```sh
.venv/bin/python site_dl.py --list --insecure
```

Download **all files** into the current working directory (`./`), preserving
subdirectories:

```sh
.venv/bin/python site_dl.py --insecure
```

Optionally choose another destination:

```sh
.venv/bin/python site_dl.py --output /volume1/downloads/site --insecure
```

The server currently uses a self-signed certificate. `--insecure` deliberately
disables server identity verification for the API, WebSocket, and aria2; an
attacker could substitute data. If you have an independently verified PEM
certificate/CA bundle, replace `--insecure` with `--ca-certificate /path/to/ca.pem`.
Downloading a certificate from the unverified connection does not establish trust.

## Resume and behavior

- Rerun from the same working directory (or use the same `--output`) after an
  interruption. aria2 resumes partial files; the client skips recorded completions
  with matching metadata and size. Keep `.aria2` control files and `.site-dl-state.json`.
- Uses one transfer and one connection at a time, respecting the site's queue.
  It obtains links just before download rather than saving expiring URLs.
- Retries expired turns, transient queue responses, and failed transfers up to
  three times. Does not blindly replay an API POST after a transport failure.
- Ctrl+C gracefully stops aria2 and attempts to cancel the queue turn. Exit
  codes: `0` success, `1` error/incomplete collection, `130` interrupted.
- Never resumes or overwrites untracked existing files, follows output symlinks,
  or deletes old downloads. A changed catalog entry or unsafe path stops the run;
  use a fresh destination rather than discarding existing data.
- A per-directory lock prevents two clients writing the same collection. Don't
  run a separate aria2 instance against the same destination files.
- Tokens remain in memory; download URLs go to aria2 over stdin, not process
  arguments or saved manifests. aria2 output is suppressed to avoid leaking
  URLs; queue/progress/completion information is displayed by the client.
- Completion checks metadata, size, and aria2's exit status. The API provides no
  checksums, so this isn't cryptographic content verification. The catalog is a
  startup snapshot, not continuous synchronization.
