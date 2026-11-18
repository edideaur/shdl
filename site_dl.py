#!/usr/bin/env python3
"""Download the complete site catalog through its normal queue, using aria2."""

import argparse
from collections import deque
from contextlib import contextmanager
from copy import copy
import fcntl
import hashlib
from http.cookiejar import MozillaCookieJar
import json
import os
from pathlib import Path
import re
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, Request, build_opener

try:
    from websockets.exceptions import ConnectionClosed, InvalidHandshake
    from websockets.sync.client import connect
except ImportError:
    raise SystemExit("Missing websockets: install dependencies with pip install -r requirements.txt")


BASE_URL = "https://91.202.233.104"
STATE_NAME = ".site-dl-state.json"
LOCK_NAME = ".site-dl.lock"
ATTEMPTS = 3
MAX_RESPONSE = 16 * 1024 * 1024


class Error(Exception):
    """An error safe to display without exposing response bodies or tokens."""


class Retryable(Error):
    pass


class APIError(Error):
    def __init__(self, status, data):
        self.status = status
        reason = data.get("reason") or data.get("error") or "request_failed"
        self.reason = reason if isinstance(reason, str) and re.fullmatch(r"[a-z_]{1,64}", reason) else "request_failed"
        super().__init__(f"API request failed: HTTP {status}, {self.reason}")


def opaque(value, label):
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Error(f"Invalid {label} in server response")
    return value


def path_parts(name):
    if not isinstance(name, str) or not name or "\\" in name or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in name):
        raise Error("Unsafe filename in catalog")
    parts = name.split("/")
    if len(name.encode("utf-8")) > 4096 or len(parts) > 128 or any(p in ("", ".", "..") or p.strip() != p for p in parts):
        raise Error("Unsafe filename in catalog")
    return parts


def safe_path(root, name):
    path = root
    for part in path_parts(name):
        path = path / part
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise Error("Refusing a symlink or a path outside the output directory")
    return path


class SameOriginRedirect(HTTPRedirectHandler):
    def __init__(self, origin):
        self.origin = urlsplit(origin)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if (target.scheme, target.netloc) != (self.origin.scheme, self.origin.netloc):
            raise Error("Refusing an off-site API redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def solve_pow(sig, bits, timeout=30):
    opaque(sig, "proof-of-work signature")
    if type(bits) is not int or not 0 <= bits <= 256:
        raise Error("Invalid proof-of-work difficulty")
    prefix = (sig + ":").encode("utf-8")
    deadline = time.monotonic() + timeout
    nonce = 0
    while True:
        if nonce % 1024 == 0 and time.monotonic() >= deadline:
            raise Error("Proof-of-work time limit exceeded")
        digest = hashlib.sha256(prefix + str(nonce).encode("ascii")).digest()
        if int.from_bytes(digest, "big") >> (256 - bits) == 0:
            return str(nonce)
        nonce += 1


class Client:
    def __init__(self, context, base_url=BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.context = context
        self.session = ""
        self.pow_token = ""
        self.pow_expiry = 0
        # Preserve the server's bucket cookie across separate connections.
        self.cookies = MozillaCookieJar()
        self.opener = build_opener(HTTPSHandler(context=context), HTTPCookieProcessor(self.cookies),
                                   SameOriginRedirect(self.base_url))

    def request(self, path, payload=None, protected=False, method=None):
        method = method or ("POST" if payload is not None else "GET")
        for attempt in range(2):
            headers = {"Accept": "application/json", "User-Agent": "site-dl/1.0"}
            if self.session:
                headers["X-Session-ID"] = self.session
            if protected and self.pow_token:
                headers["X-PoW-Token"] = self.pow_token
            body = None
            if payload is not None:
                headers["Content-Type"] = "application/json"
                body = json.dumps(payload).encode("utf-8")
            req = Request(self.base_url + path, data=body, headers=headers, method=method)
            try:
                response = self.opener.open(req, timeout=30)
            except HTTPError as exc:
                response = exc
            except (URLError, OSError) as exc:
                reason = exc.reason if isinstance(exc, URLError) else exc
                if isinstance(reason, ssl.SSLCertVerificationError):
                    raise Error("TLS certificate verification failed; use a trusted --ca-certificate or explicitly use --insecure") from exc
                # A timed-out POST may already have created a queue entry. Don't replay it blindly.
                raise Error(f"{method} API request failed; no automatic replay") from exc
            try:
                with response:
                    status = response.status
                    raw = response.read(MAX_RESPONSE + 1)
            except OSError as exc:
                raise Error(f"{method} API response interrupted; no automatic replay") from exc
            if len(raw) > MAX_RESPONSE:
                raise Error("API response exceeds the size limit")
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeError) as exc:
                raise Error(f"API returned invalid JSON (HTTP {status})") from exc
            if not isinstance(data, dict):
                raise Error("API returned an unexpected response shape")
            pow_required = data.get("error") == "pow_required" or data.get("reason") == "pow_required"
            challenge = "challenge" in data and "sig" in data
            if protected and attempt == 0 and (pow_required or (status == 401 and challenge)):
                self.refresh_pow(data if challenge else None, force=True)
                continue
            if not 200 <= status < 300 or data.get("error"):
                raise APIError(status, data)
            return data
        raise Error("Proof-of-work authorization failed")

    def refresh_pow(self, challenge=None, force=False):
        if not force and time.monotonic() + 5 < self.pow_expiry:
            return
        data = challenge if challenge is not None else self.request("/pow/challenge")
        if data.get("enabled") is False:
            self.pow_token = ""
            self.pow_expiry = time.monotonic() + 300
            return
        ch = data.get("challenge")
        if not isinstance(ch, dict):
            raise Error("Invalid proof-of-work challenge")
        sig = opaque(data.get("sig"), "proof-of-work signature")
        ttl = data.get("ttl_ms", 30000)
        if type(ttl) is not int or ttl <= 0:
            raise Error("Invalid proof-of-work lifetime")
        nonce = solve_pow(sig, ch.get("bits"), min(30, ttl / 1000))
        result = self.request("/pow/verify", {"challenge": ch, "sig": sig, "nonce": nonce})
        self.pow_token = opaque(result.get("token"), "proof-of-work token")
        ttl = result.get("token_ttl_ms")
        if type(ttl) is not int or ttl <= 0:
            raise Error("Invalid proof-of-work token lifetime")
        self.pow_expiry = time.monotonic() + ttl / 1000

    def enqueue(self, file):
        self.refresh_pow()
        data = self.request("/queue", {"file_id": file["id"]}, protected=True)
        self.session = opaque(data.get("session_id"), "session ID")
        return opaque(data.get("queue_id"), "queue ID")

    def socket(self, qid):
        scheme = "wss" if self.base_url.startswith("https://") else "ws"
        url = f"{scheme}://{urlsplit(self.base_url).netloc}/ws?" + urlencode({"queue_id": qid, "session": self.session})
        request = Request(self.base_url + "/ws")
        self.cookies.add_cookie_header(request)
        cookie = request.get_header("Cookie")
        return connect(url, ssl=self.context if scheme == "wss" else None,
                       origin=self.base_url, additional_headers={"Cookie": opaque(cookie, "cookie header")} if cookie else None,
                       compression=None, open_timeout=20,
                       close_timeout=5, max_size=65536)

    def cancel(self, qid):
        try:
            self.request("/cancel/" + quote(qid, safe=""), method="POST")
        except (Error, OSError):
            pass


def load_catalog(client):
    summary = client.request("/files/summary")
    if type(summary.get("files")) is not int or summary["files"] < 0 or type(summary.get("total_bytes")) is not int or summary["total_bytes"] < 0:
        raise Error("Invalid catalog summary")
    if summary.get("huge") or summary["files"] >= 5000:
        pending, visited, files = deque([""]), set(), []
        while pending:
            directory = pending.popleft()
            if directory in visited:
                raise Error("Duplicate directory in catalog")
            visited.add(directory)
            data = client.request("/files/browse?" + urlencode({"path": directory}), protected=True)
            children, entries = data.get("dirs"), data.get("files")
            if not isinstance(children, list) or not isinstance(entries, list):
                raise Error("Invalid directory listing")
            files.extend(entries)
            for child in children:
                if len(path_parts(child)) != 1:
                    raise Error("Invalid directory name")
                child_path = f"{directory}/{child}" if directory else child
                path_parts(child_path)
                pending.append(child_path)
    else:
        files = client.request("/files", protected=True).get("files")
    if not isinstance(files, list):
        raise Error("Invalid file catalog")
    ids, names = set(), set()
    for file in files:
        if not isinstance(file, dict):
            raise Error("Invalid file record")
        fid = opaque(file.get("id"), "file ID")
        name = file.get("name")
        path_parts(name)
        if type(file.get("size")) is not int or file["size"] < 0 or not isinstance(file.get("mod_time"), str):
            raise Error("Invalid file metadata")
        if name in (STATE_NAME, LOCK_NAME) or name.startswith(".site-dl-state."):
            raise Error("Catalog filename conflicts with client metadata")
        if fid in ids or name in names:
            raise Error("Duplicate file ID or filename in catalog")
        ids.add(fid)
        names.add(name)
    if any(name + ".aria2" in names for name in names):
        raise Error("Catalog filenames conflict with aria2 control files")
    output_files = names | {name + ".aria2" for name in names} | {STATE_NAME, LOCK_NAME}
    for name in output_files:
        parts = name.split("/")
        if any("/".join(parts[:i]) in output_files for i in range(1, len(parts))):
            raise Error("Catalog contains a file/directory path conflict")
    if len(files) != summary["files"] or sum(f["size"] for f in files) != summary["total_bytes"]:
        raise Error("Catalog changed or was truncated; rerun to obtain a consistent listing")
    return sorted(files, key=lambda f: f["name"])


@contextmanager
def output_lock(root):
    path = safe_path(root, LOCK_NAME)
    if path.exists() and not path.is_file():
        raise Error("Lock path is not a regular file")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Error("Another client is already using this output directory") from exc
        yield


def load_state(root, source):
    path = safe_path(root, STATE_NAME)
    if not path.exists():
        return {"version": 1, "source": source, "files": {}}
    if not path.is_file() or path.stat().st_size > MAX_RESPONSE:
        raise Error("State file is not regular or exceeds the size limit")
    try:
        with path.open("rb") as file:
            raw = file.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise Error("State file exceeds the size limit")
        state = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise Error("Invalid state file; refusing to overwrite it") from exc
    if not isinstance(state, dict) or state.get("version") != 1 or state.get("source") != source or not isinstance(state.get("files"), dict):
        raise Error("Output directory belongs to a different client/source or has invalid state")
    return state


def save_state(root, state):
    destination = safe_path(root, STATE_NAME)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root,
                                         prefix=".site-dl-state.", suffix=".tmp", delete=False) as file:
            tmp = Path(file.name)
            json.dump(state, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, destination)
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink()


def snapshot(file):
    return {key: file[key] for key in ("name", "size", "mod_time")}


def prepare_file(root, state, file):
    path = safe_path(root, file["name"])
    control = safe_path(root, file["name"] + ".aria2")
    entry = state["files"].get(file["id"])
    if entry is not None and (not isinstance(entry, dict) or any(entry.get(k) != v for k, v in snapshot(file).items()) or entry.get("status") not in ("partial", "complete")):
        raise Error("Tracked file metadata changed; use a fresh output directory")
    if (path.exists() or control.exists()) and entry is None:
        raise Error("Refusing to overwrite or resume an untracked existing file")
    if path.exists() and not path.is_file() or control.exists() and not control.is_file():
        raise Error("Output file/control path is not a regular file")
    if path.exists() and path.stat().st_size > file["size"]:
        raise Error("Local file is larger than the catalog entry; refusing to truncate it")
    if entry and entry["status"] == "complete" and path.exists():
        if path.stat().st_size != file["size"] or control.exists():
            raise Error("A completed file was modified or has an unexpected control file")
        return path, True
    if any(p.exists() and p.stat().st_nlink > 1 for p in (path, control)):
        raise Error("Refusing to modify a hard-linked partial/control file")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    state["files"][file["id"]] = {**snapshot(file), "status": "partial"}
    save_state(root, state)
    return path, False


def read_message(ws, timeout=1):
    try:
        raw = ws.recv(timeout=timeout)
    except TimeoutError:
        return None
    except (ConnectionClosed, OSError) as exc:
        raise Retryable("Queue connection lost") from exc
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise Error("Invalid queue message") from exc
    if not isinstance(data, dict):
        raise Error("Invalid queue message")
    return data


def wait_ready(client, ws, qid, file):
    last_position = None
    while True:
        msg = read_message(ws, timeout=30)
        if msg is None:
            continue
        kind = msg.get("type")
        if kind == "ready":
            expiry = msg.get("token_exp_ms")
            if expiry is not None and (type(expiry) is not int or expiry <= time.time() * 1000):
                raise Retryable("Download link expired before it could start")
            if msg.get("token"):
                return client.base_url + "/dl/" + quote(opaque(msg["token"], "download token"), safe="")
            return client.base_url + "/download/" + quote(file["id"], safe="") + "?" + urlencode({"queue_id": qid, "session": client.session})
        if kind in ("expired", "cancelled", "gone") or kind == "status" and msg.get("state") in ("expired", "cancelled", "gone"):
            raise Retryable("Queue turn ended before download")
        if kind == "status" and msg.get("state") == "waiting":
            position = msg.get("position")
            if type(position) is int and position > 0 and position != last_position:
                print(f"  Queue position: {position}", flush=True)
                last_position = position


def aria2_download(client, ws, url, path, size, insecure=False, ca_certificate=None):
    args = ["aria2c", "--no-conf=true", "--input-file=-", "--continue=true",
            "--always-resume=true", "--allow-overwrite=false", "--auto-file-renaming=false",
            "--split=1", "--max-connection-per-server=1", "--max-concurrent-downloads=1",
            "--file-allocation=none", "--auto-save-interval=10", "--max-tries=2",
            "--retry-wait=5", "--connect-timeout=20", "--timeout=60", "--quiet=true",
            "--follow-torrent=false", "--follow-metalink=false",
            "--check-certificate=" + ("false" if insecure else "true")]
    if ca_certificate is not None:
        args.append("--ca-certificate=" + str(ca_certificate))
    # Use stdin, not argv or a saved manifest, so bearer URLs don't appear in ps or files.
    manifest = f"{url}\n  dir={path.parent}\n  out={path.name}\n"
    try:
        export_cookies = MozillaCookieJar()
        for cookie in client.cookies:
            if cookie.is_expired():
                continue
            for value in (cookie.domain, cookie.path, cookie.name, cookie.value):
                if value:
                    opaque(value, "cookie field")
            cookie = copy(cookie)
            # aria2 requires expiry 0 for session cookies, not Python's empty field.
            if cookie.expires is None:
                cookie.expires = 0
            export_cookies.set_cookie(cookie)
        # Inherit an anonymous cookie file; aria2 applies domain/path rules, including on redirects.
        with tempfile.TemporaryFile(dir=path.parent) as cookie_file:
            cookie_path = f"/proc/self/fd/{cookie_file.fileno()}"
            export_cookies.save(cookie_path, ignore_discard=True, ignore_expires=True)
            args.append("--load-cookies=" + cookie_path)
            process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                                       pass_fds=(cookie_file.fileno(),))
    except OSError as exc:
        raise Error("Could not prepare aria2 cookies or start aria2c (requires Linux /proc/self/fd)") from exc
    monitor, last_progress = True, 0
    try:
        process.stdin.write(manifest)
        process.stdin.close()
        while process.poll() is None:
            if not monitor:
                process.wait()
                break
            try:
                msg = read_message(ws)
            except Error:
                print("  Queue monitoring disconnected; aria2 continues.", flush=True)
                monitor = False
                continue
            if msg and msg.get("type") == "progress" and sys.stdout.isatty() and time.monotonic() - last_progress >= 1:
                served = msg.get("served")
                if type(served) is int and 0 <= served <= size:
                    print(f"  {served * 100 / size if size else 100:5.1f}% ({human_size(served)} / {human_size(size)})", end="\r", flush=True)
                    last_progress = time.monotonic()
    finally:
        if process.poll() is None:
            # SIGINT lets aria2 persist its control file for the next invocation.
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=30)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                process.kill()
                process.wait()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        if last_progress:
            print()
    code = process.returncode
    if code:
        if code in (8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 28, 32):
            raise Error(f"aria2 exited with code {code} (resume/storage/configuration error); partial data kept")
        raise Retryable(f"aria2 exited with code {code}; partial data kept")
    if not path.is_file() or path.stat().st_size != size or Path(str(path) + ".aria2").exists():
        raise Retryable("Downloaded size/control state does not match the catalog; partial data kept")


def download_file(client, file, path, insecure=False, ca_certificate=None):
    for attempt in range(ATTEMPTS):
        qid, done = None, False
        try:
            qid = client.enqueue(file)
            try:
                with client.socket(qid) as ws:
                    url = wait_ready(client, ws, qid, file)
                    aria2_download(client, ws, url, path, file["size"], insecure, ca_certificate)
            except InvalidHandshake as exc:
                raise Error("Queue WebSocket handshake failed") from exc
            except (ConnectionClosed, OSError, TimeoutError) as exc:
                raise Retryable("Queue connection failed") from exc
            done = True
            return
        except APIError as exc:
            if exc.status != 429 and exc.reason not in ("rate_limited", "queue_full"):
                raise
            failure = Retryable(str(exc))
        except Retryable as exc:
            failure = exc
        finally:
            if qid is not None and not done:
                client.cancel(qid)
        if attempt + 1 == ATTEMPTS:
            raise failure
        delay = 5 * 2 ** attempt
        print(f"  {failure}; retrying with a fresh queue turn in {delay}s", flush=True)
        time.sleep(delay)


def human_size(value):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or unit == "PiB":
            return f"{value:.1f} {unit}"
        value /= 1024


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("."), help="Destination directory (default: ./)")
    parser.add_argument("--list", action="store_true", help="List the catalog without joining queues or downloading")
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--insecure", action="store_true", help="Explicitly skip HTTPS/WSS certificate verification")
    tls.add_argument("--ca-certificate", type=Path, help="Trusted PEM certificate/CA bundle (also passed to aria2)")
    args = parser.parse_args(argv)
    try:
        if not args.list and shutil.which("aria2c") is None:
            raise Error("aria2c is not installed or is not in PATH")
        context = ssl.create_default_context(cafile=args.ca_certificate)
        if args.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            print("Warning: HTTPS/WSS server identity verification is disabled.", file=sys.stderr)
        client = Client(context)
        files = load_catalog(client)
        print(f"{len(files)} files, {human_size(sum(f['size'] for f in files))}", flush=True)
        if args.list:
            for file in files:
                print(f"{human_size(file['size']):>12}  {file['name']}")
            return 0
        root = args.output.expanduser().resolve()
        if any(ord(c) < 32 or ord(c) == 127 for c in str(root)) or str(root).strip() != str(root):
            raise Error("Output path contains unsafe whitespace/control characters")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        completed, skipped, failed = 0, 0, 0
        with output_lock(root):
            state = load_state(root, client.base_url)
            for i, file in enumerate(files, 1):
                path, skip = prepare_file(root, state, file)
                print(f"[{i}/{len(files)}] {file['name']} ({human_size(file['size'])})", flush=True)
                if skip:
                    print("  Already complete; skipped.", flush=True)
                    skipped += 1
                    continue
                try:
                    download_file(client, file, path, args.insecure, args.ca_certificate)
                except Retryable as exc:
                    print(f"  Failed: {exc}", file=sys.stderr)
                    failed += 1
                    continue
                safe_path(root, file["name"])
                safe_path(root, file["name"] + ".aria2")
                state["files"][file["id"]]["status"] = "complete"
                save_state(root, state)
                print("  Complete.", flush=True)
                completed += 1
        print(f"Done: {completed} downloaded, {skipped} skipped, {failed} failed.")
        return 1 if failed else 0
    except KeyboardInterrupt:
        print("\nInterrupted; partial downloads kept. Rerun the same command to resume.", file=sys.stderr)
        return 130
    except (Error, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
