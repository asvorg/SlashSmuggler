#!/usr/bin/env python3
"""
General-purpose raw HTTP/HTTPS path-fuzzing tool for testing encoded slash/path normalization.

Examples:
  python3 double_encode_bruteforce.py --host 127.0.0.1 --port 3000 --path /private/canary.txt
  python3 double_encode_bruteforce.py --host example.com --port 443 --path /private/canary.txt --https
  python3 double_encode_bruteforce.py --host example.com --port 443 --path /private/canary.txt --https --marker "SUPER_SECRET_TOKEN"

This sends raw request lines to avoid client-side path normalization as much as possible.
"""

import argparse
import socket
import ssl
import sys
import time

DEFAULT_TIMEOUT = 5.0
DEFAULT_DELAY = 0.25
MAX_BODY_PREVIEW = 2000

# Common slash- and path-encoding variants to test
ENCODINGS = [
    "/",
    "%2F",
    "%2f",
    "%252F",
    "%252f",
    "%25252F",
    "%25252f",
    "%5C",
    "%5c",
    "%255C",
    "%255c",
    "%2E%2E%2F",
    "%2e%2e%2f",
    "%2E%2E%5C",
    "%2e%2e%5c",
    "%2f%2e%2e%2f",
    "%2F.",
    "%2f.",
    "%2f%2e%2e",
    "%252e%252e%252f",
    "%252f%252e%252e%252f",
    "%2F%2F",
    "%252F%252F",
    "%c0%af",
    "%25",
    "%2525",
]

def generate_variants(path: str):
    """
    Generate a set of request paths that vary slash and path encoding.
    Keep the output readable and deterministic.
    """
    path = path or "/"
    original = path

    # Normalize leading/trailing forms to avoid weird duplicates
    if not path.startswith("/"):
        path = "/" + path

    variants = {path, original, "/"}

    # 1) Replace the first few separators with encoded/slash variants
    segs = [p for p in path.split("/") if p != ""]
    if not segs:
        return sorted(variants)

    # Variant where all separators are replaced with a specific encoded form
    for enc in ENCODINGS:
        rebuilt = "/" + enc.join(segs)
        variants.add(rebuilt)

    # 2) Replace only the separator between selected segments
    for i in range(len(segs) - 1):
        for enc in ENCODINGS:
            rebuilt = "/" + "/".join(segs[:i+1]) + enc + "/".join(segs[i+1:])
            variants.add(rebuilt)

    # 3) Prefix/append edge-case forms
    for enc in ENCODINGS:
        variants.add("/" + enc + path.lstrip("/"))
        variants.add(path + enc)
        variants.add(path + enc + "/")

    # 4) Keep only legitimate-looking paths, but don't drop too much
    cleaned = set()
    for v in variants:
        if not v:
            continue
        if not v.startswith("/"):
            v = "/" + v
        cleaned.add(v)

    return sorted(cleaned)

def open_socket(host: str, port: int, use_https: bool, timeout: float):
    if use_https:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((host, port), timeout=timeout)
        return ctx.wrap_socket(raw, server_hostname=host)
    return socket.create_connection((host, port), timeout=timeout)

def send_raw_request(host: str, port: int, path: str, use_https: bool, headers: dict, timeout: float):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
    )
    for k, v in headers.items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"

    sock = None
    try:
        sock = open_socket(host, port, use_https, timeout)
        sock.sendall(req.encode("latin-1", "strict"))
        chunks = []
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        return b"".join(chunks)
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return f"__ERROR__ {type(exc).__name__}: {exc}".encode("utf-8", "replace")
    finally:
        if sock is not None:
            sock.close()

def parse_response(raw: bytes):
    if not raw:
        return "NO_RESPONSE", ""
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")

    # Split headers from body
    if "\r\n\r\n" in text:
        head, body = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""

    status_line = head.splitlines()[0] if head else ""
    return status_line, body[:MAX_BODY_PREVIEW]

def main():
    parser = argparse.ArgumentParser(description="General-purpose raw HTTP/HTTPS path normalization test")
    parser.add_argument("--host", required=True, help="Target host")
    parser.add_argument("--port", type=int, required=True, help="Target port")
    parser.add_argument("--path", default="/", help="Base path to test (example: /private/canary.txt)")
    parser.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout in seconds")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Sleep time between requests in seconds")
    parser.add_argument("--header", action="append", default=[], help='Custom header in "Name: Value" format; repeat as needed')
    parser.add_argument("--marker", default=None, help="Optional marker to look for in a response body")
    parser.add_argument("--nocheck", action="store_true", help="Do not show body previews (faster)")
    args = parser.parse_args()

    headers = {
        "User-Agent": "GenericPathFuzz/1.0",
        "Connection": "close",
    }

    for item in args.header:
        if ":" not in item:
            print(f"[-] Invalid header format: {item!r}. Expected 'Name: Value'", file=sys.stderr)
            continue
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()

    variants = generate_variants(args.path)
    print(f"[+] Target: {'https' if args.https else 'http'}://{args.host}:{args.port}")
    print(f"[+] Base path: {args.path}")
    print(f"[+] Generated {len(variants)} variants")

    for idx, variant in enumerate(variants, 1):
        print(f"\n[*] [{idx}/{len(variants)}] {variant}")
        raw = send_raw_request(args.host, args.port, variant, args.https, headers, args.timeout)
        status_line, body = parse_response(raw)

        if raw.startswith(b"__ERROR__"):
            print("[-] ERROR:", raw.decode("utf-8", errors="replace"))
            break

        print("    HTTP:", status_line)
        if not args.nocheck:
            print("    Body preview:", body[:MAX_BODY_PREVIEW].replace("\r", "\\r").replace("\n", "\\n"))
        if args.marker and args.marker in body:
            print(f"[!] Marker found for variant: {variant}")
            print(f"[!] Response body contained: {args.marker!r}")
        time.sleep(args.delay)

if __name__ == "__main__":
    main()
