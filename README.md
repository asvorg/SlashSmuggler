# SlashSmuggler

SlashSmuggler is a lightweight Python tool for fuzzing raw HTTP/HTTPS paths to test how servers and intermediaries handle encoded slashes, traversal sequences, and path-normalization edge cases.

## What it does

- Generates many path variants using common slash and encoding tricks such as:
  - `/`
  - `%2F`, `%252F`, `%5C`
  - `%2e%2e%2f`
  - `%c0%af`
- Sends raw GET requests without relying on a browser or client-side normalization.
- Supports both HTTP and HTTPS targets.
- Prints the HTTP status and a body preview for each variant.
- Can optionally search for a marker string in responses.

## Usage

Basic HTTP test:

```bash
python3 fuzz.py --host 127.0.0.1 --port 3000 --path /private/canary.txt
```

HTTPS test with marker search:

```bash
python3 fuzz.py --host example.com --port 443 --path /private/canary.txt --https --marker "SUPER_SECRET_TOKEN"
```

Custom headers:

```bash
python3 fuzz.py --host example.com --port 443 --path /private/canary.txt --header "Authorization: Bearer token"
```

## Notes

This project is intended for security research and controlled testing in environments you own or are authorized to test. Use responsibly.
