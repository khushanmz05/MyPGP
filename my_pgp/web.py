"""Tiny dependency-free local API and static-file server."""
from __future__ import annotations
import json, secrets
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .encoding import decode_input, encode_output
from .pipeline import run_pipeline

ROOT = Path(__file__).resolve().parent.parent / "frontend"

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)
    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/api/key":
                size = int(request.get("bytes", 16))
                if not 1 <= size <= 4096:
                    raise ValueError("key size must be between 1 and 4096 bytes")
                return self._json(200, {"key": secrets.token_hex(size), "bytes": size})
            if self.path == "/api/process":
                decrypt = request.get("mode") == "decrypt"
                source = decode_input(str(request.get("input", "")), str(request.get("input_format", "hex" if decrypt else "text")))
                result = run_pipeline(source, request.get("steps", []), decrypt)
                output_format = str(request.get("output_format", "text" if decrypt else "hex"))
                return self._json(200, {"output": encode_output(result, output_format), "input_bytes": len(source), "output_bytes": len(result)})
            self._json(404, {"error": "not found"})
        except Exception as exc:
            self._json(400, {"error": str(exc)})

def main():
    address = ("127.0.0.1", 8080)
    print(f"my_pgp frontend: http://{address[0]}:{address[1]}")
    ThreadingHTTPServer(address, Handler).serve_forever()

if __name__ == "__main__":
    main()
