import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("PORT", "8080"))

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/health" or self.path == "/health":
            self.send_json(200, {"status": "ok", "service": "server-test"})
        elif self.path.startswith("/api/"):
            self.send_json(200, {
                "message": "hello from jkbase server container",
                "path": self.path,
                "port": PORT,
            })
        else:
            self.send_json(404, {"error": "not found"})

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"server-test listening on :{PORT}", flush=True)
    server.serve_forever()
