from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        origin = self.headers.get("Origin")

        self.send_response(200)
        self.send_header("Content-Type", "text/html")

        # Reveals (fake) software versions - bad practice
        self.send_header("Server", "Apache/2.2.8")
        self.send_header("X-Powered-By", "PHP/5.2.4")

        # Bad CORS: copies any Origin and allows credentials
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")

        # Weak cookie: no Secure, HttpOnly or SameSite flags
        self.send_header("Set-Cookie", "session=abc123")

        self.end_headers()
        self.wfile.write(b"<h1>Intentionally vulnerable test server</h1>")


print("Test server running on http://127.0.0.1:5000 (press Ctrl+C to stop)")
HTTPServer(("127.0.0.1", 5000), Handler).serve_forever()