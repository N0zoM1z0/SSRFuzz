from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import socket

# ANSI color codes
GREEN = "\033[92m"
RESET = "\033[0m"

class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Prepare response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Set different content based on the path
        if self.path == "/ssrftest":
            self.wfile.write(b"VULN")
        else:
            self.wfile.write(b"NO")
        
        # Log the connection
        client_ip, client_port = self.client_address
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        log_message = f"{timestamp} - Connection from {client_ip}:{client_port} - Path: {self.path} - Headers: {dict(self.headers)}"
        
        # Print in green if accessing /ssrftest
        if self.path == "/ssrftest":
            print(f"{GREEN}[SSRF DETECTED] {log_message}{RESET}")
        else:
            print(log_message)

def run_server(host="localhost", port=8000):
    server_address = (host, port)
    httpd = HTTPServer(server_address, CallbackHandler)
    
    print(f"{GREEN}Starting callback server on http://{host}:{port}{RESET}")
    print(f"{GREEN}Watch for SSRF at http://{host}:{port}/ssrftest{RESET}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"{GREEN}Shutting down server...{RESET}")
        httpd.server_close()

if __name__ == "__main__":
    run_server()