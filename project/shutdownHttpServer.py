from http.server import HTTPServer, BaseHTTPRequestHandler, SimpleHTTPRequestHandler
import socketserver
import threading

httpd = None

class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if (self.path == '/shutdown'):
            global httpd
            httpd.shutdown()

        return SimpleHTTPRequestHandler.do_GET(self)


def start_server(ip):
    handler = SimpleHTTPRequestHandler
    port = 5003
    global httpd
    httpd = socketserver.ThreadingTCPServer((ip, port), CustomHandler)
    httpd.daemon=True
    httpd.allow_reuse_address = True
    print("shutdown server on port: ", port)

    t = threading.Thread(target=httpd.serve_forever)
    t.daemon = True
    t.start()
    return t
