# from http.server import HTTPServer, BaseHTTPRequestHandler, SimpleHTTPRequestHandler
# import ssl
# import threading
#
#
# def get_server():
#     httpd = HTTPServer(('localhost', 5001), SimpleHTTPRequestHandler)
#
#     httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="key.pem",certfile='certificate.pem', server_side=True)
#
#     t = threading.Thread(target=httpd.serve_forever)
#     t.daemon = True
#     return t


from http.server import HTTPServer, BaseHTTPRequestHandler, SimpleHTTPRequestHandler
import ssl
import threading



def start_server(ip):
    handler = SimpleHTTPRequestHandler
    port = 5001
    httpd = HTTPServer((ip, port), SimpleHTTPRequestHandler)

    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="key.pem",certfile='certificate.pem', server_side=True)
    print("certificate server on port: ", port)

    t = threading.Thread(target=httpd.serve_forever)
    t.daemon = True
    t.start()
    return t
