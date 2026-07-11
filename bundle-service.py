#!/usr/bin/env python3

import argparse
import ssl
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import os


class BundleHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path not in ["/", "/bundle"]:
            self.send_response(404)
            self.end_headers()
            return

        bundle_path = self.server.bundle_path

        if not os.path.exists(bundle_path):
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Bundle not found")
            return

        with open(bundle_path, "r") as f:
            bundle = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(bundle)))
        self.end_headers()
        self.wfile.write(bundle.encode())

        print(f"✓ Bundle served to {self.client_address[0]}")

    def log_message(self, format, *args):
        pass


def start_public_https_server(port, cert_path, key_path, bundle_path):
    # Fix gegenüber der alten Version: reiner Server-Kontext statt
    # ssl.Purpose.CLIENT_AUTH (der fälschlich mTLS suggeriert, ohne
    # dass verify_mode je gesetzt wurde). Dieser Endpoint ist bewusst
    # öffentlich, ohne Client-Zertifikat.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    server = ThreadingHTTPServer(("0.0.0.0", port), BundleHandler)
    server.bundle_path = bundle_path
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"[PUBLIC] HTTPS Bundle-Endpoint erreichbar auf :{port} (/bundle)")
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True,
                         help="Öffentlicher Port für den Bundle-Endpoint")
    parser.add_argument('--cert', type=str,
                         default="/home/azureuser/acme-lab/04-finalize/http-certificate.pem",
                         help="Pfad zum Let's-Encrypt-Zertifikat")
    parser.add_argument('--key', type=str,
                         default="/home/azureuser/acme-lab/04-finalize/domain-key.pem",
                         help="Pfad zum privaten Domain-Key")
    parser.add_argument('--bundle', type=str,
                         default="/tmp/primary.bundle",
                         help="Pfad zum SPIFFE Trust Bundle, das ausgeliefert werden soll")
    args = parser.parse_args()

    if not os.path.exists(args.cert) or not os.path.exists(args.key):
        print(f"Error: Zertifikat oder Key nicht gefunden ({args.cert} / {args.key})")
        return 1

    print("Start Bundle Download Server")
    start_public_https_server(args.port, args.cert, args.key, args.bundle)


if __name__ == '__main__':
    main()