#!/usr/bin/env python3
import json
import ssl
import time
import urllib.request
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
import threading
import secrets
import hashlib
import os
import logging
import subprocess

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("game-service")

MOVES = ["rock", "paper", "scissors"]

# Globale Speicherstrukturen
active_games = {}

# =====================================================================
# REQUIREMENT: CLI Interface with Score Tracking (3 Points)
# Part 1: In-Memory scoreboard tracking wins and losses per SPIFFE ID
# =====================================================================
scores = {}  # spiffe_id -> {"wins": 0, "losses": 0}

# ---------- Crypto & Spiel-Logik Helpers ----------

# =====================================================================
# REQUIREMENT: Game Protocol with Commit-Reveal (3 Points)
# Part 1: Cryptographic Commitment Verification using SHA256 Hashing
# =====================================================================
def make_commitment(move, salt):
    """Generates the SHA256 hash (commitment) of the move concatenated with the salt."""
    return hashlib.sha256(f"{move}{salt}".encode()).hexdigest()

def verify_commitment(move, salt, commitment):
    """Verifies if the revealed move and salt match the original commitment."""
    return make_commitment(move, salt) == commitment

def decide(a, b):
    if a == b:
        return "tie"
    wins = {("rock", "scissors"), ("scissors", "paper"), ("paper", "rock")}
    return "win" if (a, b) in wins else "loss"

# =====================================================================
# REQUIREMENT: CLI Interface with Score Tracking (3 Points)
# Part 2: Updating the local database mapped directly to peer SPIFFE ID
# =====================================================================
def update_score(peer_id, result):
    if peer_id not in scores:
        scores[peer_id] = {"wins": 0, "losses": 0}
    if result == "win":
        scores[peer_id]["wins"] += 1
    elif result == "loss":
        scores[peer_id]["losses"] += 1

# =====================================================================
# REQUIREMENT: Cross-domain Authentication (5 Points)
# Part 1: Extraction of peer SPIFFE ID (URI SAN) from client cert
# =====================================================================
def get_peer_spiffe_id(handler):
    """Extrahiert die SPIFFE-ID (URI) aus dem Client-Zertifikat."""
    try:
        # getpeercert() pulls the peer certificate verified during the TLS handshake
        cert = handler.connection.getpeercert()
        if cert and 'subjectAltName' in cert:
            for san in cert['subjectAltName']:
                if san[0] == 'URI' and san[1].startswith('spiffe://'):
                    return san[1]
    except Exception as e:
        logger.error(f"Fehler bei SPIFFE-ID Extraktion: {e}")
    return None

def get_own_spiffe_id():
    """Liest die eigene SPIFFE-ID absolut und fehlersicher über openssl aus."""
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = os.path.join(base_dir, 'certs', 'svid.pem')
        
        if not os.path.exists(cert_path):
            return "unknown"

        result = subprocess.run(
            ['openssl', 'x509', '-in', cert_path, '-text', '-noout'],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.split('\n'):
            if 'URI:spiffe://' in line:
                return line.split('URI:')[1].strip()
    except Exception:
        return "unknown"
    return "unknown"

# ---------- HTTP Server Handler ----------

class GameHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        # =====================================================================
        # REQUIREMENT: Cross-domain Authentication (5 Points)
        # Part 2: Authorization gate. Validates extracted SPIFFE ID and block
        # any unauthenticated workload immediately with 401 Unauthorized.
        # =====================================================================
        peer_id = get_peer_spiffe_id(self)
        if not peer_id:
            logger.warning(f"Abgewiesen: Unauthentifizierter Zugriff von {self.client_address[0]}")
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"Unauthorized: Valid SPIFFE ID required.")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        data = json.loads(body)

        if self.path == "/challenge" and data.get("type") == "challenge":
            self.handle_challenge(data, peer_id)
        elif self.path == "/reveal" and data.get("type") == "reveal":
            self.handle_reveal(data, peer_id)
        else:
            self.send_response(400)
            self.end_headers()

    # =====================================================================
    # REQUIREMENT: Game Protocol with Commit-Reveal (3 Points)
    # Part 2: Receiving MESSAGE 1 (Challenge) & replying with MESSAGE 2 (Response)
    # =====================================================================
    def handle_challenge(self, data, peer_id):
        commitment = data["commitment"]
        my_move = secrets.choice(MOVES)

        # Store commitment and local choice mapped to opponent ID to handle late reveals
        active_games[peer_id] = {
            "commitment": commitment,
            "my_move": my_move
        }
        logger.info(f"Challenge von {peer_id} erhalten. Mein verdeckter Zug: {my_move}")

        # Sending MESSAGE 2 directly in the active HTTP response body to avoid network deadlocks
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "type": "response",
            "move": my_move
        }).encode())

    # =====================================================================
    # REQUIREMENT: Game Protocol with Commit-Reveal (3 Points)
    # Part 3: Receiving MESSAGE 3 (Reveal), verifying commitment & determining winner
    # =====================================================================
    def handle_reveal(self, data, peer_id):
        game = active_games.get(peer_id)
        if not game:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "No active challenge for this ID"}).encode())
            return

        opponent_move = data["move"]
        opponent_salt = data["salt"]

        # Validate cryptographic commitment before processing logic to guarantee fairness
        if not verify_commitment(opponent_move, opponent_salt, game["commitment"]):
            logger.error(f"❌ Verifikation fehlgeschlagen für {peer_id}! Schwindel erkannt.")
            self.send_response(400)
            self.end_headers()
            return

        my_move = game["my_move"]
        server_result = decide(my_move, opponent_move)
        
        logger.info(f"[DUELL] Ich ({my_move}) vs {peer_id} ({opponent_move}) -> Ergebnis für mich: {server_result}")
        
        if server_result != "tie":
            update_score(peer_id, server_result)
            del active_games[peer_id]

        own_id = get_own_spiffe_id()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "status": server_result,
            "server_spiffe_id": own_id
        }).encode())

    def log_message(self, format, *args):
        pass

# ---------- Client-Spielfluss (Initiator) ----------

# =====================================================================
# BONUS: WebPKI/ACME – Scoreboard-Endpoint via HTTPS mit Let's Encrypt
# =====================================================================
class PublicScoreHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path != "/score":
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"scores": scores}).encode())

    def log_message(self, format, *args):
        pass

# =====================================================================
# REQUIREMENT: SPIFFE mTLS - Single Domain (7 Points)
# Part 1: Loading SPIFFE certificates & establishing mutual TLS (Client-side)
# =====================================================================
def build_client_ssl_context():
    context = ssl.create_default_context()
    context.load_cert_chain('certs/svid.pem', 'certs/svid_key.pem')
    context.load_verify_locations('certs/svid_bundle.pem')
    context.check_hostname = False
    return context

def send_request(url, payload, context):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, context=context, timeout=5) as r:
        return json.loads(r.read().decode())

def play_round(target_url, context):
    # =====================================================================
    # REQUIREMENT: Game Protocol with Commit-Reveal (3 Points)
    # Part 4: Client execution. Choosing move, sending Challenge, receiving Response,
    # then initiating Reveal.
    # =====================================================================
    while True:
        my_move = secrets.choice(MOVES)
        salt = secrets.token_hex(8)
        commitment = make_commitment(my_move, salt)

        logger.info(f"[CLIENT] Starte neue Runde. Mein geheimer Zug: {my_move}")

        # Sending MESSAGE 1 (Challenge)
        try:
            response_data = send_request(f"{target_url}/challenge", {
                "type": "challenge",
                "commitment": commitment
            }, context)
        except Exception as e:
            logger.error(f"Challenge fehlgeschlagen: {e}")
            return

        # Receiving MESSAGE 2 (Response)
        opponent_move = response_data.get("move")
        logger.info(f"[CLIENT] Gegner-Zug empfangen: {opponent_move}. Sende Reveal...")

        # Sending MESSAGE 3 (Reveal)
        try:
            result_data = send_request(f"{target_url}/reveal", {
                "type": "reveal",
                "move": my_move,
                "salt": salt
            }, context)
        except Exception as e:
            logger.error(f"Reveal fehlgeschlagen: {e}")
            return

        server_status = result_data.get("status")
        server_spiffe_id = result_data.get("server_spiffe_id", target_url)
        
        # =====================================================================
        # REQUIREMENT: Game Protocol with Commit-Reveal (3 Points)
        # Part 5: Tie Handling. If "tie" status is returned, the loop replays
        # immediately using 'continue' statement.
        # =====================================================================
        if server_status == "tie":
            logger.info("  Unentschieden! Sofortige Replay-Runde wird gestartet...")
            time.sleep(1)
            continue
        
        client_result = "loss" if server_status == "win" else "win"
        logger.info(f"🎉 Rundenende! Ergebnis für mich: {client_result.upper()}")
        
        update_score(server_spiffe_id, client_result)
        break

# =====================================================================
# REQUIREMENT: CLI Interface with Score Tracking (3 Points)
# Part 3: CLI implementation to challenge, show scoreboard and quit.
# =====================================================================
def game_loop(target_url):
    context = build_client_ssl_context()
    time.sleep(2)
    
    while True:
        print("\n--- SPIFFE ROCK-PAPER-SCISSORS ---")
        print(" [n] Neues Spiel starten")
        print(" [s] Aktuelle Scores anzeigen")
        print(" [x] Beenden")
        action = input("Was möchtest du tun? ").strip().lower()

        if action == "n":
            play_round(target_url, context)
        elif action == "s":
            print(json.dumps({"scores": scores}, indent=4))
        elif action == "x":
            print("Spiel beendet.")
            break

# =====================================================================
# REQUIREMENT: SPIFFE mTLS - Single Domain (7 Points)
# Part 2: Threading HTTPS server context forcing mTLS (Server-side)
# =====================================================================
def start_server(port):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('certs/svid.pem', 'certs/svid_key.pem')
    context.load_verify_locations('certs/svid_bundle.pem')
    context.verify_mode = ssl.CERT_REQUIRED  # Enforces client cert authentication

    server = ThreadingHTTPServer(('localhost', port), GameHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    logger.info(f"mTLS Game Server lauscht auf Port {port}...")
    server.serve_forever()


# =====================
# NEEDED FOR THE SCORE-BOARD WITH HTTPS
# ========================
def start_public_https_server(httpport, cert_path, key_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    server = ThreadingHTTPServer(("0.0.0.0", httpport), PublicScoreHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    logger.info(f"[PUBLIC] HTTPS Scoreboard erreichbar auf :{httpport}/score")
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True, help="Lokaler Server-Port")
    parser.add_argument('--target', type=str, required=True, help="Gegnerische HTTPS-URL (z.B. https://localhost:8002)")
    parser.add_argument('--httpport', type=int, default=8443, help="Öffentlicher Scoreboard-Port")
    parser.add_argument('--cert', type=str,
                         default="/home/azureuser/acme-lab/04-finalize/http-certificate.pem",
                         help="Pfad zum Let's-Encrypt-Zertifikat")
    parser.add_argument('--key', type=str,
                         default="/home/azureuser/acme-lab/04-finalize/domain-key.pem",
                         help="Pfad zum privaten Domain-Key")
    
    args = parser.parse_args()

    if not all(os.path.exists(f'certs/{f}') for f in ['svid.pem', 'svid_key.pem', 'svid_bundle.pem']):
        print("Error: Zertifikatsdateien nicht gefunden! Bitte starte zuerst den spiffe-helper.")
        return 1

    threading.Thread(
        target=start_public_https_server,
        args=(args.httpport, args.cert, args.key),
        daemon=True
    ).start()

    threading.Thread(target=start_server, args=(args.port,), daemon=True).start()
    game_loop(args.target)

if __name__ == '__main__':
    main()