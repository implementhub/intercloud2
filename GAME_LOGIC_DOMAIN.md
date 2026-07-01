# Peer-to-Peer Rock-Paper-Scissors with SPIFFE/SPIRE mTLS

This repository contains a **de-centralized, Peer-to-Peer (P2P)** implementation of a **Rock-Paper-Scissors** game. It uses **SPIFFE/SPIRE** for Zero-Trust workload identification and **mutual TLS (mTLS)** to secure communications.

The game relies on a cryptographic **3-Message Commit-Reveal Protocol** to prevent cheating and secure score tracking mapped to verified **SPIFFE IDs**.

---

# 1. System Architecture (Localhost Setup)

In this Peer-to-Peer architecture, there is **no central server**. Every running instance of `game-domain.py` acts as both a **Client** and a **Server** simultaneously.

### Server Role

Runs in a background thread, listening for incoming connection challenges via a secure mTLS socket.

### Client Role

Runs in the foreground, providing an interactive command-line interface (CLI) to initiate challenges against a target peer.

Both workloads running on localhost fetch their cryptographic identities (**X.509-SVIDs**) dynamically from the local **SPIRE Agent** via the `spiffe-helper`.

```text
                       +-----------------------------------+
                       |           SPIRE SERVER            |
                       |       (Local Trust Domain)        |
                       +-----------------+-----------------+
                                         |
                       Issues Trust Bundles & SVIDs
                                         |
                                         v
                       +-----------------+-----------------+
                       |           SPIRE AGENT             |
                       +-----------------+-----------------+
                                         |
                                   SPIFFE Socket
                                         |
                    +--------------------+--------------------+
                    |                                         |
                    v                                         v
      +---------------------------+             +---------------------------+
      |        WORKLOAD 1         |             |        WORKLOAD 2         |
      |   Dir: ~/workload1/       |             |   Dir: ~/workload2/       |
      |                           |             |                           |
      |  +---------------------+  |             |  +---------------------+  |
      |  |    spiffe-helper    |  |             |  |    spiffe-helper    |  |
      |  | (Writes SVIDs)      |  |             |  | (Writes SVIDs)      |  |
      |  +----------+----------+  |             |  +----------+----------+  |
      |             |             |             |             |             |
      |  +----------v----------+  |             |  +----------v----------+  |
      |  |   game-domain.py    |  |             |  |   game-domain.py    |  |
      |  |                     |  |             |  |                     |  |
      |  | [Server] (Port 8001)|<==============|==|== HTTP POST /reveal |
      |  |                     |  |             |  |                     |  |
      |  | [Client]            |  |             |  | [Server] (Port 8002)|
      |  | Send /challenge ===>|==|============>|  |                     |  |
      |  +---------------------+  |             |  +---------------------+  |
      +---------------------------+             +---------------------------+
```

---

# 2. Commit-Reveal Protocol & Sequence Flow

To prevent a player from waiting for the opponent's move and choosing a winning hand afterwards, the game implements a cryptographic **Commit-Reveal protocol**.

## Commit

Player A chooses a secret move and generates a random salt.

A SHA256 hash (commitment) is computed:

```text
SHA256(move + salt)
```

The commitment is sent to Player B.

At this point:

- Player A is cryptographically bound to the move.
- Player B cannot determine the move.

## Response

Player B chooses a move and sends it openly to Player A.

## Reveal

Player A reveals:

- the original move
- the random salt

Player B verifies:

```text
SHA256(revealed_move + salt) == commitment
```

If verification succeeds, the winner is determined.

## Dynamic Sequence Flow

```text
 Workload 1 (Initiator / Client)                  Workload 2 (Responder / Server)
=================================                =================================

  [play_round()]
  - Choose secret move & salt
  - Compute SHA256 Commitment
          |
          |  1. Establish secure mTLS channel
          |     (Both sides verify certificates against SPIFFE trust bundle)
          |<------------------- mTLS Handshake ------------------->|
          |
          |  2. POST /challenge {"commitment": "hash..."}
          |--------------------------------------------------------> [do_POST() -> handle_challenge()]
          |                                                          - Extract verified peer SPIFFE ID
          |                                                          - Save commitment
          |                                                          - Choose secret move (e.g. "rock")
          |
          |  3. HTTP 200 Response {"move": "rock"} (JSON)
          |<-------------------------------------------------------- (Returns immediately in active request)
          |
  - Receive opponent's move
          |
          |  4. POST /reveal {"move": "paper", "salt": "xyz..."}
          |--------------------------------------------------------> [do_POST() -> handle_reveal()]
          |                                                          - Cryptographically verify commitment
          |                                                          - Execute decide() win/loss logic
          |                                                          - Update peer_id score
          |                                                          - Call get_own_spiffe_id()
          |
          |  5. HTTP 200 Response
          |     {
          |       "status": "win",
          |       "server_spiffe_id": "spiffe://..."
          |     }
          |<-------------------------------------------------------- (Returns game result & Server Identity)
          |
  - Extract Server SPIFFE ID
  - Update score for Server ID
  [Round Complete]                                           [Round Complete]
```

---

# 3. Code-to-Requirement Mapping

For evaluation purposes, here is the exact mapping of where core course requirements are implemented in `game-domain.py`.

## SPIFFE mTLS Handshake (Client & Server Authentication)

### Server Context

`start_server()` creates:

```python
ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
```

By setting:

```python
context.verify_mode = ssl.CERT_REQUIRED
```

the server forces client certificate verification.

### Client Context

`build_client_ssl_context()` loads the local SVID certificates:

- `certs/svid.pem`
- `certs/svid_key.pem`
- `certs/svid_bundle.pem`

to securely connect to peers.

---

## SPIFFE ID Extraction & Authorization

`get_peer_spiffe_id()` extracts the URI Subject Alternative Name (SAN) from the peer certificate using:

```python
handler.connection.getpeercert()
```

`GameHandler.do_POST()` strictly authorizes incoming requests.

If `get_peer_spiffe_id()` returns `None`, the server immediately returns:

```text
401 Unauthorized
```

preventing unauthenticated workloads from participating.

---

## Cryptographic Commitment Handling

The following functions implement the SHA256 commitment mechanism:

- `make_commitment()`
- `verify_commitment()`

---

## Tie Handling (No-Ties Rule)

Inside `play_round()`, a:

```python
while True:
```

loop ensures continuous gameplay.

If the server responds with:

```json
{
  "status": "tie"
}
```

the game simply executes:

```python
continue
```

and immediately starts a new round without leaving the active CLI session.

---

## Peer-Specific Scoreboard

Scores are stored in the global in-memory dictionary:

```python
scores
```

Each score is mapped directly to a verified SPIFFE ID:

```text
spiffe://<trust-domain>/<service>
```

---

# 4. How to Run Locally

## Step 1 — Trigger SVID Generation

Make sure SPIRE is running and your `spiffe-helper` instances have generated the workloads' credentials.

Trigger them using:

```bash
~/start-helpers.sh
```

---

## Step 2 — Start Workload 1 (Port 8001)

Open a terminal (for example, a tmux pane) and run:

```bash
cd ~/workload1
./game-domain.py --port 8001 --target https://localhost:8002
```

---

## Step 3 — Start Workload 2 (Port 8002)

Open another terminal and run:

```bash
cd ~/workload2
./game-domain.py --port 8002 --target https://localhost:8001
```

---

## Step 4 — Play

Start a new secure game round by typing:

```text
n
```

Display the scoreboard (containing validated SPIFFE IDs) by typing:

```text
s
```
