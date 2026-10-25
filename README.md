# AirDrop-Zero (Phase 3: Modern Desktop GUI & Encrypted Mesh)

AirDrop-Zero is a zero-configuration, secure local network file sharing tool built with pure Python, **CustomTkinter**, and **Fernet AES-128-CBC + HMAC-SHA256**.

---

## Features

* **Phase 1 (Networking Core)**:
  * UDP broadcast peer discovery over port `6000` with cross-platform socket options (`SO_REUSEADDR` / `SO_REUSEPORT` / Windows `SIO_UDP_CONNRESET`).
  * TCP file chunk streaming (64 KB chunks).
* **Phase 2 (End-to-End Encryption)**:
  * AES authenticated encryption (`cryptography.fernet`) with deterministic key derivation from a shared mesh passphrase via **PBKDF2-HMAC-SHA256** (100,000 iterations).
  * Framed encrypted chunks with length prefix and EOF sentinel.
  * Bit-for-bit **SHA-256 integrity verification** on reconstructed files before ACK confirmation.
* **Phase 3 (Modern Desktop GUI)**:
  * Dark-mode interface built with **CustomTkinter**.
  * **Top Bar**: Live node name, assigned TCP port, local IP, encryption status, and discovery toggle indicator (`● Discovery: Active`).
  * **Nearby Peers Panel**: Live dynamic list of discovered local peers (refreshed every 2s). Click to select target.
  * **Transfer Card**: Native 'Browse File' picker, 'Send Encrypted File' button, live progress bar, speed indicator (MB/s), and SHA-256 confirmation.
  * **Activity & Security Audit Log**: Scrollable real-time log of discovery heartbeats, inbound/outbound encrypted streams, and cryptographic verification results.
  * **Non-Blocking Threading**: Network listeners and transfers run in background `threading.Thread` instances with a thread-safe UI queue dispatch so the GUI never freezes.

---

## Quick Start: Launching the Desktop GUI

To test on your laptop, open two separate terminals in the project folder:

### Terminal 1 (Alice):
```powershell
python gui.py --name Alice --port 5001
```

### Terminal 2 (Bob):
```powershell
python gui.py --name Bob --port 5002
```

*(You can also use `python app.py --gui --name Alice --port 5001`)*

### How to Transfer:
1. In Alice's GUI, Bob will appear in the **Nearby Peers** list on the left.
2. Click on **👤 Bob** to select him as the transfer target.
3. Click **Browse File...** to select any file from disk.
4. Click **Send Encrypted File**.
5. Watch the progress bar stream encrypted chunks in real time. Bob's GUI will show the inbound transfer, verify the SHA-256 checksum, and log the integrity match!
6. Click **Open Received Files** in Bob's GUI to view the saved file.

---

## CLI Mode

If you prefer terminal-only operation without GUI:
```powershell
python app.py --name Alice --port 5001
python app.py --name Bob --port 5002
```

---

## Verification Test Suites

1. **Phase 2 Crypto & Core Networking Test**:
   ```powershell
   python test_networking_core.py
   ```
2. **Phase 3 GUI Integration Test**:
   ```powershell
   python test_gui_integration.py
   ```
3. **Dual-Terminal Simulation Test**:
   ```powershell
   python demo_two_terminals.py
   ```
