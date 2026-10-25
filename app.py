"""AirDrop-Zero: CLI Entrypoint (Phase 2)
CLI entrypoint linking peer discovery, AES encrypted chunk streaming,
and SHA-256 integrity verification.
"""

import argparse
import os
import sys
import threading
import time
from typing import Optional

from crypto_utils import DEFAULT_PASSPHRASE, MeshCrypto
from discovery import PeerDiscovery
from transfer import FileReceiver, format_bytes, render_progress_bar, send_file

# Reconfigure stdout/stderr to UTF-8 on Windows if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Global lock for clean terminal printing across threads
print_lock = threading.Lock()


def safe_print(*args, **kwargs):
    """Thread-safe print to avoid garbled console output."""
    with print_lock:
        print(*args, **kwargs)
        sys.stdout.flush()


class AirDropApp:
    def __init__(
        self,
        name: str,
        tcp_port: int,
        discovery_port: int = 6000,
        passphrase: Optional[str] = DEFAULT_PASSPHRASE,
        save_dir: Optional[str] = None,
    ):
        self.name = name
        self.tcp_port = tcp_port
        self.discovery_port = discovery_port
        self.passphrase = passphrase
        self.save_dir = save_dir or f"./downloads_{tcp_port}"
        self.running = False

        # Initialize Mesh Crypto (Fernet AES)
        self.crypto = MeshCrypto(passphrase) if passphrase else None

        # Initialize Discovery
        self.discovery = PeerDiscovery(
            name=self.name,
            tcp_port=self.tcp_port,
            broadcast_port=self.discovery_port,
            on_peer_found=self._on_peer_found,
            on_peer_lost=self._on_peer_lost,
        )

        # Initialize TCP Receiver with AES decryption & SHA-256 verification
        self.receiver = FileReceiver(
            port=self.tcp_port,
            save_dir=self.save_dir,
            crypto=self.crypto,
            on_start=self._on_receive_start,
            on_progress=self._on_receive_progress,
            on_complete=self._on_receive_complete,
            on_error=self._on_receive_error,
        )

    def _on_peer_found(self, peer: dict):
        safe_print(
            f"\n[+] Peer discovered: '{peer['name']}' at {peer['ip']}:{peer['tcp_port']}"
        )
        sys.stdout.write("airdrop> ")
        sys.stdout.flush()

    def _on_peer_lost(self, peer: dict):
        safe_print(f"\n[-] Peer departed / timed out: '{peer['name']}'")
        sys.stdout.write("airdrop> ")
        sys.stdout.flush()

    def _on_receive_start(
        self, filename: str, filesize: int, sender: str, is_encrypted: bool
    ):
        enc_badge = "[AES-Encrypted]" if is_encrypted else "[Plaintext]"
        safe_print(
            f"\n[<] Incoming transfer {enc_badge}: '{filename}' ({format_bytes(filesize)}) from {sender}"
        )

    def _on_receive_progress(
        self, filename: str, received: int, total: int, speed: float
    ):
        bar = render_progress_bar(received, total, speed)
        with print_lock:
            sys.stdout.write(f"\r[< Receiving] {bar}  ")
            sys.stdout.flush()

    def _on_receive_complete(
        self,
        filename: str,
        filepath: str,
        filesize: int,
        elapsed: float,
        sha256_hash: str,
    ):
        avg_speed = filesize / max(elapsed, 0.001)
        safe_print(
            f"\n[OK] Received & Verified '{filename}' ({format_bytes(filesize)}) in {elapsed:.2f}s "
            f"({format_bytes(int(avg_speed))}/s)\n"
            f"     SHA-256 : {sha256_hash} [MATCH]\n"
            f"     Saved to: {filepath}"
        )
        sys.stdout.write("airdrop> ")
        sys.stdout.flush()

    def _on_receive_error(self, filename: str, error: str):
        safe_print(f"\n[FAIL] Failed receiving '{filename}': {error}")
        sys.stdout.write("airdrop> ")
        sys.stdout.flush()

    def start(self):
        self.running = True
        self.discovery.start()
        self.receiver.start()

    def stop(self):
        self.running = False
        safe_print("\nShutting down AirDrop-Zero...")
        self.discovery.stop()
        self.receiver.stop()
        safe_print("Goodbye!")

    def list_peers(self):
        peers = self.discovery.get_peers()
        if not peers:
            safe_print(
                f"No peers currently discovered on UDP port {self.discovery_port}."
            )
            safe_print(
                "Tip: Launch a second terminal running 'python app.py --name Bob --port 5002'"
            )
            return

        now = time.time()
        safe_print("\n" + "=" * 65)
        safe_print(
            f"{'#':<3} {'Name':<18} {'IP Address':<16} {'Port':<8} {'Last Seen':<10}"
        )
        safe_print("-" * 65)
        for idx, p in enumerate(peers, start=1):
            age = max(0, int(now - p["last_seen"]))
            safe_print(
                f"{idx:<3} {p['name']:<18} {p['ip']:<16} {p['tcp_port']:<8} {f'{age}s ago':<10}"
            )
        safe_print("=" * 65 + "\n")

    def handle_send(self, target_arg: str, filepath: str):
        if not os.path.isfile(filepath):
            safe_print(f"[!] Error: File '{filepath}' does not exist.")
            return

        peers = self.discovery.get_peers()
        target_peer = None

        if target_arg.isdigit():
            idx = int(target_arg)
            if 1 <= idx <= len(peers):
                target_peer = peers[idx - 1]

        if not target_peer:
            for p in peers:
                if p["name"].lower() == target_arg.lower():
                    target_peer = p
                    break

        if not target_peer:
            safe_print(
                f"[!] Peer '{target_arg}' not found. Run 'peers' to see active peers."
            )
            return

        ip = target_peer["ip"]
        port = target_peer["tcp_port"]
        filesize = os.path.getsize(filepath)
        enc_badge = "[AES-Encrypted]" if self.crypto else "[Plaintext]"

        safe_print(
            f"[>] Sending '{os.path.basename(filepath)}' ({format_bytes(filesize)}) {enc_badge} to '{target_peer['name']}' ({ip}:{port})..."
        )

        def sender_progress(fname, sent, total, speed):
            bar = render_progress_bar(sent, total, speed)
            with print_lock:
                sys.stdout.write(f"\r[> Sending  ] {bar}  ")
                sys.stdout.flush()

        success, msg, file_hash = send_file(
            host=ip,
            port=port,
            filepath=filepath,
            sender_name=self.name,
            crypto=self.crypto,
            progress_callback=sender_progress,
        )

        with print_lock:
            sys.stdout.write("\n")
            sys.stdout.flush()

        if success:
            safe_print(f"[OK] Success: {msg}")
        else:
            safe_print(f"[FAIL] Transfer failed: {msg}")

    def create_dummy_file(self, filename: str, size_mb: float):
        try:
            total_bytes = int(float(size_mb) * 1024 * 1024)
            chunk = b"AirDrop-Zero-Phase2-DataChunk-PaddingBlock\n"
            written = 0
            with open(filename, "wb") as f:
                while written < total_bytes:
                    to_write = min(len(chunk), total_bytes - written)
                    f.write(chunk[:to_write])
                    written += to_write
            safe_print(
                f"[OK] Created test file '{filename}' ({format_bytes(total_bytes)})"
            )
        except Exception as e:
            safe_print(f"[!] Failed to create file: {e}")

    def print_banner(self):
        enc_status = (
            f"AES-128-CBC + HMAC-SHA256 (Passphrase: '{self.passphrase}')"
            if self.crypto
            else "Disabled (Plaintext)"
        )
        banner = f"""
============================================================
              AirDrop-Zero (Phase 2: Encrypted Mesh)
============================================================
 Node Name       : {self.name}
 TCP Transfer    : Listening on 0.0.0.0:{self.tcp_port}
 UDP Discovery   : Broadcasting on port {self.discovery_port}
 Encryption      : {enc_status}
 Downloads Dir   : {os.path.abspath(self.save_dir)}
============================================================
 Commands:
   peers                        - List discovered network peers
   send <#|Name> <file_path>    - Send a file to a peer
   make-file <name> <size_mb>   - Create dummy test file
   help                         - Show this help message
   exit / quit                  - Shutdown node
============================================================
"""
        safe_print(banner)

    def run_cli(self):
        self.start()
        self.print_banner()

        while self.running:
            try:
                line = input("airdrop> ").strip()
                if not line:
                    continue

                parts = line.split()
                cmd = parts[0].lower()

                if cmd in ["exit", "quit", "q"]:
                    break
                elif cmd in ["peers", "ls"]:
                    self.list_peers()
                elif cmd == "send":
                    if len(parts) < 3:
                        safe_print("Usage: send <peer_index_or_name> <file_path>")
                    else:
                        target = parts[1]
                        filepath = " ".join(parts[2:])
                        self.handle_send(target, filepath)
                elif cmd in ["make-file", "makefile", "dummy"]:
                    if len(parts) < 3:
                        safe_print("Usage: make-file <filename> <size_in_mb>")
                    else:
                        self.create_dummy_file(parts[1], float(parts[2]))
                elif cmd in ["help", "?"]:
                    self.print_banner()
                elif cmd in ["clear", "cls"]:
                    os.system("cls" if os.name == "nt" else "clear")
                else:
                    safe_print(
                        f"Unknown command: '{cmd}'. Type 'help' for available commands."
                    )

            except (KeyboardInterrupt, EOFError):
                break
            except Exception as e:
                safe_print(f"[!] Error: {e}")

        self.stop()


def main():
    parser = argparse.ArgumentParser(
        description="AirDrop-Zero: Encrypted Mesh Discovery & TCP File Transfer"
    )
    parser.add_argument(
        "--name",
        "-n",
        type=str,
        default=f"Peer-{os.getpid() % 1000}",
        help="Display name for this peer (e.g. Alice, Bob)",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=5001,
        help="TCP port to listen on for incoming file transfers (e.g. 5001, 5002)",
    )
    parser.add_argument(
        "--discovery-port",
        "-d",
        type=int,
        default=6000,
        help="UDP broadcast port for peer discovery (default: 6000)",
    )
    parser.add_argument(
        "--passphrase",
        "-k",
        type=str,
        default=DEFAULT_PASSPHRASE,
        help=f"Shared mesh passphrase for AES chunk encryption (default: '{DEFAULT_PASSPHRASE}')",
    )
    parser.add_argument(
        "--no-encrypt",
        action="store_true",
        help="Disable AES encryption and transfer in plaintext",
    )
    parser.add_argument(
        "--save-dir",
        "-s",
        type=str,
        default=None,
        help="Directory to save received files (default: ./downloads_<port>)",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the modern dark-mode Desktop GUI (Phase 3)",
    )

    args = parser.parse_args()
    passphrase = None if args.no_encrypt else args.passphrase

    if args.gui:
        try:
            from gui import AirDropGUI

            app = AirDropGUI(
                name=args.name,
                tcp_port=args.port,
                discovery_port=args.discovery_port,
                passphrase=passphrase or DEFAULT_PASSPHRASE,
                save_dir=args.save_dir,
            )
            app.mainloop()
            return
        except ImportError as e:
            safe_print(f"[!] Failed to launch GUI: {e}. Falling back to CLI mode.")

    app = AirDropApp(
        name=args.name,
        tcp_port=args.port,
        discovery_port=args.discovery_port,
        passphrase=passphrase,
        save_dir=args.save_dir,
    )
    app.run_cli()


if __name__ == "__main__":
    main()
