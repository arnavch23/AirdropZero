"""AirDrop-Zero: Desktop GUI (Phase 3)
Modern dark-mode GUI using CustomTkinter for encrypted local file sharing.
"""

import argparse
import datetime
import logging
import os
import platform
import queue
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog
from typing import Dict, Optional

import customtkinter as ctk

from crypto_utils import DEFAULT_PASSPHRASE, MeshCrypto
from discovery import PeerDiscovery
from transfer import FileReceiver, format_bytes, send_file

logger = logging.getLogger("gui")

# Set modern dark mode theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


def get_local_ip() -> str:
    """Detect local network IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


class AirDropGUI(ctk.CTk):
    def __init__(
        self,
        name: str,
        tcp_port: int,
        discovery_port: int = 6000,
        passphrase: str = DEFAULT_PASSPHRASE,
        save_dir: Optional[str] = None,
    ):
        super().__init__()

        self.node_name = name
        self.tcp_port = tcp_port
        self.discovery_port = discovery_port
        self.passphrase = passphrase
        self.save_dir = os.path.abspath(save_dir or f"./downloads_{tcp_port}")
        self.local_ip = get_local_ip()

        # Thread-safe UI update queue
        self.ui_queue = queue.Queue()
        self.is_running = True

        # Crypto instance
        self.crypto = MeshCrypto(self.passphrase)

        # Selected state
        self.selected_peer: Optional[dict] = None
        self.selected_filepath: Optional[str] = None
        self.is_sending = False
        self.discovery_active = True

        # Window configuration
        self.title(f"AirDrop-Zero | {self.node_name} (Port {self.tcp_port})")
        self.geometry("1020 x 740")
        self.minsize(920, 640)

        # Build UI Components
        self._build_top_bar()
        self._build_main_layout()

        # Start periodic GUI queue processor
        self._schedule_ui_queue_poll()

        # Initialize Backend Discovery & TCP Receiver
        self.discovery = PeerDiscovery(
            name=self.node_name,
            tcp_port=self.tcp_port,
            broadcast_port=self.discovery_port,
            on_peer_found=self._on_peer_found_backend,
            on_peer_lost=self._on_peer_lost_backend,
        )

        self.receiver = FileReceiver(
            port=self.tcp_port,
            save_dir=self.save_dir,
            crypto=self.crypto,
            on_start=self._on_receive_start_backend,
            on_progress=self._on_receive_progress_backend,
            on_complete=self._on_receive_complete_backend,
            on_error=self._on_receive_error_backend,
        )

        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Start Networking Core in Background
        self.receiver.start()
        self.discovery.start()

        # Log system initialization
        self.log(
            "SYSTEM",
            f"AirDrop-Zero initialized. Listening on TCP {self.tcp_port}, UDP {self.discovery_port}",
        )
        self.log(
            "CRYPTO",
            f"AES-128-CBC + HMAC-SHA256 active. Mesh Key: {self.crypto.key.decode()[:16]}...",
        )
        self.log("STORAGE", f"Downloads folder: {self.save_dir}")

        # Start dynamic periodic peer list refresh loop (every 2s)
        self._schedule_peer_refresh()

    def dispatch_to_gui(self, callback):
        """Thread-safe dispatch of any function to the GUI event loop."""
        self.ui_queue.put(callback)

    def _schedule_ui_queue_poll(self):
        """Drain and execute pending callbacks on the main GUI thread."""
        while not self.ui_queue.empty():
            try:
                fn = self.ui_queue.get_nowait()
                fn()
            except Exception as e:
                logger.error(f"Error executing GUI dispatch: {e}")

        if self.is_running:
            self.after(30, self._schedule_ui_queue_poll)

    # ---------------------------------------------------------
    # UI Building
    # ---------------------------------------------------------
    def _build_top_bar(self):
        """Build top status bar with local node information and discovery indicator."""
        self.top_frame = ctk.CTkFrame(self, corner_radius=10, height=75)
        self.top_frame.pack(fill="x", padx=15, pady=(15, 10))
        self.top_frame.pack_propagate(False)

        # Title & Node Name
        title_box = ctk.CTkFrame(self.top_frame, fg_color="transparent")
        title_box.pack(side="left", padx=15, pady=10)

        ctk.CTkLabel(
            title_box,
            text="AirDrop-Zero",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#3B8ED0",
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_box,
            text=f"Node: {self.node_name}",
            font=ctk.CTkFont(size=13, weight="normal"),
            text_color="#DCE4EE",
        ).pack(anchor="w")

        # Network Info Badges
        badge_box = ctk.CTkFrame(self.top_frame, fg_color="transparent")
        badge_box.pack(side="left", padx=25, pady=10)

        ctk.CTkLabel(
            badge_box,
            text=f"IP: {self.local_ip}  |  TCP: {self.tcp_port}  |  UDP: {self.discovery_port}",
            font=ctk.CTkFont(size=12, family="Consolas"),
            text_color="#9BA3AF",
        ).pack(anchor="w")

        ctk.CTkLabel(
            badge_box,
            text=f"Passphrase: '{self.passphrase}' (AES Encrypted)",
            font=ctk.CTkFont(size=11),
            text_color="#10B981",
        ).pack(anchor="w")

        # Right-side Discovery Toggle & Indicator
        status_box = ctk.CTkFrame(self.top_frame, fg_color="transparent")
        status_box.pack(side="right", padx=15, pady=10)

        self.discovery_btn = ctk.CTkButton(
            status_box,
            text="● Discovery: Active",
            fg_color="#10B981",
            hover_color="#059669",
            text_color="#FFFFFF",
            font=ctk.CTkFont(size=12, weight="bold"),
            width=160,
            command=self._toggle_discovery,
        )
        self.discovery_btn.pack(side="right", padx=5)

    def _build_main_layout(self):
        """Build two-panel layout: Left for peers, Right for transfer & audit log."""
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # LEFT PANEL: Discovered Peers List
        self.left_panel = ctk.CTkFrame(self.main_container, width=320, corner_radius=10)
        self.left_panel.pack(side="left", fill="both", padx=(0, 10), pady=0)
        self.left_panel.pack_propagate(False)

        left_header = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        left_header.pack(fill="x", padx=15, pady=(15, 5))

        self.peers_title_label = ctk.CTkLabel(
            left_header,
            text="Nearby Peers (0)",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        self.peers_title_label.pack(side="left")

        ctk.CTkButton(
            left_header,
            text="⟳",
            width=30,
            height=28,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._manual_refresh_peers,
        ).pack(side="right")

        # Scrollable Peers List
        self.peers_scroll = ctk.CTkScrollableFrame(
            self.left_panel,
            fg_color="#1E1E24",
            corner_radius=8,
        )
        self.peers_scroll.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        # Placeholder label
        self.no_peers_label = ctk.CTkLabel(
            self.peers_scroll,
            text="Scanning local network on UDP 6000...\nLaunch another peer to connect.",
            font=ctk.CTkFont(size=12),
            text_color="#6B7280",
            justify="center",
        )
        self.no_peers_label.pack(pady=40)

        # RIGHT PANEL: Transfer controls & Audit Log
        self.right_panel = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.right_panel.pack(side="right", fill="both", expand=True, padx=0, pady=0)

        # Card 1: Transfer Area
        self.transfer_card = ctk.CTkFrame(self.right_panel, corner_radius=10)
        self.transfer_card.pack(fill="x", pady=(0, 10), padx=0)

        transfer_header = ctk.CTkFrame(self.transfer_card, fg_color="transparent")
        transfer_header.pack(fill="x", padx=15, pady=(15, 5))

        ctk.CTkLabel(
            transfer_header,
            text="Encrypted File Transfer",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(side="left")

        self.target_label = ctk.CTkLabel(
            transfer_header,
            text="Target: (Select a peer on the left)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#F59E0B",
        )
        self.target_label.pack(side="right")

        # File Selection Row
        file_row = ctk.CTkFrame(self.transfer_card, fg_color="transparent")
        file_row.pack(fill="x", padx=15, pady=8)

        self.browse_btn = ctk.CTkButton(
            file_row,
            text="Browse File...",
            width=120,
            command=self._browse_file,
        )
        self.browse_btn.pack(side="left", padx=(0, 10))

        self.file_info_label = ctk.CTkLabel(
            file_row,
            text="No file selected",
            font=ctk.CTkFont(size=13),
            text_color="#9BA3AF",
            anchor="w",
        )
        self.file_info_label.pack(side="left", fill="x", expand=True)

        # Action Buttons Row
        action_row = ctk.CTkFrame(self.transfer_card, fg_color="transparent")
        action_row.pack(fill="x", padx=15, pady=(4, 10))

        self.send_btn = ctk.CTkButton(
            action_row,
            text="Send Encrypted File",
            fg_color="#3B8ED0",
            hover_color="#1F6AA5",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=36,
            command=self._start_send_file,
        )
        self.send_btn.pack(side="left", padx=(0, 10))

        self.open_downloads_btn = ctk.CTkButton(
            action_row,
            text="Open Received Files",
            fg_color="#374151",
            hover_color="#4B5563",
            font=ctk.CTkFont(size=12),
            height=36,
            command=self._open_downloads_folder,
        )
        self.open_downloads_btn.pack(side="left")

        # Progress & Status Display
        progress_box = ctk.CTkFrame(self.transfer_card, fg_color="transparent")
        progress_box.pack(fill="x", padx=15, pady=(5, 15))

        self.status_label = ctk.CTkLabel(
            progress_box,
            text="Ready",
            font=ctk.CTkFont(size=12),
            text_color="#9BA3AF",
            anchor="w",
        )
        self.status_label.pack(fill="x", pady=(0, 4))

        self.progress_bar = ctk.CTkProgressBar(progress_box, height=12)
        self.progress_bar.set(0.0)
        self.progress_bar.pack(fill="x", pady=(0, 4))

        self.metrics_label = ctk.CTkLabel(
            progress_box,
            text="Speed: 0.0 KB/s  |  Transferred: 0 B  |  SHA-256: Idle",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color="#6B7280",
            anchor="w",
        )
        self.metrics_label.pack(fill="x")

        # Card 2: Activity & Audit Log
        self.log_card = ctk.CTkFrame(self.right_panel, corner_radius=10)
        self.log_card.pack(fill="both", expand=True, padx=0, pady=0)

        log_header = ctk.CTkFrame(self.log_card, fg_color="transparent")
        log_header.pack(fill="x", padx=15, pady=(10, 5))

        ctk.CTkLabel(
            log_header,
            text="Activity & Security Audit Log",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).pack(side="left")

        ctk.CTkButton(
            log_header,
            text="Clear Log",
            width=80,
            height=24,
            font=ctk.CTkFont(size=11),
            fg_color="#374151",
            hover_color="#4B5563",
            command=self._clear_log,
        ).pack(side="right")

        self.log_textbox = ctk.CTkTextbox(
            self.log_card,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word",
            corner_radius=8,
        )
        self.log_textbox.pack(fill="both", expand=True, padx=12, pady=(5, 12))
        self.log_textbox.configure(state="disabled")

    # ---------------------------------------------------------
    # Logging Helper
    # ---------------------------------------------------------
    def log(self, category: str, message: str):
        """Append timestamped message to the GUI audit log."""

        def _append():
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            entry = f"[{timestamp}] [{category.upper()}] {message}\n"
            self.log_textbox.configure(state="normal")
            self.log_textbox.insert("end", entry)
            self.log_textbox.see("end")
            self.log_textbox.configure(state="disabled")

        self.dispatch_to_gui(_append)

    # ---------------------------------------------------------
    # Discovery Management & Peer List
    # ---------------------------------------------------------
    def _toggle_discovery(self):
        """Toggle UDP discovery broadcast on or off."""
        if self.discovery_active:
            self.discovery.stop()
            self.discovery_active = False
            self.discovery_btn.configure(
                text="○ Discovery: Paused",
                fg_color="#EF4444",
                hover_color="#DC2626",
            )
            self.log("DISCOVERY", "UDP broadcast discovery paused.")
        else:
            self.discovery.start()
            self.discovery_active = True
            self.discovery_btn.configure(
                text="● Discovery: Active",
                fg_color="#10B981",
                hover_color="#059669",
            )
            self.log("DISCOVERY", f"UDP discovery resumed on port {self.discovery_port}.")

    def _schedule_peer_refresh(self):
        """Periodically refresh the peer list every 2000 ms."""
        self._refresh_peers_ui()
        if self.is_running:
            self.after(2000, self._schedule_peer_refresh)

    def _manual_refresh_peers(self):
        self._refresh_peers_ui()
        self.log("DISCOVERY", "Manually queried active peer list.")

    def _refresh_peers_ui(self):
        """Re-render the peer list from discovery cache."""
        peers = self.discovery.get_peers()
        self.peers_title_label.configure(text=f"Nearby Peers ({len(peers)})")

        for widget in self.peers_scroll.winfo_children():
            widget.destroy()

        if not peers:
            self.no_peers_label = ctk.CTkLabel(
                self.peers_scroll,
                text="Scanning local network on UDP 6000...\nLaunch another peer to connect.",
                font=ctk.CTkFont(size=12),
                text_color="#6B7280",
                justify="center",
            )
            self.no_peers_label.pack(pady=40)
            return

        now = time.time()
        for peer in peers:
            is_selected = (
                self.selected_peer
                and self.selected_peer.get("instance_id") == peer.get("instance_id")
            )

            card = ctk.CTkFrame(
                self.peers_scroll,
                fg_color="#2563EB" if is_selected else "#2A2B36",
                corner_radius=8,
                cursor="hand2",
            )
            card.pack(fill="x", pady=4, padx=2)

            def make_select(p=peer):
                return lambda e: self._select_peer(p)

            card.bind("<Button-1>", make_select())

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=10, pady=8)
            inner.bind("<Button-1>", make_select())

            name_lbl = ctk.CTkLabel(
                inner,
                text=f"👤 {peer['name']}",
                font=ctk.CTkFont(size=14, weight="bold"),
                anchor="w",
            )
            name_lbl.pack(fill="x")
            name_lbl.bind("<Button-1>", make_select())

            age = max(0, int(now - peer["last_seen"]))
            addr_lbl = ctk.CTkLabel(
                inner,
                text=f"{peer['ip']}:{peer['tcp_port']}  (seen {age}s ago)",
                font=ctk.CTkFont(size=11, family="Consolas"),
                text_color="#E5E7EB" if is_selected else "#9CA3AF",
                anchor="w",
            )
            addr_lbl.pack(fill="x")
            addr_lbl.bind("<Button-1>", make_select())

    def _select_peer(self, peer: dict):
        """Handle peer selection."""
        self.selected_peer = peer
        self.target_label.configure(
            text=f"Target: {peer['name']} ({peer['ip']}:{peer['tcp_port']})",
            text_color="#3B8ED0",
        )
        self.log(
            "SELECT",
            f"Selected target peer '{peer['name']}' at {peer['ip']}:{peer['tcp_port']}",
        )
        self._refresh_peers_ui()

    # ---------------------------------------------------------
    # File Sending Logic (Non-blocking)
    # ---------------------------------------------------------
    def _browse_file(self):
        """Open native file dialog to choose a file."""
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        self.selected_filepath = filepath
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)

        self.file_info_label.configure(
            text=f"{filename}  ({format_bytes(filesize)})",
            text_color="#FFFFFF",
        )
        self.log("FILE", f"Selected '{filename}' ({format_bytes(filesize)})")

    def _start_send_file(self):
        """Validate and dispatch file sending thread."""
        if not self.selected_peer:
            self.log("ERROR", "Please click on a discovered peer on the left first.")
            self.status_label.configure(
                text="Error: No target peer selected!", text_color="#EF4444"
            )
            return

        if not self.selected_filepath or not os.path.isfile(self.selected_filepath):
            self.log("ERROR", "Please select a valid file to send.")
            self.status_label.configure(
                text="Error: No file selected!", text_color="#EF4444"
            )
            return

        if self.is_sending:
            self.log("WARN", "A file transfer is already in progress.")
            return

        # Start sender in background thread
        self.is_sending = True
        self.send_btn.configure(state="disabled")
        self.browse_btn.configure(state="disabled")

        sender_thread = threading.Thread(
            target=self._send_file_worker,
            args=(self.selected_peer, self.selected_filepath),
            daemon=True,
        )
        sender_thread.start()

    def _send_file_worker(self, target_peer: dict, filepath: str):
        """Background thread worker for streaming file."""
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        ip = target_peer["ip"]
        port = target_peer["tcp_port"]
        peer_name = target_peer["name"]

        self.log(
            "SEND",
            f"Starting AES encrypted stream of '{filename}' ({format_bytes(filesize)}) to {peer_name} ({ip}:{port})",
        )

        def on_send_progress(fname, sent, total, speed):
            pct = sent / max(total, 1)

            def _update():
                self.progress_bar.set(pct)
                self.status_label.configure(
                    text=f"Sending '{filename}'... ({int(pct * 100)}%)",
                    text_color="#3B8ED0",
                )
                self.metrics_label.configure(
                    text=f"Speed: {format_bytes(int(speed))}/s  |  Transferred: {format_bytes(sent)} / {format_bytes(total)}  |  AES Encrypted"
                )

            self.dispatch_to_gui(_update)

        success, msg, file_hash = send_file(
            host=ip,
            port=port,
            filepath=filepath,
            sender_name=self.node_name,
            crypto=self.crypto,
            progress_callback=on_send_progress,
        )

        def _finish():
            self.is_sending = False
            self.send_btn.configure(state="normal")
            self.browse_btn.configure(state="normal")

            if success:
                self.progress_bar.set(1.0)
                self.status_label.configure(
                    text=f"[OK] Transfer Complete: '{filename}' successfully sent!",
                    text_color="#10B981",
                )
                self.metrics_label.configure(
                    text=f"SHA-256 Checksum: {file_hash}  [VERIFIED]"
                )
                self.log("SEND", f"[OK] Sent '{filename}' to {peer_name}. {msg}")
                self.log("CRYPTO", f"Sender SHA-256: {file_hash} [MATCH]")
            else:
                self.status_label.configure(
                    text=f"[FAIL] Transfer Failed: {msg}",
                    text_color="#EF4444",
                )
                self.log("ERROR", f"Send failure: {msg}")

        self.dispatch_to_gui(_finish)

    # ---------------------------------------------------------
    # File Receiving Callbacks (Backend to GUI Thread via Queue)
    # ---------------------------------------------------------
    def _on_receive_start_backend(
        self, filename: str, filesize: int, sender: str, is_encrypted: bool
    ):
        enc_badge = "AES Encrypted" if is_encrypted else "Plaintext"

        def _update():
            self.status_label.configure(
                text=f"Receiving '{filename}' from {sender} [{enc_badge}]...",
                text_color="#F59E0B",
            )
            self.progress_bar.set(0.0)
            self.log(
                "RECV",
                f"Inbound stream started for '{filename}' ({format_bytes(filesize)}) from {sender} [{enc_badge}]",
            )

        self.dispatch_to_gui(_update)

    def _on_receive_progress_backend(
        self, filename: str, received: int, total: int, speed: float
    ):
        pct = received / max(total, 1)

        def _update():
            self.progress_bar.set(pct)
            self.status_label.configure(
                text=f"Receiving '{filename}'... ({int(pct * 100)}%)",
                text_color="#F59E0B",
            )
            self.metrics_label.configure(
                text=f"Speed: {format_bytes(int(speed))}/s  |  Received: {format_bytes(received)} / {format_bytes(total)}"
            )

        self.dispatch_to_gui(_update)

    def _on_receive_complete_backend(
        self,
        filename: str,
        filepath: str,
        filesize: int,
        elapsed: float,
        sha256_hash: str,
    ):
        avg_speed = filesize / max(elapsed, 0.001)

        def _update():
            self.progress_bar.set(1.0)
            self.status_label.configure(
                text=f"[OK] Received & Verified '{filename}' ({format_bytes(filesize)})!",
                text_color="#10B981",
            )
            self.metrics_label.configure(
                text=f"SHA-256 Checksum: {sha256_hash}  [INTEGRITY MATCH]"
            )
            self.log(
                "RECV",
                f"[OK] Received '{filename}' in {elapsed:.2f}s ({format_bytes(int(avg_speed))}/s) -> {filepath}",
            )
            self.log(
                "CRYPTO",
                f"[OK] SHA-256 bit-for-bit integrity confirmed: {sha256_hash} [MATCH]",
            )

        self.dispatch_to_gui(_update)

    def _on_receive_error_backend(self, filename: str, error: str):
        def _update():
            self.status_label.configure(
                text=f"[FAIL] Error receiving '{filename}': {error}",
                text_color="#EF4444",
            )
            self.log("ERROR", f"Receive failed for '{filename}': {error}")

        self.dispatch_to_gui(_update)

    # ---------------------------------------------------------
    # Discovery Callbacks
    # ---------------------------------------------------------
    def _on_peer_found_backend(self, peer: dict):
        self.log(
            "DISCOVERY",
            f"Peer '{peer['name']}' detected at {peer['ip']}:{peer['tcp_port']}",
        )
        self.dispatch_to_gui(self._refresh_peers_ui)

    def _on_peer_lost_backend(self, peer: dict):
        self.log(
            "DISCOVERY",
            f"Peer '{peer['name']}' departed or timed out.",
        )
        self.dispatch_to_gui(self._refresh_peers_ui)

    # ---------------------------------------------------------
    # Action Helpers
    # ---------------------------------------------------------
    def _open_downloads_folder(self):
        """Open system file explorer to the downloads folder cross-platform."""
        os.makedirs(self.save_dir, exist_ok=True)
        current_os = platform.system()
        try:
            if current_os == "Windows":
                os.startfile(self.save_dir)
            elif current_os == "Darwin":
                subprocess.Popen(["open", self.save_dir])
            else:  # Linux and other Unix-like systems
                subprocess.Popen(["xdg-open", self.save_dir])
            self.log("STORAGE", f"Opened downloads folder: {self.save_dir}")
        except Exception as e:
            self.log("ERROR", f"Could not open folder '{self.save_dir}': {e}")

    def _clear_log(self):
        self.log_textbox.configure(state="normal")
        self.log_textbox.delete("1.0", "end")
        self.log_textbox.configure(state="disabled")

    def _on_close(self):
        """Gracefully terminate background network sockets upon window close."""
        self.is_running = False
        self.log("SYSTEM", "Shutting down background network threads...")
        try:
            self.discovery.stop()
        except Exception:
            pass
        try:
            self.receiver.stop()
        except Exception:
            pass
        self.destroy()


def main():
    parser = argparse.ArgumentParser(
        description="AirDrop-Zero: Modern Desktop GUI (Phase 3)"
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
        "--save-dir",
        "-s",
        type=str,
        default=None,
        help="Directory to save received files (default: ./downloads_<port>)",
    )

    args = parser.parse_args()

    app = AirDropGUI(
        name=args.name,
        tcp_port=args.port,
        discovery_port=args.discovery_port,
        passphrase=args.passphrase,
        save_dir=args.save_dir,
    )
    app.mainloop()


if __name__ == "__main__":
    main()
