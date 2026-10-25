"""AirDrop-Zero: Discovery Module (Phase 1)
Handles periodic UDP broadcast discovery with cross-platform socket options.
"""

import json
import logging
import socket
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("discovery")


class PeerDiscovery:
    """Manages UDP broadcast discovery of peers on the local network."""

    def __init__(
        self,
        name: str,
        tcp_port: int,
        broadcast_port: int = 6000,
        interval: float = 2.0,
        timeout: float = 6.0,
        on_peer_found: Optional[Callable[[dict], None]] = None,
        on_peer_lost: Optional[Callable[[dict], None]] = None,
    ):
        self.name = name
        self.tcp_port = tcp_port
        self.broadcast_port = broadcast_port
        self.interval = interval
        self.timeout = timeout
        self.instance_id = str(uuid.uuid4())

        self.on_peer_found = on_peer_found
        self.on_peer_lost = on_peer_lost

        self._peers: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._running = False

        self._recv_sock: Optional[socket.socket] = None
        self._send_sock: Optional[socket.socket] = None
        self._listener_thread: Optional[threading.Thread] = None
        self._broadcaster_thread: Optional[threading.Thread] = None

    def _setup_receiver_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Cross-platform reuse options
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass

        # Windows-specific fix for ICMP Port Unreachable (WSAECONNRESET 10054) on UDP
        if hasattr(socket, "SIO_UDP_CONNRESET"):
            try:
                sock.ioctl(socket.SIO_UDP_CONNRESET, False)
            except Exception:
                pass

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1.0)
        sock.bind(("", self.broadcast_port))
        return sock

    def _setup_sender_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return sock

    def start(self) -> None:
        """Start UDP broadcast transmitter and listener threads."""
        if self._running:
            return

        self._running = True
        self._recv_sock = self._setup_receiver_socket()
        self._send_sock = self._setup_sender_socket()

        self._listener_thread = threading.Thread(
            target=self._listen_loop, name="discovery-listener", daemon=True
        )
        self._broadcaster_thread = threading.Thread(
            target=self._broadcast_loop, name="discovery-broadcaster", daemon=True
        )

        self._listener_thread.start()
        self._broadcaster_thread.start()
        logger.info(
            f"Discovery started for '{self.name}' on UDP port {self.broadcast_port}"
        )

    def stop(self) -> None:
        """Stop discovery threads and broadcast departure notice."""
        if not self._running:
            return

        self._running = False

        # Broadcast departure notice so peers drop us immediately
        try:
            bye_payload = json.dumps(
                {"type": "DISCOVER_BYE", "instance_id": self.instance_id}
            ).encode("utf-8")
            if self._send_sock:
                self._send_sock.sendto(bye_payload, ("<broadcast>", self.broadcast_port))
                self._send_sock.sendto(bye_payload, ("127.0.0.1", self.broadcast_port))
        except Exception:
            pass

        if self._recv_sock:
            try:
                self._recv_sock.close()
            except Exception:
                pass

        if self._send_sock:
            try:
                self._send_sock.close()
            except Exception:
                pass

        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=1.5)
        if self._broadcaster_thread and self._broadcaster_thread.is_alive():
            self._broadcaster_thread.join(timeout=1.5)

        logger.info("Discovery stopped.")

    def _listen_loop(self) -> None:
        while self._running:
            try:
                if not self._recv_sock:
                    break
                data, addr = self._recv_sock.recvfrom(4096)
                msg = json.loads(data.decode("utf-8"))

                instance_id = msg.get("instance_id")
                # Ignore our own broadcast
                if not instance_id or instance_id == self.instance_id:
                    continue

                msg_type = msg.get("type")

                if msg_type == "DISCOVER_HEARTBEAT":
                    sender_ip = addr[0]
                    tcp_port = int(msg.get("tcp_port", 0))
                    peer_name = msg.get("name", "Unknown")

                    peer_info = {
                        "instance_id": instance_id,
                        "name": peer_name,
                        "ip": sender_ip,
                        "tcp_port": tcp_port,
                        "last_seen": time.time(),
                    }

                    new_peer = False
                    with self._lock:
                        if instance_id not in self._peers:
                            new_peer = True
                        self._peers[instance_id] = peer_info

                    if new_peer and self.on_peer_found:
                        self.on_peer_found(peer_info)

                elif msg_type == "DISCOVER_BYE":
                    removed_peer = None
                    with self._lock:
                        if instance_id in self._peers:
                            removed_peer = self._peers.pop(instance_id)

                    if removed_peer and self.on_peer_lost:
                        self.on_peer_lost(removed_peer)

            except socket.timeout:
                continue
            except OSError as e:
                # On Windows, ignore WSAECONNRESET (10054)
                if getattr(e, "winerror", None) == 10054:
                    continue
                if not self._running:
                    break
            except Exception:
                if not self._running:
                    break

    def _broadcast_loop(self) -> None:
        while self._running:
            payload = json.dumps(
                {
                    "type": "DISCOVER_HEARTBEAT",
                    "instance_id": self.instance_id,
                    "name": self.name,
                    "tcp_port": self.tcp_port,
                    "timestamp": time.time(),
                }
            ).encode("utf-8")

            # Broadcast on local subnet & loopback
            for target_ip in ["<broadcast>", "127.0.0.1"]:
                try:
                    if self._send_sock:
                        self._send_sock.sendto(payload, (target_ip, self.broadcast_port))
                except Exception:
                    pass

            # Check for peer timeouts
            now = time.time()
            expired_peers = []
            with self._lock:
                for pid, pinfo in list(self._peers.items()):
                    if now - pinfo["last_seen"] > self.timeout:
                        expired_peers.append(self._peers.pop(pid))

            for peer in expired_peers:
                if self.on_peer_lost:
                    self.on_peer_lost(peer)

            # Sleep in short increments for responsive shutdown
            slept = 0.0
            while self._running and slept < self.interval:
                time.sleep(0.1)
                slept += 0.1

    def get_peers(self) -> List[dict]:
        """Return a copy of the current list of discovered peers."""
        with self._lock:
            # Sort by name for consistent UI display
            return sorted(
                list(self._peers.values()),
                key=lambda x: (x["name"].lower(), x["ip"]),
            )
