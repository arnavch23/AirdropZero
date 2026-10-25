"""AirDrop-Zero: Transfer Module (Phase 2)
Handles TCP file chunk streaming with metadata framing, AES encryption (Fernet),
and SHA-256 checksum verification.
"""

import hashlib
import json
import logging
import os
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Callable, Optional, Tuple

from crypto_utils import MeshCrypto, calculate_file_sha256

logger = logging.getLogger("transfer")

CHUNK_SIZE = 64 * 1024  # 64 KB plaintext chunks
HEADER_PREFIX_FORMAT = "!I"  # 4 bytes unsigned int, big-endian
HEADER_PREFIX_SIZE = struct.calcsize(HEADER_PREFIX_FORMAT)


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable string (KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0 or unit == "TB":
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} B"


def render_progress_bar(
    transferred: int, total: int, speed: float, bar_length: int = 25
) -> str:
    """Render a text-based progress bar."""
    if total <= 0:
        percent = 100.0
        filled = bar_length
    else:
        percent = min(100.0, (transferred / total) * 100)
        filled = int(bar_length * transferred // total)

    bar = "#" * filled + "-" * (bar_length - filled)
    speed_str = f"{format_bytes(int(speed))}/s"
    return f"[{bar}] {percent:5.1f}% ({format_bytes(transferred)} / {format_bytes(total)}) {speed_str}"


def _get_unique_filepath(directory: str, filename: str) -> str:
    """Ensure safe filename and prevent collisions by appending counter if needed."""
    safe_name = os.path.basename(filename).strip().replace("\x00", "")
    if not safe_name:
        safe_name = "unnamed_file"

    target_path = os.path.join(directory, safe_name)
    if not os.path.exists(target_path):
        return target_path

    base, ext = os.path.splitext(safe_name)
    counter = 1
    while True:
        candidate = os.path.join(directory, f"{base} ({counter}){ext}")
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    """Read exactly length bytes from socket or raise EOFError."""
    chunks = []
    received = 0
    while received < length:
        chunk = sock.recv(min(length - received, CHUNK_SIZE))
        if not chunk:
            raise EOFError(
                f"Socket closed unexpectedly. Expected {length} bytes, got {received}"
            )
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


class FileReceiver:
    """TCP File Receiver that listens for incoming chunk streams, decrypts them,

    and validates SHA-256 bit-for-bit integrity.
    """

    def __init__(
        self,
        port: int,
        save_dir: str = "./received_files",
        crypto: Optional[MeshCrypto] = None,
        on_start: Optional[Callable[[str, int, str, bool], None]] = None,
        on_progress: Optional[Callable[[str, int, int, float], None]] = None,
        on_complete: Optional[Callable[[str, str, int, float, str], None]] = None,
        on_error: Optional[Callable[[str, str], None]] = None,
    ):
        self.port = port
        self.save_dir = save_dir
        self.crypto = crypto
        self.on_start = on_start
        self.on_progress = on_progress
        self.on_complete = on_complete
        self.on_error = on_error

        self._running = False
        self._server_sock: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None
        self._active_connections = set()
        self._lock = threading.Lock()

        os.makedirs(self.save_dir, exist_ok=True)

    def start(self) -> None:
        """Start listening for incoming TCP transfers."""
        if self._running:
            return

        self._running = True
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("", self.port))
        self._server_sock.listen(5)
        self._server_sock.settimeout(1.0)

        self._server_thread = threading.Thread(
            target=self._accept_loop, name="tcp-receiver-server", daemon=True
        )
        self._server_thread.start()
        logger.info(f"TCP FileReceiver listening on port {self.port}")

    def stop(self) -> None:
        """Stop TCP server and close sockets."""
        if not self._running:
            return

        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

        with self._lock:
            for conn in list(self._active_connections):
                try:
                    conn.close()
                except Exception:
                    pass

        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=1.5)

        logger.info("TCP FileReceiver stopped.")

    def _accept_loop(self) -> None:
        while self._running:
            try:
                if not self._server_sock:
                    break
                conn, addr = self._server_sock.accept()
                with self._lock:
                    self._active_connections.add(conn)

                worker = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                worker.start()
            except socket.timeout:
                continue
            except OSError:
                if not self._running:
                    break
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                if not self._running:
                    break

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        filepath: Optional[str] = None
        filename = "unknown"
        filesize = 0
        start_time = time.time()

        try:
            conn.settimeout(15.0)

            # 1. Read header prefix (length of JSON header)
            prefix_data = _recv_exact(conn, HEADER_PREFIX_SIZE)
            (header_len,) = struct.unpack(HEADER_PREFIX_FORMAT, prefix_data)

            # 2. Read and parse JSON header
            header_bytes = _recv_exact(conn, header_len)
            header = json.loads(header_bytes.decode("utf-8"))

            filename = header.get("filename", "unknown")
            filesize = int(header.get("filesize", 0))
            sender_name = header.get("sender", addr[0])
            is_encrypted = bool(header.get("encrypted", False))
            expected_sha256 = header.get("sha256")

            if is_encrypted and not self.crypto:
                raise ValueError(
                    "Transfer is AES-encrypted, but receiver has no crypto/passphrase configured!"
                )

            filepath = _get_unique_filepath(self.save_dir, filename)

            if self.on_start:
                self.on_start(filename, filesize, sender_name, is_encrypted)

            # 3. Read framed chunks, decrypt, and compute SHA-256
            bytes_written = 0
            last_speed_calc = time.time()
            bytes_since_last_calc = 0
            current_speed = 0.0
            hasher = hashlib.sha256()

            with open(filepath, "wb") as f:
                while True:
                    # Read 4-byte chunk length
                    chunk_len_data = _recv_exact(conn, HEADER_PREFIX_SIZE)
                    (chunk_len,) = struct.unpack(HEADER_PREFIX_FORMAT, chunk_len_data)

                    # EOF sentinel
                    if chunk_len == 0:
                        break

                    chunk_data = _recv_exact(conn, chunk_len)

                    # Decrypt chunk if encrypted
                    if is_encrypted and self.crypto:
                        plain_chunk = self.crypto.decrypt_chunk(chunk_data)
                    else:
                        plain_chunk = chunk_data

                    f.write(plain_chunk)
                    hasher.update(plain_chunk)

                    bytes_written += len(plain_chunk)
                    bytes_since_last_calc += len(plain_chunk)

                    now = time.time()
                    dt = now - last_speed_calc
                    if dt >= 0.25 or bytes_written == filesize:
                        current_speed = bytes_since_last_calc / max(dt, 0.001)
                        last_speed_calc = now
                        bytes_since_last_calc = 0

                        if self.on_progress:
                            self.on_progress(
                                filename, bytes_written, filesize, current_speed
                            )

                f.flush()
                os.fsync(f.fileno())

            # 4. Verify SHA-256 Checksum
            actual_sha256 = hasher.hexdigest()
            if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
                raise ValueError(
                    f"SHA-256 mismatch! Expected {expected_sha256}, got {actual_sha256}"
                )

            elapsed = max(time.time() - start_time, 0.001)

            # Notify receiver callback BEFORE sending ACK
            # This ensures Bob's state is completely updated before Alice gets the ACK
            if self.on_complete:
                self.on_complete(
                    filename, filepath, bytes_written, elapsed, actual_sha256
                )

            # 5. Send ACK response
            ack = json.dumps(
                {
                    "status": "OK",
                    "bytes_received": bytes_written,
                    "sha256": actual_sha256,
                }
            ).encode("utf-8")
            conn.sendall(struct.pack(HEADER_PREFIX_FORMAT, len(ack)) + ack)

        except Exception as e:
            logger.error(f"Transfer failed for {filename} from {addr}: {e}")
            if filepath and os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except Exception:
                    pass

            # Send error ACK if socket is still open
            try:
                err_msg = json.dumps({"status": "ERROR", "message": str(e)}).encode(
                    "utf-8"
                )
                conn.sendall(struct.pack(HEADER_PREFIX_FORMAT, len(err_msg)) + err_msg)
            except Exception:
                pass

            if self.on_error:
                self.on_error(filename, str(e))

        finally:
            with self._lock:
                self._active_connections.discard(conn)
            try:
                conn.close()
            except Exception:
                pass


def send_file(
    host: str,
    port: int,
    filepath: str,
    sender_name: str,
    crypto: Optional[MeshCrypto] = None,
    progress_callback: Optional[Callable[[str, int, int, float], None]] = None,
) -> Tuple[bool, str, Optional[str]]:
    """Send a file over TCP with optional AES chunk encryption and SHA-256 verification.

    Returns:
        (success: bool, message: str, sha256_hash: Optional[str])
    """
    path_obj = Path(filepath)
    if not path_obj.is_file():
        return False, f"File not found: {filepath}", None

    filename = path_obj.name
    filesize = path_obj.stat().st_size

    # Calculate SHA-256 before sending
    file_sha256 = calculate_file_sha256(str(path_obj))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15.0)

    try:
        sock.connect((host, port))

        # 1. Send Header
        header_data = json.dumps(
            {
                "filename": filename,
                "filesize": filesize,
                "sender": sender_name,
                "encrypted": bool(crypto is not None),
                "sha256": file_sha256,
            }
        ).encode("utf-8")

        prefix = struct.pack(HEADER_PREFIX_FORMAT, len(header_data))
        sock.sendall(prefix + header_data)

        # 2. Stream File in Framed (and optionally encrypted) Chunks
        start_time = time.time()
        bytes_sent = 0
        last_speed_calc = start_time
        bytes_since_last_calc = 0
        current_speed = 0.0

        with open(filepath, "rb") as f:
            while bytes_sent < filesize:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break

                # Encrypt chunk if crypto enabled
                if crypto:
                    payload = crypto.encrypt_chunk(chunk)
                else:
                    payload = chunk

                # Send 4-byte chunk length + payload
                chunk_prefix = struct.pack(HEADER_PREFIX_FORMAT, len(payload))
                sock.sendall(chunk_prefix + payload)

                bytes_sent += len(chunk)
                bytes_since_last_calc += len(chunk)

                now = time.time()
                dt = now - last_speed_calc
                if dt >= 0.25 or bytes_sent == filesize:
                    current_speed = bytes_since_last_calc / max(dt, 0.001)
                    last_speed_calc = now
                    bytes_since_last_calc = 0

                    if progress_callback:
                        progress_callback(filename, bytes_sent, filesize, current_speed)

        # 3. Send EOF Sentinel (0-length chunk)
        sock.sendall(struct.pack(HEADER_PREFIX_FORMAT, 0))

        # 4. Wait for ACK from receiver
        ack_prefix = _recv_exact(sock, HEADER_PREFIX_SIZE)
        (ack_len,) = struct.unpack(HEADER_PREFIX_FORMAT, ack_prefix)
        ack_bytes = _recv_exact(sock, ack_len)
        ack = json.loads(ack_bytes.decode("utf-8"))

        elapsed = max(time.time() - start_time, 0.001)
        if ack.get("status") == "OK":
            speed_overall = filesize / elapsed
            enc_tag = " (AES Encrypted)" if crypto else ""
            return (
                True,
                (
                    f"Sent {format_bytes(filesize)}{enc_tag} in {elapsed:.2f}s "
                    f"({format_bytes(int(speed_overall))}/s) | SHA-256: {file_sha256[:12]}..."
                ),
                file_sha256,
            )
        else:
            return (
                False,
                f"Receiver error: {ack.get('message', 'Unknown error')}",
                file_sha256,
            )

    except Exception as e:
        return False, f"Transfer failed: {e}", file_sha256

    finally:
        try:
            sock.close()
        except Exception:
            pass
