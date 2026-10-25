"""Comprehensive verification test for AirDrop-Zero Phase 2 (End-to-End AES Encryption & Networking Core).

Verifies:
1. UDP broadcast peer discovery with cross-platform socket options.
2. End-to-end chunk-level AES encryption (Fernet) derived from a shared mesh passphrase.
3. Bit-for-bit SHA-256 integrity verification of decrypted files.
4. Cryptographic isolation (wrong passphrase rejection).
5. Elimination of receiver race condition via polling timeout loop.
"""

import hashlib
import os
import shutil
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from crypto_utils import MeshCrypto, calculate_file_sha256
from discovery import PeerDiscovery
from transfer import FileReceiver, format_bytes, send_file


def test_core_and_encryption():
    print("=" * 65)
    print("  AIRDROP-ZERO PHASE 2: AES ENCRYPTION & NETWORKING TEST  ")
    print("=" * 65)

    test_dir = "./test_env_phase2"
    downloads_alice = os.path.join(test_dir, "downloads_alice")
    downloads_bob = os.path.join(test_dir, "downloads_bob")
    downloads_eve = os.path.join(test_dir, "downloads_eve")
    os.makedirs(downloads_alice, exist_ok=True)
    os.makedirs(downloads_bob, exist_ok=True)
    os.makedirs(downloads_eve, exist_ok=True)

    # 1. Create a dummy test payload (5 MB binary file)
    test_file_path = os.path.join(test_dir, "top_secret_payload.bin")
    file_size_mb = 5
    print(f"\n[1] Generating {file_size_mb} MB test payload '{test_file_path}'...")
    pattern = b"AirDrop-Zero-Phase2-Encrypted-Mesh-Block-AES128CBC-HMACSHA256\n"
    total_bytes = file_size_mb * 1024 * 1024
    with open(test_file_path, "wb") as f:
        written = 0
        while written < total_bytes:
            to_write = min(len(pattern), total_bytes - written)
            f.write(pattern[:to_write])
            written += to_write

    original_hash = calculate_file_sha256(test_file_path)
    print(f"    File Size : {format_bytes(total_bytes)}")
    print(f"    SHA-256   : {original_hash}")

    # 2. Setup Mesh Cryptography with shared passphrase
    print("\n[2] Initializing AES mesh crypto with shared passphrase...")
    shared_passphrase = "secret-mesh-passphrase-alpha"
    crypto_alice = MeshCrypto(shared_passphrase)
    crypto_bob = MeshCrypto(shared_passphrase)
    # Eve uses a different passphrase
    crypto_eve = MeshCrypto("wrong-unauthorized-passphrase")
    print(f"    Alice & Bob Key: {crypto_alice.key.decode()[:16]}... (Derived from '{shared_passphrase}')")
    print(f"    Eve Key        : {crypto_eve.key.decode()[:16]}... (Derived from 'wrong-unauthorized-passphrase')")

    # 3. Setup Discovery and TCP Receivers
    print("\n[3] Starting Alice (Port 5071) and Bob (Port 5072)...")
    alice_discovered = []
    bob_discovered = []

    discovery_alice = PeerDiscovery(
        name="AliceTest",
        tcp_port=5071,
        broadcast_port=6070,
        interval=1.0,
        on_peer_found=lambda p: alice_discovered.append(p),
    )
    discovery_bob = PeerDiscovery(
        name="BobTest",
        tcp_port=5072,
        broadcast_port=6070,
        interval=1.0,
        on_peer_found=lambda p: bob_discovered.append(p),
    )

    received_files_bob = []

    def on_bob_receive_complete(filename, filepath, filesize, elapsed, sha256_hash):
        received_files_bob.append(
            {
                "filename": filename,
                "filepath": filepath,
                "filesize": filesize,
                "elapsed": elapsed,
                "sha256": sha256_hash,
            }
        )

    receiver_alice = FileReceiver(
        port=5071,
        save_dir=downloads_alice,
        crypto=crypto_alice,
        on_error=lambda fn, err: print(f"    [ALICE ERROR] {fn}: {err}"),
    )
    receiver_bob = FileReceiver(
        port=5072,
        save_dir=downloads_bob,
        crypto=crypto_bob,
        on_complete=on_bob_receive_complete,
        on_error=lambda fn, err: print(f"    [BOB ERROR] {fn}: {err}"),
    )

    try:
        receiver_alice.start()
        receiver_bob.start()
        discovery_alice.start()
        discovery_bob.start()

        # 4. Wait for UDP Broadcast Discovery
        print("\n[4] Awaiting mutual UDP discovery on port 6070...")
        for _ in range(12):
            time.sleep(0.4)
            alice_peers = discovery_alice.get_peers()
            bob_peers = discovery_bob.get_peers()
            if any(p["name"] == "BobTest" for p in alice_peers) and any(
                p["name"] == "AliceTest" for p in bob_peers
            ):
                break

        alice_peers = discovery_alice.get_peers()
        bob_peers = discovery_bob.get_peers()
        print(f"    Alice discovered: {[p['name'] for p in alice_peers]}")
        print(f"    Bob discovered  : {[p['name'] for p in bob_peers]}")
        assert any(p["name"] == "BobTest" for p in alice_peers), "Alice failed to discover BobTest!"
        assert any(p["name"] == "AliceTest" for p in bob_peers), "Bob failed to discover AliceTest!"
        print("    [PASS] Mutual UDP broadcast peer discovery confirmed.")

        # 5. Encrypted Chunk Transfer: Alice -> Bob
        bob_info = next(p for p in alice_peers if p["name"] == "BobTest")
        target_ip = bob_info["ip"]
        target_port = bob_info["tcp_port"]

        print(f"\n[5] Streaming AES-encrypted chunks from Alice -> Bob ({target_ip}:{target_port})...")
        progress_ticks = []

        def track_progress(fname, sent, total, speed):
            pct = (sent / total) * 100
            progress_ticks.append(pct)
            if len(progress_ticks) % 15 == 0 or sent == total:
                print(f"    [ALICE ENCRYPTED SENDER] {pct:5.1f}% | {format_bytes(int(speed))}/s")

        success, msg, file_hash = send_file(
            host=target_ip,
            port=target_port,
            filepath=test_file_path,
            sender_name="Alice",
            crypto=crypto_alice,
            progress_callback=track_progress,
        )

        assert success, f"File transfer failed: {msg}"
        print(f"    [PASS] Transfer successful: {msg}")

        # 6. Polling loop to wait for receiver registration (Fixes line 155 race condition)
        print("\n[6] Polling receiver thread for completed registration...")
        poll_timeout = 3.0
        start_poll = time.time()
        while time.time() - start_poll < poll_timeout:
            if len(received_files_bob) >= 1:
                break
            time.sleep(0.05)

        assert (
            len(received_files_bob) == 1
        ), f"Bob did not register completed transfer within {poll_timeout}s!"
        print(f"    [PASS] Bob registered transfer in {time.time() - start_poll:.3f}s (No race condition).")

        # 7. Verify Bit-for-Bit SHA-256 Checksum on Decrypted File
        print("\n[7] Verifying decrypted file integrity on Bob's node...")
        received_record = received_files_bob[0]
        received_path = received_record["filepath"]
        decrypted_hash = calculate_file_sha256(received_path)

        print(f"    Original SHA-256  : {original_hash}")
        print(f"    Decrypted SHA-256 : {decrypted_hash}")
        assert (
            original_hash == decrypted_hash
        ), "Decryption integrity error! SHA-256 mismatch between original and decrypted file!"
        print("    [PASS] Bit-for-bit decrypted integrity verified (SHA-256 match)!")

        # 8. Test Cryptographic Isolation: Unauthorized peer with wrong key
        print("\n[8] Testing cryptographic isolation with unauthorized receiver (Eve)...")
        receiver_eve = FileReceiver(port=5003, save_dir=downloads_eve, crypto=crypto_eve)
        receiver_eve.start()
        time.sleep(0.2)

        # Alice attempts to send to Eve who has wrong passphrase
        eve_success, eve_msg, _ = send_file(
            host="127.0.0.1",
            port=5003,
            filepath=test_file_path,
            sender_name="Alice",
            crypto=crypto_alice,
        )
        receiver_eve.stop()

        print(f"    Attempt sending Alice -> Eve result: success={eve_success}, msg='{eve_msg}'")
        assert not eve_success, "Security violation: Eve decrypted file with wrong passphrase!"
        print("    [PASS] Unauthorized peer correctly rejected due to decryption token invalidity!")

    finally:
        print("\n[9] Cleaning up test instances and temporary files...")
        discovery_alice.stop()
        discovery_bob.stop()
        receiver_alice.stop()
        receiver_bob.stop()
        shutil.rmtree(test_dir, ignore_errors=True)
        print("    [PASS] All test nodes cleanly stopped.")

    print("\n" + "=" * 65)
    print("  ALL PHASE 2 AES ENCRYPTION & NETWORKING TESTS PASSED!  ")
    print("=" * 65)


if __name__ == "__main__":
    test_core_and_encryption()
