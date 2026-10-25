"""Simulates two terminals interacting via app.py CLI with Phase 2 AES encryption."""

import os
import subprocess
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def run_demo():
    print("=" * 65)
    print("  SIMULATING TWO TERMINALS RUNNING AIRDROP-ZERO PHASE 2  ")
    print("        (AES-128-CBC + HMAC-SHA256 MESH ENCRYPTION)     ")
    print("=" * 65)

    test_file = "confidential_document.txt"
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("Classified Content: AirDrop-Zero Phase 2 AES Encrypted Transmission!\n" * 400)
    print(f"Created test payload '{test_file}' ({os.path.getsize(test_file)} bytes)")

    # Launch Instance 1 (Alice on Port 5001) with shared passphrase
    p1 = subprocess.Popen(
        [
            sys.executable,
            "app.py",
            "--name",
            "Alice",
            "--port",
            "5001",
            "--passphrase",
            "secure-mesh-2026",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    # Launch Instance 2 (Bob on Port 5002) with the same passphrase
    p2 = subprocess.Popen(
        [
            sys.executable,
            "app.py",
            "--name",
            "Bob",
            "--port",
            "5002",
            "--passphrase",
            "secure-mesh-2026",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        print("\nWaiting for mutual broadcast discovery on UDP 6000...")
        time.sleep(2.5)

        print("\n>>> [TERMINAL 1: ALICE] typing 'peers'...")
        p1.stdin.write("peers\n")
        p1.stdin.flush()
        time.sleep(1.0)

        print(f"\n>>> [TERMINAL 1: ALICE] typing 'send Bob {test_file}'...")
        p1.stdin.write(f"send Bob {test_file}\n")
        p1.stdin.flush()
        time.sleep(2.0)

        print("\n>>> Shutting down both terminals...")
        p1.stdin.write("exit\n")
        p1.stdin.flush()
        p2.stdin.write("exit\n")
        p2.stdin.flush()

        out1, _ = p1.communicate(timeout=5)
        out2, _ = p2.communicate(timeout=5)

        print("\n" + "-" * 30 + " TERMINAL 1 (ALICE) OUTPUT " + "-" * 30)
        print(out1)
        print("-" * 30 + " TERMINAL 2 (BOB) OUTPUT " + "-" * 30)
        print(out2)

        # Check Bob's downloads directory
        received_path = os.path.join("./downloads_5002", test_file)
        if os.path.exists(received_path):
            with open(test_file, "rb") as f1, open(received_path, "rb") as f2:
                orig_bytes = f1.read()
                recv_bytes = f2.read()
                assert orig_bytes == recv_bytes, "Content mismatch!"
            print(f"\n[SUCCESS] File verified bit-for-bit in Bob's directory: {received_path}")
            print(f"Size: {len(recv_bytes)} bytes | Decrypted successfully!")

    finally:
        if p1.poll() is None:
            p1.kill()
        if p2.poll() is None:
            p2.kill()
        if os.path.exists(test_file):
            os.remove(test_file)
        # Clean downloads
        for d in ["./downloads_5001", "./downloads_5002"]:
            if os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    import shutil
    run_demo()
