"""Integration test for AirDropGUI (Phase 3).
Verifies that the GUI can receive encrypted transfers and update its audit log & progress bar.
"""

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

from crypto_utils import DEFAULT_PASSPHRASE, MeshCrypto, calculate_file_sha256
from gui import AirDropGUI
from transfer import send_file


def test_gui():
    print("Testing AirDropGUI integration...")
    test_dir = "./test_gui_env"
    os.makedirs(test_dir, exist_ok=True)
    test_file = os.path.join(test_dir, "gui_payload.txt")
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("AirDrop-Zero Phase 3 GUI Integration Test Data\n" * 200)

    original_sha256 = calculate_file_sha256(test_file)

    # Launch GUI instance for Bob
    app_bob = AirDropGUI(
        name="BobGUI",
        tcp_port=5012,
        discovery_port=6012,
        save_dir=os.path.join(test_dir, "downloads"),
    )
    app_bob.update()

    # Create sender crypto for Alice
    crypto_alice = MeshCrypto(DEFAULT_PASSPHRASE)

    # Alice sends file to Bob's GUI
    print("Sending encrypted file from Alice -> Bob's GUI...")
    success, msg, file_hash = send_file(
        host="127.0.0.1",
        port=5012,
        filepath=test_file,
        sender_name="Alice",
        crypto=crypto_alice,
    )

    assert success, f"Transfer to GUI failed: {msg}"
    print("Transfer succeeded:", msg)

    # Drain UI queue and process GUI events
    for _ in range(20):
        time.sleep(0.05)
        app_bob._schedule_ui_queue_poll()
        app_bob.update()

    # Verify log content in GUI textbox
    log_content = app_bob.log_textbox.get("1.0", "end")
    print("\nGUI Audit Log Content:\n" + "-" * 40)
    print(log_content.strip())
    print("-" * 40)

    assert "Inbound stream started" in log_content, "Missing inbound stream log!"
    assert "SHA-256 bit-for-bit integrity confirmed" in log_content, "Missing integrity log!"
    print("✓ Audit log verification passed!")

    # Verify received file on disk
    received_file = os.path.join(test_dir, "downloads", "gui_payload.txt")
    assert os.path.exists(received_file), "Received file missing!"
    decrypted_sha256 = calculate_file_sha256(received_file)
    assert decrypted_sha256 == original_sha256, "SHA-256 hash mismatch!"
    print("✓ Reconstructed file SHA-256 integrity match confirmed!")

    # Clean close
    app_bob._on_close()
    shutil.rmtree(test_dir, ignore_errors=True)
    print("\n[PASS] AirDropGUI integration test PASSED completely!")


if __name__ == "__main__":
    test_gui()
