# AirDrop-Zero 🚀
> Cross-platform, air-gapped, zero-cloud peer-to-peer (P2P) encrypted file transfer mesh over local networks.

AirDrop-Zero enables instant, secure file discovery and chunked streaming between devices across different operating systems (Windows, macOS, Linux) without requiring internet connectivity, third-party cloud servers, or Bluetooth pairing.


## 🛠️ Features & Architecture
- **Zero-Cloud / Air-Gapped**: Functions entirely on local subnets or mobile hotspots (even with cellular data disabled).
- **Automated Peer Discovery**: UDP broadcast beacons over port `6000` allow nearby nodes to discover each other dynamically.
- **High-Speed Chunk Streaming**: Dedicated TCP socket channels transmit chunked binary payloads with flow control.
- **End-to-End Security**: Payload encryption using symmetric AES-128-CBC via Fernet cryptography.
- **Bit-for-Bit Integrity Verification**: Real-time SHA-256 checksum computation and validation upon completion.
- **Cross-Platform Modern UI**: Clean dark-mode interface built with CustomTkinter.

---

## 📋 Prerequisites
- **Python 3.10+** installed on all participating machines.
- All devices connected to the **same local Wi-Fi or mobile hotspot**.

---

## 📥 1. Clone the Repository
On each computer, open a terminal and run:
```bash
git clone [https://github.com/arnavch23/AirdropZero.git](https://github.com/arnavch23/AirdropZero.git)
cd AirdropZero
💻 2. Setup & Execution
🪟 Windows Setup
Open Command Prompt or PowerShell inside the AirdropZero directory:

Install dependencies:

DOS
py -m pip install -r requirements.txt
(Or pip install -r requirements.txt if python is added to your PATH)

Launch the application:

DOS
py gui.py --name "Windows-PC"

🍎 macOS & Linux Setup
Open Terminal inside the AirdropZero directory:

Create and activate a virtual environment (recommended):

Bash
python3 -m venv venv
source venv/bin/activate
Install dependencies:

Bash
pip install -r requirements.txt
Launch the application:

Bash
python3 gui.py --name "MacBook"

🧪 3. How to Test
A. Single Machine Local Testing (Simulation)
Open two separate terminal windows on your laptop to simulate two peers:

Terminal 1 (Alice):

Bash
python gui.py --name Alice --port 5001
Terminal 2 (Bob):

Bash
python gui.py --name Bob --port 5002
B. Multi-Laptop Offline Demo (Real World Demonstration)
Turn on a mobile hotspot on a smartphone.

Turn Mobile Data OFF on the phone to prove complete offline functionality.

Connect Laptop A and Laptop B to the hotspot.

Run the app on both machines:

Laptop A: python gui.py --name Laptop-A

Laptop B: python gui.py --name Laptop-B(Port defaults to 5001 automatically when on separate physical IPs).

Select the target device from Nearby Peers, click Browse File, and press Send Encrypted File.

📂 Project Structure
Plaintext
AirdropZero/
├── gui.py                  # CustomTkinter modern dark-mode GUI
├── discovery.py            # UDP beacon broadcasting & peer listener (Port 6000)
├── transfer.py             # TCP streaming socket engine (Sender & Receiver)
├── crypto_utils.py         # AES encryption & SHA-256 checksum utilities
├── requirements.txt        # Runtime dependencies
└── README.md               # Documentation & setup guide