# 🔍 Python Port Scanner

> A fast, simple, **threaded TCP port scanner** for learning, ethical hacking labs, and small-scale network discovery.  
> Built using Python’s `socket` and `concurrent.futures` — no external dependencies.

---

## ⚡ Overview
This lightweight scanner helps you understand how TCP connections and port probing work.  
Perfect for **students**, **SOC analysts**, and **cybersecurity enthusiasts** experimenting in controlled environments.

---

## ✨ Features
- 🧠 **Multithreaded** scanning for high performance  
- 🌐 Scan **single hosts** or **CIDR ranges** (IPv4)  
- ⚙️ Supports port **ranges** (`1-1024`) and **lists** (`22,80,443`)  
- 🕒 Configurable **timeout** and **thread count**  
- 🧾 Optional **banner grabbing** for open ports  
- 🧰 Clean output, no dependencies, pure Python  

---

## 🔧 Requirements
- **Python 3.7+** (Recommended: 3.10+)
- No external packages required

Install (optional `rich` for colorful output):
```bash
pip install rich
💾 Installation
Clone this repository:

bash
Copy code
git clone https://github.com/helloashishghimire/python-port-scanner.git
cd python-port-scanner
Run help:

bash
Copy code
python3 simple_port_scanner.py --help
🚀 Usage Examples
Scan specific ports
bash
Copy code
python3 simple_port_scanner.py --host example.com --ports 22,80,443
Scan a full range
bash
Copy code
python3 simple_port_scanner.py -H 192.168.1.10 -p 1-1024
CIDR range with banners
bash
Copy code
python3 simple_port_scanner.py --cidr 192.168.1.0/28 --ports 22,80 --banner
Custom threads and timeout
bash
Copy code
python3 simple_port_scanner.py -H 10.0.0.5 -p 22,80,443 -w 200 --timeout 0.8
⚙️ CLI Options
Flag	Description
-H, --host	Hostname or IPv4 address to scan
-C, --cidr	CIDR range (e.g., 192.168.1.0/28)
-p, --ports	Comma-separated or ranged ports (required)
-w, --workers	Number of concurrent threads (default: 100)
--banner	Attempt simple banner grabbing
--timeout	Socket timeout (default: 1.0s)
-h, --help	Show help message

🧠 How It Works
Parses ports → list & range support

Expands targets → resolves host or CIDR range

Threads → launches parallel connections

Connects via socket → checks TCP port status

Prints results → shows open ports and banners

🔎 Example Output
sql
Copy code
============================================================
Scan results for 192.168.1.10 — 2 open port(s)
------------------------------------------------------------
Port 22/tcp — OPEN — Banner: SSH-2.0-OpenSSH_8.6p1 Ubuntu-4ubuntu0.3
Port 80/tcp — OPEN — Banner: HTTP/1.1 200 OK
🧪 Test It Safely
Try scanning your local machine or a lab VM:

bash
Copy code
python3 simple_port_scanner.py -H 127.0.0.1 -p 22,80,443
✅ Works great for practice, SOC labs, and home-lab simulations.

🛡️ Disclaimer
This tool is for educational and authorized use only.
Do not scan systems without explicit permission.
Unauthorized scanning is illegal and unethical.

💡 Future Ideas
CSV / JSON output

AsyncIO rewrite for ultra-fast scanning

Service fingerprinting

Web dashboard for visualization

📜 License
MIT License — Free to modify and distribute.

👤 Author
Ashish Ghimire
🎓 Cybersecurity Student | 💻 SOC Analyst | 🧠 Python Developer
🔗 GitHub Profile →

⭐ If you like this project, give it a star!
Made with ❤️ in Python.

yaml
Copy code

---

This version:
- Looks **amazing** in GitHub’s dark & light mode  
- Includes clean emoji headings 🧠 ⚙️ 🚀  
- Reads like a real open-source project (not a homework file)  
- Has a professional bottom section with author + license  

Would you like me to make it show **GitHub-style badges** (like “Python 3.10+”, “MIT License”, “Contributions Welcome”)?  
That makes it look even more professional at the top of your repo.






Voice chat ended



