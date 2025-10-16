# 🔍 Python Port Scanner

A fast, simple, **asynchronous TCP port scanner** for learning and small-scale network discovery.  
Built with `asyncio` and `asyncio.open_connection` — designed for education, automation practice, and SOC lab use.

---

## ⚡ Quick pitch
Scan a host or CIDR range quickly and concurrently. Good for learning how TCP port probing works, practising network reconnaissance in authorized environments, and integrating into security tooling pipelines.

---

## ✨ Features
- Asynchronous scanning for high performance (uses `asyncio`).
- Scan single IPs, hostnames, or CIDR ranges.
- Range and list port scanning (e.g., `1-1024` or `22,80,443`).
- Adjustable concurrency and timeout.
- Optional CSV or plain-text output.
- Clean, minimal dependency list.

---

## 🔧 Requirements
- Python 3.10+ recommended
- Uses only standard library (no external deps required) — optional `rich` for nicer output

Install (optional `rich`):
```bash
python -m pip install rich
💾 Installation
Clone and run:

bash
Copy code
git clone https://github.com/helloashishghimire/python-port-scanner.git
cd python-port-scanner
# run directly with python
python scanner.py --help
🚀 Usage examples
Scan common ports on a single host:

bash
Copy code
python scanner.py -t 192.168.1.10 -p 22,80,443
Scan first 1024 ports on a host:

bash
Copy code
python scanner.py -t example.com -p 1-1024 -T 0.5
Scan a CIDR range (example: 192.168.1.0/28) with concurrency:

bash
Copy code
python scanner.py -t 192.168.1.0/28 -p 22,80 -c 200 -o results.csv
Show verbose output:

bash
Copy code
python scanner.py -t 10.0.0.5 -p 22,80,443 -v
⚙️ CLI options
lua
Copy code
-t, --target      Target IP / hostname / CIDR (required)
-p, --ports       Ports: comma-separated and/or ranges (e.g., 22,80,1000-1010)
-c, --concurrency Max concurrent connection tasks (default: 100)
-T, --timeout     Socket timeout in seconds (default: 1.0)
-o, --output      Save results to file (csv or txt by extension)
-v, --verbose     Verbose output (shows connection attempts)
--json            Output results as JSON
-h, --help        Show help message
🔎 Example output
pgsql
Copy code
[+] 192.168.1.10:22 OPEN
[+] 192.168.1.10:80 OPEN
[-] 192.168.1.10:443 CLOSED
Scan complete: 3 ports scanned on 1 target
Saved results to results.csv
🧩 Example (core) implementation idea
The repository includes an async scanner; below is the core pattern used:

python
Copy code
import asyncio

async def check_port(host: str, port: int, timeout=1.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def scan_host(host: str, ports: list[int], concurrency: int = 100):
    sem = asyncio.Semaphore(concurrency)
    async def worker(port):
        async with sem:
            open_ = await check_port(host, port)
            if open_:
                print(f"[+] {host}:{port} OPEN")
    await asyncio.gather(*(worker(p) for p in ports))
🛡️ Disclaimer & safe use
This tool is for educational purposes only.
Only scan systems you own or have explicit permission to test. Unauthorized scanning can be illegal and unethical. By using this tool you accept responsibility for your actions.

🧪 Tests & validation
Manual testing recommended on local lab networks (e.g., VMs or isolated subnets).

Example: spin up a small VM with SSH enabled (port 22) and test scanning against it.

🛠️ Development & contribution
Contributions welcome! Suggested workflow:

Fork the repo

Create a feature branch: git checkout -b feat/async-timeout

Commit & open a PR with description and test cases

Ideas:

Add UDP scanning (careful: requires privileged sockets / raw sockets)

Add service banner grabbing for open ports

Integrate rich for better terminal UX

Add a web UI for quick scans in a lab environment

📜 License
MIT License — see LICENSE for details.

📫 Contact / Author
Ashish Ghimire
Master’s in Cybersecurity • Student SOC Analyst
LinkedIn • X
