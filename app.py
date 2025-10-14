import asyncio
import socket
import json
import time
from typing import List, Tuple, Dict, Any, Optional
import subprocess

# ---------------- Basic Async TCP Scanner ----------------
async def check_port(host: str, port: int, connect_timeout: float, read_timeout: float) -> dict:
    result = {"port": port, "state": "closed", "service_hint": None, "banner": None, "rtt_ms": None}
    start = time.time()
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=connect_timeout)
        result["state"] = "open"
        result["rtt_ms"] = round((time.time() - start) * 1000, 2)

        # attempt to grab banner
        try:
            writer.write(b"\r\n")
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=read_timeout)
            if banner:
                result["banner"] = banner.decode(errors="ignore").strip()
        except Exception:
            pass

        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    return result


async def run_scan_async(target: str, start_port: int, end_port: int,
                         concurrency: int, connect_timeout: float, read_timeout: float,
                         rate_delay: float = 0.0, jitter: float = 0.0) -> List[dict]:
    sem = asyncio.Semaphore(concurrency)

    async def sem_task(port):
        async with sem:
            await asyncio.sleep(rate_delay)
            return await check_port(target, port, connect_timeout, read_timeout)

    tasks = [asyncio.create_task(sem_task(p)) for p in range(start_port, end_port + 1)]
    return await asyncio.gather(*tasks)


def run_scan_sync(target: str, start: int, end: int, concurrency: int,
                  connect_timeout: float, read_timeout: float, rate_delay: float, jitter: float) -> Tuple[str, List[dict]]:
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = target

    results = asyncio.run(run_scan_async(ip, start, end, concurrency, connect_timeout, read_timeout, rate_delay, jitter))
    return ip, results


# ---------------- Analysis / Enrichment ----------------
def analyze_results(results: List[dict]) -> List[dict]:
    SERVICE_HINTS = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 3306: "mysql", 8080: "http-proxy"
    }

    for r in results:
        if r["port"] in SERVICE_HINTS:
            r["service_hint"] = SERVICE_HINTS[r["port"]]
    return [r for r in results if r["state"] == "open"]


def format_scan_results(result_obj: Dict[str, Any]) -> str:
    target = result_obj.get("target", "?")
    resolved_ip = result_obj.get("resolved_ip", "?")
    out = [f"Port Scan Report for {target} ({resolved_ip})", "=" * 60]

    for r in result_obj.get("results", []):
        line = f"{r['port']:>5}/tcp  {r['state']:<6}  {r.get('service_hint','') or ''}"
        if r.get("banner"):
            line += f" | {r['banner'][:80]}"
        out.append(line)

    if not result_obj.get("results"):
        out.append("No open ports found.")
    return "\n".join(out)


# ---------------- Nmap Integration ----------------
def run_nmap_service_scan(target: str, ports: str = "1-1024", aggressive: bool = False) -> Optional[str]:
    """Run nmap -sV or -A depending on aggressive flag. Returns stdout text."""
    try:
        cmd = ["nmap", "-p", ports]
        cmd += ["-A"] if aggressive else ["-sV"]
        cmd.append(target)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout
    except Exception:
        return None


def parse_nmap_aggressive(output: str) -> dict:
    data = {"ports": [], "os_text": None, "service_info": None, "host_up": None}
    if not output:
        return data

    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port = int(parts[0].split("/")[0])
                state = parts[1]
                service = parts[2]
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                data["ports"].append({"port": port, "state": state, "service": service, "version": version})

        elif line.startswith("Service Info:"):
            data["service_info"] = line
        elif line.startswith("Aggressive OS guesses:"):
            data["os_text"] = line
        elif "Host is up" in line:
            data["host_up"] = True

    return data
