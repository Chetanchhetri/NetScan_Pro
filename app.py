import subprocess
from flask import Flask, render_template, request, jsonify, Response
from concurrent.futures import ThreadPoolExecutor, Future
import uuid
import time
import logging
from typing import Tuple, Dict, Any

# Import fixed scanner
from port_scanner import (
    run_scan_sync,
    analyze_results,
    format_scan_results,
    run_nmap_service_scan,
    parse_nmap_aggressive
)

app = Flask(__name__, static_folder="static", template_folder="templates")
logging.basicConfig(level=logging.INFO)

jobs: Dict[str, Dict[str, Any]] = {}
executor = ThreadPoolExecutor(max_workers=4)

MAX_PORT_RANGE = 2000
MAX_CONCURRENCY = 2000


def validate_params(target: str, start: int, end: int, concurrency: int):
    if not target:
        raise ValueError("target required")
    if start < 1 or end > 65535 or start > end:
        raise ValueError("invalid port range")
    if (end - start + 1) > MAX_PORT_RANGE:
        raise ValueError(f"port range too large (limit {MAX_PORT_RANGE})")
    if concurrency < 1 or concurrency > MAX_CONCURRENCY:
        raise ValueError("invalid concurrency")


def run_scan_task(target: str, start: int, end: int, concurrency: int,
                  connect_timeout: float, read_timeout: float, rate_delay: float, jitter: float,
                  no_banner: bool, use_nmap: bool = False, aggressive: bool = False) -> dict:
    try:
        ip, raw = run_scan_sync(target, start, end, concurrency,
                                connect_timeout, (0.01 if no_banner else read_timeout),
                                rate_delay, jitter)
        enriched = analyze_results(raw)
        result_obj = {
            "status": "done",
            "target": target,
            "resolved_ip": ip,
            "start": start,
            "end": end,
            "results": enriched,
            "scanned_at": time.time()
        }

        if use_nmap:
            logging.info("Running nmap (aggressive=%s)...", aggressive)
            nmap_out = run_nmap_service_scan(target, ports=f"{start}-{end}", aggressive=aggressive)
            if nmap_out:
                result_obj["_nmap"] = parse_nmap_aggressive(nmap_out)

        result_obj["_formatted"] = format_scan_results(result_obj)
        return result_obj
    except Exception as e:
        logging.exception("Scan failed for %s", target)
        return {"status": "error", "error": str(e)}


def create_scan_job(target: str, start: int, end: int, concurrency: int,
                    connect_timeout: float, read_timeout: float, rate_delay: float, jitter: float,
                    no_banner: bool, use_nmap: bool = False, aggressive: bool = False) -> Tuple[str, dict]:
    job_id = str(uuid.uuid4())
    future = executor.submit(run_scan_task, target, start, end, concurrency,
                             connect_timeout, read_timeout, rate_delay, jitter,
                             no_banner, use_nmap, aggressive)
    jobs[job_id] = {"future": future, "created": time.time(),
                    "params": {"target": target, "start": start, "end": end}}
    return job_id, jobs[job_id]


@app.route("/")
def index():
    return "<h3>Port Scanner API Running ✅</h3>"


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or request.form
    try:
        target = data["target"]
        start = int(data.get("start", 1))
        end = int(data.get("end", 1024))
        concurrency = int(data.get("concurrency", 200))
        connect_timeout = float(data.get("connect_timeout", 3.0))
        read_timeout = float(data.get("read_timeout", 2.0))
        rate_delay = float(data.get("rate_delay", 0.0))
        jitter = float(data.get("jitter", 0.02))
        no_banner = bool(data.get("no_banner", False))
        use_nmap = bool(data.get("use_nmap", False))
        aggressive = bool(data.get("aggressive", False))

        validate_params(target, start, end, concurrency)
        job_id, job_meta = create_scan_job(target, start, end, concurrency,
                                           connect_timeout, read_timeout, rate_delay, jitter, no_banner,
                                           use_nmap, aggressive)
        return jsonify({"status": "submitted", "job_id": job_id})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/scan-status/<job_id>", methods=["GET"])
def scan_status(job_id):
    meta = jobs.get(job_id)
    if not meta:
        return jsonify({"status": "error", "error": "job not found"}), 404
    future: Future = meta["future"]
    if future.done():
        res = future.result()
        return Response(res.get("_formatted", "No data"), mimetype="text/plain")
    return jsonify({"status": "running"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
