"""Katana crawling service."""
import os
import subprocess
from app.config import settings

# Maximum endpoints to pass to Nuclei per scan mode
MAX_ENDPOINTS = {
    "fast": 100,
    "deep": 300,
    "comprehensive": 500,
}

# Katana crawl timeout per scan mode (seconds)
KATANA_TIMEOUT = {
    "fast": 180,
    "deep": 600,
    "comprehensive": 900,
}


def run_katana(target: str, job_id: int, scan_mode: str = "deep") -> str | None:
    """Run katana on a target and return the output file path containing discovered URLs.
    
    Limitations are applied per scan_mode to prevent Nuclei from timing out:
    - fast:          100 endpoints, 3-min crawl
    - deep:          300 endpoints, 10-min crawl
    - comprehensive: 500 endpoints, 15-min crawl
    """
    katana_bin = settings.KATANA_BIN

    if not os.path.exists(settings.SCAN_OUTPUT_DIR):
        os.makedirs(settings.SCAN_OUTPUT_DIR, exist_ok=True)

    raw_output   = os.path.join(settings.SCAN_OUTPUT_DIR, f"katana-raw-{job_id}.txt")
    output_file  = os.path.join(settings.SCAN_OUTPUT_DIR, f"katana-job-{job_id}.txt")

    # Crawl config per mode
    depth = "2" if scan_mode == "fast" else "3"
    duration = KATANA_TIMEOUT.get(scan_mode, 600)
    concurrency = "3" if scan_mode == "fast" else "5"

    cmd = [
        katana_bin,
        "-u", target,
        "-o", raw_output,
        "-depth", depth,               # Limit crawl depth
        "-crawl-duration", str(duration),  # Hard time cap
        "-c", concurrency,              # Low concurrency for VPS
        "-p", concurrency,              # Low parallelism
        "-jc",                          # Parse JS files for extra endpoints
        "-duc",                         # Disable update check
        "-silent",
    ]
    # NOTE: no -passive flag — that causes Wayback/AlienVault historical
    # URLs (tens-of-thousands) which makes Nuclei time out.

    # Resolve binary from PATH if the configured path doesn't exist
    if not os.path.isfile(katana_bin):
        import shutil
        found_bin = shutil.which("katana")
        if found_bin:
            cmd[0] = found_bin
        else:
            print("Katana binary not found!")
            return None

    try:
        custom_env = os.environ.copy()
        custom_env["GOMAXPROCS"] = "1"  # Prevent thread-panic on shared VPS

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=custom_env,
        )

        # Add a small safety buffer on top of crawl-duration
        timeout = duration + 60
        try:
            process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            print(f"[Katana] Crawl timed out after {timeout}s (job {job_id}) — using partial results")

        if not os.path.exists(raw_output) or os.path.getsize(raw_output) == 0:
            print(f"[Katana] No output produced (job {job_id})")
            return None

        # De-duplicate and cap to MAX_ENDPOINTS
        max_eps = MAX_ENDPOINTS.get(scan_mode, 300)
        with open(raw_output, "r", encoding="utf-8", errors="replace") as fh:
            seen = set()
            unique_urls = []
            for line in fh:
                url = line.strip()
                if url and url not in seen:
                    seen.add(url)
                    unique_urls.append(url)
                if len(unique_urls) >= max_eps:
                    break

        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(unique_urls))

        print(f"[Katana] Discovered {len(unique_urls)} unique endpoints (capped at {max_eps}) for job {job_id}")
        return output_file

    except Exception as e:
        print(f"Katana execution failed: {e}")
        return None
