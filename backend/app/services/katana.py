"""Katana crawling service."""
import os
import subprocess
from app.config import settings

def run_katana(target: str, job_id: int) -> str | None:
    """Run katana on a target and return the output file path containing discovered URLs."""
    katana_bin = settings.KATANA_BIN
    
    if not os.path.exists(settings.SCAN_OUTPUT_DIR):
        os.makedirs(settings.SCAN_OUTPUT_DIR, exist_ok=True)
        
    output_file = os.path.join(settings.SCAN_OUTPUT_DIR, f"katana-job-{job_id}.txt")
    
    # Use conservative defaults for shared VPS
    cmd = [
        katana_bin,
        "-u", target,
        "-o", output_file,
        "-jc",  # Parse JS files for endpoints
        "-passive", # Use passive sources (AlienVault, Wayback, etc)
        "-c", "5",  # low concurrency
        "-p", "5",  # low parallelism
    ]
    
    # Also check if katana exists in PATH if not at configured bin
    if not os.path.isfile(katana_bin):
        import shutil
        found_bin = shutil.which("katana")
        if found_bin:
            cmd[0] = found_bin
        else:
            print("Katana binary not found!")
            return None
    
    try:
        # Prevent OS thread panic on VPS for Katana as well
        custom_env = os.environ.copy()
        custom_env["GOMAXPROCS"] = "1"
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=custom_env,
        )
        
        # Katana may take time, limit to 30 mins max crawl time
        stdout, stderr = process.communicate(timeout=1800)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return output_file
        
        return None
        
    except Exception as e:
        print(f"Katana execution failed: {e}")
        return None
