"""Command-line file integrity monitor using SHA-256 content hashes.

Run ``python monitor.py DIRECTORY --baseline`` to create a baseline, then
``python monitor.py DIRECTORY --monitor`` to report new, modified, and deleted
files. The baseline and alert log are written to the current working directory.
"""

import os
import sys
import json
import time
import hashlib
import argparse
from datetime import datetime

# Configuration constants
BASELINE_FILE = "baseline.json"
LOG_FILE = "fim_alerts.log"

def log_event(status, file_path, message=""):
    """Write a timestamped event to standard output and the alert log.

    Args:
        status: Event category, such as ``MODIFIED`` or ``DELETED``.
        file_path: Path of the file associated with the event.
        message: Optional explanatory text appended to the event.

    The event is appended to :data:`LOG_FILE` in the current working directory.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{status}] {file_path} {message}".strip()
    
    # Print to console for immediate visibility
    print(log_entry)
    
    # Append to the log file for auditing
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

def calculate_sha256(file_path):
    """Calculate a file's SHA-256 digest by reading it in chunks.

    Args:
        file_path: Path to the file to hash.

    Returns:
        The lowercase hexadecimal SHA-256 digest, or ``None`` if the file is
        missing or cannot be read due to a permission error.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read in 4KB chunks
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (FileNotFoundError, PermissionError):
        # Return None if the file was deleted mid-scan or locked by the system
        return None

def generate_baseline(target_directory):
    """Recursively hash files and write their paths and digests to the baseline.

    Args:
        target_directory: Directory tree to scan.

    Raises:
        SystemExit: If ``target_directory`` does not exist.

    The baseline is saved as :data:`BASELINE_FILE` in the current working
    directory. File paths are normalized to use forward slashes.
    """
    if not os.path.exists(target_directory):
        print(f"[-] Error: Target directory '{target_directory}' does not exist.")
        sys.exit(1)

    print(f"[*] Generating baseline for directory: {target_directory}...")
    baseline_data = {}

    # Recursively walk through the directory structure
    for root, _, files in os.walk(target_directory):
        for file in files:
            full_path = os.path.join(root, file).replace("\\", "/") # Normalize paths for cross-OS compatibility
            file_hash = calculate_sha256(full_path)
            if file_hash:
                baseline_data[full_path] = file_hash

    # Save data structurally to JSON
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline_data, f, indent=4)
        
    print(f"[+] Baseline successfully generated with {len(baseline_data)} files saved to '{BASELINE_FILE}'.")

def monitor_directory(target_directory, interval=2):
    """Continuously compare a directory tree with its saved baseline.

    Args:
        target_directory: Directory tree to monitor.
        interval: Seconds to wait between scans; defaults to two seconds.

    Raises:
        SystemExit: If :data:`BASELINE_FILE` is not present in the current
            working directory.

    New, modified, and deleted files are reported through :func:`log_event`.
    Pressing Ctrl+C stops monitoring. Baseline updates during monitoring are
    kept in memory and are not written back to the baseline file.
    """
    if not os.path.exists(BASELINE_FILE):
        print(f"[-] Error: Baseline file '{BASELINE_FILE}' not found. Run with --baseline first.")
        sys.exit(1)

    # Load the established baseline data
    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    print(f"[*] Starting continuous monitoring on '{target_directory}'... Press Ctrl+C to stop.")
    
    try:
        while True:
            current_files = {}
            
            # 1. Scan the directory for its current state
            for root, _, files in os.walk(target_directory):
                for file in files:
                    full_path = os.path.join(root, file).replace("\\", "/")
                    file_hash = calculate_sha256(full_path)
                    if file_hash:
                        current_files[full_path] = file_hash

            # 2. Check for Modified or Created files
            for file_path, current_hash in current_files.items():
                if file_path not in baseline:
                    log_event("NEW_FILE", file_path, "- A new untracked file was introduced.")
                    # Update baseline memory so it only alerts once per event
                    baseline[file_path] = current_hash 
                elif baseline[file_path] != current_hash:
                    log_event("MODIFIED", file_path, "- File content has changed!")
                    baseline[file_path] = current_hash

            # 3. Check for Deleted files
            deleted_files = []
            for file_path in baseline.keys():
                if file_path not in current_files:
                    log_event("DELETED", file_path, "- File was removed from the file system.")
                    deleted_files.append(file_path)
            
            # Remove deleted files from current memory baseline
            for file_path in deleted_files:
                del baseline[file_path]

            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python File Integrity Monitor (FIM)")
    parser.add_argument("directory", help="The target directory to baseline or monitor.")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-b", "--baseline", action="store_true", help="Generate a new baseline hash file.")
    group.add_argument("-m", "--monitor", action="store_true", help="Start monitoring against the existing baseline.")
    
    args = parser.parse_args()

    if args.baseline:
        generate_baseline(args.directory)
    elif args.monitor:
        monitor_directory(args.directory)
