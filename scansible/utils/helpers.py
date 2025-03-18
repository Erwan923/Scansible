"""
Helper utilities for Scansible
-----------------------------
Common utility functions used across the project.
"""

import subprocess
from typing import Tuple, Optional
import os
import re
import platform

def is_valid_target(target: str) -> bool:
    """Check if a target string is valid (IP, domain, or network range)."""
    # Simple check for now
    return bool(target and len(target.strip()) > 0)

def run_command(command: str) -> Tuple[bool, str, str]:
    """Run a shell command and return success status and output."""
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        success = process.returncode == 0
        return success, stdout, stderr
    except Exception as e:
        return False, "", str(e)

def get_system_info() -> dict:
    """Get basic information about the system."""
    info = {
        'os': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
    }
    return info
