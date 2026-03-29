"""
Procmon Capture Control Module

Provides functionality to launch and control Procmon for automated log capture.
"""

import os
import subprocess
import logging
import time
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

# Default Procmon paths to search
DEFAULT_PROCMON_PATHS = [
    r"C:\Users\user\Desktop\Procmon64.exe",
    r"C:\Users\user\Desktop\Procmon.exe",
    r"C:\Program Files\Procmon\Procmon64.exe",
    r"C:\Program Files\Procmon\Procmon.exe",
    r"C:\Program Files (x86)\Procmon\Procmon64.exe",
    r"C:\Program Files (x86)\Procmon\Procmon.exe",
    r"C:\Windows\Procmon64.exe",
    r"C:\Windows\Procmon.exe",
    r"C:\Tools\Procmon64.exe",
    r"C:\Tools\Procmon.exe",
]


def find_procmon_executable() -> Optional[str]:
    """
    Search for Procmon64.exe or Procmon.exe in common locations.

    Returns:
        Path to Procmon executable, or None if not found
    """
    for path in DEFAULT_PROCMON_PATHS:
        if os.path.isfile(path):
            return path

    # Also check PATH environment
    for exe_name in ["Procmon64.exe", "Procmon.exe"]:
        try:
            result = subprocess.run(
                ["where", exe_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                found_path = result.stdout.strip().split('\n')[0]
                if os.path.isfile(found_path):
                    return found_path
        except Exception:
            pass

    return None


def validate_pmc_file(pmc_path: str) -> bool:
    """
    Validate that a PMC file exists and is readable.

    Args:
        pmc_path: Path to PMC file

    Returns:
        True if valid, False otherwise
    """
    if not os.path.exists(pmc_path):
        return False
    if not os.path.isfile(pmc_path):
        return False
    # PMC files should have at least some bytes
    if os.path.getsize(pmc_path) < 16:
        return False
    return True


def start_procmon_capture(
    pmc_file_path: str,
    output_pml: str,
    runtime_seconds: int = 60,
    procmon_path: Optional[str] = None,
    wait_for_completion: bool = True,
    quiet: bool = True
) -> Dict[str, Any]:
    """
    Start a Procmon capture session.

    Command format:
    Procmon64.exe /AcceptEula /Quiet /LoadConfig "PMC_PATH" /Runtime SECONDS /BackingFile "OUTPUT.PML"

    Args:
        pmc_file_path: Path to PMC configuration file
        output_pml: Output PML file path
        runtime_seconds: Capture duration in seconds (default: 60)
        procmon_path: Path to Procmon executable (auto-detected if None)
        wait_for_completion: Whether to wait for capture to complete
        quiet: Whether to run in quiet mode (no GUI)

    Returns:
        Result dictionary with success status and details
    """
    # Validate PMC file
    if not validate_pmc_file(pmc_file_path):
        return {
            "success": False,
            "error": f"PMC file not found or invalid: {pmc_file_path}"
        }

    # Find Procmon executable
    if procmon_path is None:
        procmon_path = find_procmon_executable()

    if procmon_path is None or not os.path.isfile(procmon_path):
        return {
            "success": False,
            "error": "Procmon executable not found. Please specify procmon_path or install Procmon."
        }

    # Build command arguments
    cmd = [procmon_path, "/AcceptEula"]

    if quiet:
        cmd.append("/Quiet")

    cmd.extend([
        "/LoadConfig", pmc_file_path,
        "/Runtime", str(runtime_seconds),
        "/BackingFile", output_pml
    ])

    logger.info(f"Starting Procmon capture: {' '.join(cmd)}")

    result = {
        "success": False,
        "command": " ".join(cmd),
        "procmon_path": procmon_path,
        "pmc_file": pmc_file_path,
        "output_pml": output_pml,
        "runtime_seconds": runtime_seconds,
        "start_time": datetime.now().isoformat(),
    }

    try:
        # Start Procmon process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if quiet else 0
        )

        result["pid"] = process.pid
        result["process_started"] = True

        if wait_for_completion:
            logger.info(f"Waiting for Procmon capture to complete ({runtime_seconds}s)...")
            # Wait for the process to complete (it will exit after runtime)
            # Add a buffer time for startup/shutdown
            max_wait = runtime_seconds + 30
            stdout, stderr = process.communicate(timeout=max_wait)

            result["return_code"] = process.returncode
            result["stdout"] = stdout.decode('utf-8', errors='replace') if stdout else ""
            result["stderr"] = stderr.decode('utf-8', errors='replace') if stderr else ""
            result["end_time"] = datetime.now().isoformat()
            result["success"] = process.returncode == 0

            # Check if output file was created
            if os.path.exists(output_pml):
                result["output_file_exists"] = True
                result["output_file_size"] = os.path.getsize(output_pml)
            else:
                result["output_file_exists"] = False
                result["warning"] = "Output PML file was not created"

        else:
            # Non-blocking mode - return immediately
            result["success"] = True
            result["message"] = f"Procmon started with PID {process.pid}. Capture will run for {runtime_seconds} seconds."

    except subprocess.TimeoutExpired:
        result["error"] = f"Procmon process timed out after {runtime_seconds + 30} seconds"
        result["success"] = False

    except FileNotFoundError as e:
        result["error"] = f"Procmon executable not found: {e}"
        result["success"] = False

    except Exception as e:
        logger.exception("Failed to start Procmon capture")
        result["error"] = str(e)
        result["success"] = False

    return result


def stop_procmon_capture(procmon_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Stop any running Procmon instances.

    Args:
        procmon_path: Path to Procmon executable (used to find running instances)

    Returns:
        Result dictionary
    """
    try:
        # Use taskkill to stop Procmon
        result = subprocess.run(
            ["taskkill", "/F", "/IM", "Procmon64.exe"],
            capture_output=True,
            text=True,
            timeout=10
        )

        result2 = subprocess.run(
            ["taskkill", "/F", "/IM", "Procmon.exe"],
            capture_output=True,
            text=True,
            timeout=10
        )

        return {
            "success": True,
            "message": "Procmon processes terminated",
            "procmon64_output": result.stdout,
            "procmon_output": result2.stdout
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def check_procmon_running() -> Dict[str, Any]:
    """
    Check if Procmon is currently running.

    Returns:
        Dictionary with running status and PIDs
    """
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Procmon64.exe", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=5
        )

        result2 = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Procmon.exe", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=5
        )

        running = []
        for line in result.stdout.strip().split('\n'):
            if 'Procmon64.exe' in line:
                # Parse CSV: "Procmon64.exe","PID","Session Name","Session#","Mem Usage"
                parts = line.replace('"', '').split(',')
                if len(parts) >= 2:
                    running.append({"name": "Procmon64.exe", "pid": parts[1].strip()})

        for line in result2.stdout.strip().split('\n'):
            if 'Procmon.exe' in line:
                parts = line.replace('"', '').split(',')
                if len(parts) >= 2:
                    running.append({"name": "Procmon.exe", "pid": parts[1].strip()})

        return {
            "running": len(running) > 0,
            "processes": running,
            "count": len(running)
        }

    except Exception as e:
        return {
            "running": False,
            "error": str(e),
            "processes": [],
            "count": 0
        }


def launch_process(
    executable_path: str,
    arguments: Optional[str] = None,
    working_directory: Optional[str] = None,
    wait_for_completion: bool = False,
    timeout_seconds: int = 300,
    hidden: bool = False
) -> Dict[str, Any]:
    """
    Launch a process using one of two methods:
    - With arguments: Uses subprocess.Popen to execute with command line
    - Without arguments: Uses os.startfile to simulate double-click

    Args:
        executable_path: Path to the executable file
        arguments: Optional command line arguments. If provided, uses Popen; otherwise uses startfile
        working_directory: Optional working directory (only used with Popen)
        wait_for_completion: Whether to wait for the process to complete
        timeout_seconds: Timeout for waiting (default: 300 seconds)
        hidden: Whether to run the process hidden (no window, only used with Popen)

    Returns:
        Result dictionary with success status and process details
    """
    result = {
        "success": False,
        "executable_path": executable_path,
        "arguments": arguments,
        "working_directory": working_directory,
        "start_time": datetime.now().isoformat(),
        "launch_method": None,
    }

    # Validate executable path
    if not os.path.exists(executable_path):
        result["error"] = f"Executable not found: {executable_path}"
        return result

    if not os.path.isfile(executable_path):
        result["error"] = f"Path is not a file: {executable_path}"
        return result

    # Method 1: With arguments - use subprocess.Popen
    if arguments:
        result["launch_method"] = "subprocess.Popen"

        cmd = [executable_path]
        import shlex
        try:
            cmd.extend(shlex.split(arguments))
        except Exception:
            cmd.append(arguments)

        cwd = working_directory if working_directory else os.path.dirname(executable_path)
        if not os.path.exists(cwd):
            cwd = os.getcwd()

        creation_flags = subprocess.CREATE_NO_WINDOW if hidden else 0

        logger.info(f"Launching process with Popen: {' '.join(cmd)}")

        try:
            process = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE if wait_for_completion else subprocess.DEVNULL,
                stderr=subprocess.PIPE if wait_for_completion else subprocess.DEVNULL,
                creationflags=creation_flags
            )

            result["pid"] = process.pid
            result["process_started"] = True

            if wait_for_completion:
                logger.info(f"Waiting for process to complete (PID: {process.pid})...")
                try:
                    stdout, stderr = process.communicate(timeout=timeout_seconds)

                    result["return_code"] = process.returncode
                    result["end_time"] = datetime.now().isoformat()
                    result["success"] = process.returncode == 0

                    if stdout:
                        result["stdout"] = stdout.decode('utf-8', errors='replace')
                    if stderr:
                        result["stderr"] = stderr.decode('utf-8', errors='replace')

                except subprocess.TimeoutExpired:
                    process.kill()
                    result["error"] = f"Process timed out after {timeout_seconds} seconds"
                    result["return_code"] = -1
                    result["end_time"] = datetime.now().isoformat()
            else:
                result["success"] = True
                result["message"] = f"Process launched successfully with PID {process.pid}"

                # Verify process is running
                time.sleep(0.5)
                poll_result = process.poll()
                if poll_result is not None:
                    result["success"] = False
                    result["error"] = f"Process exited immediately with code {poll_result}"

        except FileNotFoundError as e:
            result["error"] = f"File not found: {e}"
        except PermissionError as e:
            result["error"] = f"Permission denied: {e}"
        except Exception as e:
            logger.exception("Failed to launch process")
            result["error"] = str(e)

    # Method 2: Without arguments - use os.startfile (simulate double-click)
    else:
        result["launch_method"] = "os.startfile"

        logger.info(f"Launching process with startfile: {executable_path}")

        try:
            if wait_for_completion:
                # Use cmd start /wait for blocking mode
                cmd = ["cmd", "/c", "start", "/wait", "", executable_path]
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

                try:
                    stdout, stderr = process.communicate(timeout=timeout_seconds)
                    result["return_code"] = process.returncode
                    result["end_time"] = datetime.now().isoformat()
                    result["success"] = process.returncode == 0
                except subprocess.TimeoutExpired:
                    process.kill()
                    result["error"] = f"Process timed out after {timeout_seconds} seconds"
            else:
                # Non-blocking: use os.startfile
                os.startfile(executable_path)
                result["success"] = True
                result["message"] = f"Process launched via startfile: {executable_path}"

        except Exception as e:
            logger.exception("Failed to launch process via startfile")
            result["error"] = str(e)

    return result


def get_process_info(pid: int) -> Dict[str, Any]:
    """
    Get information about a running process by PID.

    Args:
        pid: Process ID

    Returns:
        Dictionary with process information
    """
    result = {
        "pid": pid,
        "running": False
    }

    try:
        import psutil
        proc = psutil.Process(pid)

        result["running"] = proc.is_running()
        result["name"] = proc.name()
        result["exe"] = proc.exe()
        result["cmdline"] = proc.cmdline()
        result["cwd"] = proc.cwd()
        result["create_time"] = datetime.fromtimestamp(proc.create_time()).isoformat()
        result["cpu_percent"] = proc.cpu_percent(interval=0.1)
        result["memory_mb"] = proc.memory_info().rss / (1024 * 1024)

    except psutil.NoSuchProcess:
        result["error"] = f"Process with PID {pid} not found"
    except psutil.AccessDenied:
        result["error"] = f"Access denied to process {pid}"
    except ImportError:
        # Fallback using tasklist
        try:
            output = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                text=True,
                timeout=5
            )
            if str(pid) in output:
                result["running"] = True
                parts = output.replace('"', '').split(',')
                if len(parts) >= 5:
                    result["name"] = parts[0].strip()
                    result["memory_kb"] = parts[4].replace(',', '').replace(' K', '').strip()
        except Exception as e:
            result["error"] = str(e)

    return result


def terminate_process(pid: int, force: bool = True) -> Dict[str, Any]:
    """
    Terminate a process by PID.

    Args:
        pid: Process ID to terminate
        force: Whether to force termination (kill vs terminate)

    Returns:
        Result dictionary
    """
    result = {
        "success": False,
        "pid": pid
    }

    try:
        import psutil
        proc = psutil.Process(pid)

        if force:
            proc.kill()
        else:
            proc.terminate()

        result["success"] = True
        result["message"] = f"Process {pid} terminated"

    except psutil.NoSuchProcess:
        result["error"] = f"Process with PID {pid} not found"
    except psutil.AccessDenied:
        result["error"] = f"Access denied to terminate process {pid}"
    except ImportError:
        # Fallback using taskkill
        try:
            cmd = ["taskkill", "/PID", str(pid)]
            if force:
                cmd.append("/F")

            output = subprocess.check_output(cmd, text=True, timeout=10)
            result["success"] = "SUCCESS" in output.upper()
            result["output"] = output

        except subprocess.CalledProcessError as e:
            result["error"] = e.stdout if e.stdout else str(e)
        except Exception as e:
            result["error"] = str(e)

    return result