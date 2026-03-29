# Changelog

All notable changes to the ProcmonMCP-enhance project will be documented in this file.

## [1.3.0] - 2025-03-29

### Changed

#### `launch_process` Function Refactored

Refactored to support two distinct launch methods based on whether arguments are provided:

1. **With arguments (`arguments` non-empty)**
   - Uses `subprocess.Popen` to execute with command line
   - Supports `hidden`, `working_directory` parameters
   - Returns `pid` and process status
   - Added `launch_method: "subprocess.Popen"` to result

2. **Without arguments (`arguments` is None or empty)**
   - Uses `os.startfile` to simulate user double-click
   - Opens file with Windows shell association
   - Added `launch_method: "os.startfile"` to result

### Removed

- **`launch_process_shell`** function and MCP tool
  - Functionality merged into `launch_process(arguments=None)`
  - Simplified API: use `launch_process(executable_path)` without arguments for shell launch

### Modified Files

- `procmon_mcp/capture.py`: Refactored `launch_process`, removed `launch_process_shell`
- `procmon_mcp/tools.py`: Removed `launch_process_shell` MCP tool definition

---

## [1.2.0] - 2025-03-28

### Added

#### New Process Execution MCP Tools

1. **`launch_process`**
   - Launches a process by executing the specified executable file
   - Parameters:
     - `executable_path`: Full path to the executable file
     - `arguments`: Optional command line arguments
     - `working_directory`: Optional working directory
     - `wait_for_completion`: Whether to wait for process to complete (default: False)
     - `timeout_seconds`: Timeout if waiting (default: 300)
     - `hidden`: Run without visible window (default: False)
   - Returns PID and process status

2. **`get_process_info`**
   - Retrieves detailed information about a running process by PID
   - Returns: name, exe path, command line, CPU/memory usage, create time

3. **`terminate_process`**
   - Terminates a running process by PID
   - Parameters:
     - `pid`: Process ID to terminate
     - `force`: Force kill vs graceful terminate

4. **`monitor_and_capture`**
   - Complete workflow: Start Procmon → Launch process → Wait → Stop
   - Combines all steps into one convenient tool
   - Parameters:
     - `executable_path`: Path to executable to monitor
     - `process_filter`: Process name filter (auto-detected if None)
     - `arguments`: Optional executable arguments
     - `capture_duration`: Total capture duration (default: 60s)
     - `output_dir`: Output directory for PML file

### New Functions in capture.py

- `launch_process()`: Direct process execution
- `get_process_info()`: Query process details by PID
- `terminate_process()`: Kill/terminate a process

### Usage Examples

```python
# Launch with arguments (uses subprocess.Popen)
launch_process(
    executable_path="C:\\path\\to\\loader.exe",
    arguments="--config test.ini"
)

# Launch without arguments (uses os.startfile, simulates double-click)
launch_process(executable_path="C:\\path\\to\\document.pdf")

# Complete monitoring workflow
monitor_and_capture(
    executable_path="C:\\path\\to\\malware.exe",
    capture_duration=120
)
```

## [1.1.0] - 2025-03-28

### Added

#### New MCP Tools

1. **`generate_capture_config`**
   - Generates Procmon capture configuration JSON based on user-specified process filter
   - Parameters:
     - `process_filter`: Process name to filter (default: "loader")
     - `relation`: Relation type - is, is_not, contains, begins_with, ends_with (default: "contains")
     - `action`: Filter action - include or exclude (default: "include")
     - `destructive_filter`: Whether to drop filtered events (default: True)
     - `history_depth`: Maximum events in millions (default: 10)
   - Uses template based on `malware_mon.json`
   - Returns configuration JSON that can be used to generate PMC files

2. **`generate_pmc_file`**
   - Converts JSON configuration to PMC binary file format
   - Parameters:
     - `config_json`: Optional pre-built configuration JSON
     - `process_filter`: Process name filter if generating default config (default: "loader")
     - `relation`: Relation type if generating default config (default: "contains")
     - `output_path`: Output PMC file path (default: `<timestamp>_<filter>.pmc`)
   - Ported functionality from `pmc_generator.py`
   - Uses procmon_parser library for binary format generation

3. **`start_procmon_capture`**
   - Launches Procmon64.exe with specified configuration
   - Parameters:
     - `pmc_file_path`: Path to PMC configuration file
     - `runtime_seconds`: Capture duration in seconds (default: 60)
     - `output_pml`: Output PML file path (default: `<timestamp>_capture.PML`)
     - `procmon_path`: Path to Procmon executable (auto-detected if None)
     - `wait_for_completion`: Whether to wait for capture to complete (default: True)
   - Executes command: `Procmon64.exe /AcceptEula /Quiet /LoadConfig "PMC_PATH" /Runtime SECONDS /BackingFile "OUTPUT.PML"`

4. **`quick_capture`**
   - Convenience function for complete capture workflow
   - Combines all three steps: generate config -> create PMC -> start capture
   - Parameters:
     - `process_filter`: Process name to capture (default: "loader")
     - `relation`: Relation type (default: "contains")
     - `runtime_seconds`: Capture duration in seconds (default: 60)
     - `output_dir`: Directory for output files (default: current directory)

### New Files

- `procmon_mcp/pmc_config.py`: PMC configuration generation module
  - `generate_capture_config()`: Generate configuration JSON
  - `save_pmc_file()`: Save configuration to PMC file
  - `config_dict_to_pmc()`: Convert config dict to PMC binary
  - Column/relation/action parsing functions

- `procmon_mcp/capture.py`: Procmon capture control module
  - `find_procmon_executable()`: Auto-detect Procmon location
  - `start_procmon_capture()`: Launch and control capture
  - `stop_procmon_capture()`: Stop running instances
  - `check_procmon_running()`: Check if Procmon is running

- `CHANGELOG.md`: This changelog file

### Modified Files

- `procmon_mcp/tools.py`: Added 4 new MCP tool functions
- `procmon_mcp/__init__.py`: Added imports for new modules

### Dependencies

- Requires `procmon_parser` library for PMC file generation
- Requires `Procmon64.exe` or `Procmon.exe` for capture functionality
- Optional: `psutil` for enhanced process information

### Default Behavior

- Default process filter: "loader"
- Default capture duration: 60 seconds
- Default output format: `<timestamp>_<filter>.PML`
- Default template excludes: System process, Procmon itself, IRP_MJ_* operations, FASTIO_* operations, Profiling events