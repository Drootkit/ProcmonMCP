# 更新日志

本文档记录 ProcmonMCP-enhance 项目的所有重要变更。

## [1.3.0] - 2025-03-29

### 变更

#### `launch_process` 函数重构

根据是否提供命令行参数，支持两种不同的启动方式：

1. **带参数启动（`arguments` 非空）**
   - 使用 `subprocess.Popen` 执行带命令行的进程
   - 支持 `hidden`、`working_directory` 参数
   - 返回 `pid` 和进程状态
   - 结果中新增 `launch_method: "subprocess.Popen"` 字段

2. **无参数启动（`arguments` 为 None 或空）**
   - 使用 `os.startfile` 模拟用户双击打开
   - 通过 Windows Shell 关联打开文件
   - 结果中新增 `launch_method: "os.startfile"` 字段

### 移除

- **`launch_process_shell`** 函数及 MCP 工具
  - 功能已合并到 `launch_process(arguments=None)` 中
  - 简化 API：无参数调用 `launch_process(executable_path)` 即可实现 Shell 启动

### 修改的文件

- `procmon_mcp/capture.py`：重构 `launch_process`，删除 `launch_process_shell`
- `procmon_mcp/tools.py`：删除 `launch_process_shell` MCP 工具定义

### 使用示例

```python
# 带参数启动 - 使用 subprocess.Popen
launch_process(
    executable_path="C:\\path\\to\\loader.exe",
    arguments="--config test.ini"
)

# 无参数启动 - 使用 os.startfile（模拟双击）
launch_process(executable_path="C:\\path\\to\\document.pdf")

# 完整监控流程
monitor_and_capture(
    executable_path="C:\\path\\to\\malware.exe",
    capture_duration=120
)
```

---

## [1.2.0] - 2025-03-28

### 新增

#### 进程执行 MCP 工具

1. **`launch_process`**
   - 启动指定的可执行文件
   - 参数：
     - `executable_path`：可执行文件完整路径
     - `arguments`：可选的命令行参数
     - `working_directory`：可选的工作目录
     - `wait_for_completion`：是否等待进程完成（默认：False）
     - `timeout_seconds`：等待超时时间（默认：300）
     - `hidden`：是否隐藏窗口运行（默认：False）
   - 返回 PID 和进程状态

2. **`get_process_info`**
   - 根据 PID 获取运行中进程的详细信息
   - 返回：进程名、exe 路径、命令行、CPU/内存使用、创建时间

3. **`terminate_process`**
   - 根据 PID 终止运行中的进程
   - 参数：
     - `pid`：进程 ID
     - `force`：强制终止还是优雅终止

4. **`monitor_and_capture`**
   - 完整工作流：启动 Procmon → 启动目标进程 → 等待 → 停止
   - 参数：
     - `executable_path`：要监控的可执行文件路径
     - `process_filter`：进程名过滤器（None 时自动检测）
     - `arguments`：可选的可执行文件参数
     - `capture_duration`：捕获时长（默认：60秒）
     - `output_dir`：PML 文件输出目录

### capture.py 新增函数

- `launch_process()`：直接执行进程
- `get_process_info()`：根据 PID 查询进程详情
- `terminate_process()`：终止进程

---

## [1.1.0] - 2025-03-28

### 新增

#### MCP 工具

1. **`generate_capture_config`**
   - 根据用户指定的进程过滤器生成 Procmon 捕获配置 JSON
   - 参数：
     - `process_filter`：进程名过滤器（默认："loader"）
     - `relation`：关系类型 - is, is_not, contains, begins_with, ends_with（默认："contains"）
     - `action`：过滤动作 - include 或 exclude（默认："include"）
     - `destructive_filter`：是否丢弃过滤事件（默认：True）
     - `history_depth`：最大事件数（百万，默认：10）
   - 使用基于 `malware_mon.json` 的模板

2. **`generate_pmc_file`**
   - 将 JSON 配置转换为 PMC 二进制文件格式
   - 参数：
     - `config_json`：可选的预构建配置 JSON
     - `process_filter`：进程名过滤器（默认："loader"）
     - `relation`：关系类型（默认："contains"）
     - `output_path`：输出 PMC 文件路径（默认：`<时间戳>_<过滤器>.pmc`）
   - 使用 procmon_parser 库生成二进制格式

3. **`start_procmon_capture`**
   - 使用指定配置启动 Procmon64.exe
   - 参数：
     - `pmc_file_path`：PMC 配置文件路径
     - `runtime_seconds`：捕获时长（默认：60）
     - `output_pml`：输出 PML 文件路径（默认：`<时间戳>_capture.PML`）
     - `procmon_path`：Procmon 可执行文件路径（None 时自动检测）
     - `wait_for_completion`：是否等待捕获完成（默认：True）

4. **`quick_capture`**
   - 便捷函数，执行完整捕获流程
   - 组合三步：生成配置 → 创建 PMC → 启动捕获
   - 参数：
     - `process_filter`：进程名（默认："loader"）
     - `relation`：关系类型（默认："contains"）
     - `runtime_seconds`：捕获时长（默认：60）
     - `output_dir`：输出目录（默认：当前目录）

### 新增文件

- `procmon_mcp/pmc_config.py`：PMC 配置生成模块
- `procmon_mcp/capture.py`：Procmon 捕获控制模块
- `CHANGELOG.md`：更新日志文件

### 修改文件

- `procmon_mcp/tools.py`：新增 4 个 MCP 工具函数
- `procmon_mcp/__init__.py`：新增模块导入

### 依赖

- 需要 `procmon_parser` 库用于 PMC 文件生成
- 需要 `Procmon64.exe` 或 `Procmon.exe` 用于捕获功能
- 可选：`psutil` 用于增强进程信息获取

### 默认行为

- 默认进程过滤器："loader"
- 默认捕获时长：60 秒
- 默认输出格式：`<时间戳>_<过滤器>.PML`
- 默认模板排除：System 进程、Procmon 自身、IRP_MJ_* 操作、FASTIO_* 操作、Profiling 事件