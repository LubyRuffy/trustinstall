# UTM 调用 VM 完成跨平台集成测试：技术方案（macOS 宿主机）

本文整理一套“在 macOS 宿主机上，通过 UTM 启动/控制 Linux 与 Windows（可选 macOS）虚拟机，并在 guest 内执行 `go test`”的跨平台集成测试方案。

该方案的目标是解决以下问题：

- 需要真实修改系统信任库/证书存储（Linux root、Windows 管理员权限），不适合仅用单元测试或纯 mock
- Apple Silicon 上需要在 ARM64 的 Windows/Linux 环境里验证行为一致性
- 让同一套测试在 macOS 宿主机上“编排”多平台执行，并能在 CI 机器上稳定运行

本仓库的落地实现集中在 `integration/` 包中，宿主机通过 `utmctl`、SSH、WinRM 触发 guest 内执行测试。

## 1. 总体架构

核心思路：宿主机只负责“编排与触发”，真正的系统级动作在 guest 内执行。

- 宿主机（macOS）
  - 安装 UTM（含 `utmctl`）
  - 负责启动 VM、获取 IP、触发远程命令、上传/分发代码（必要时）
  - 执行入口：`go test ./integration ...`
- guest（Linux/Windows/macOS）
  - 具备 Go（版本以 `go.mod` 为准）
  - 具备仓库代码（或允许宿主机分发）
  - 具备执行集成测试所需权限（Linux root/sudo；Windows 管理员）

UTM 编排链路（推荐优先级）：

1. SSH（可观测性好、限制少）
2. WinRM（Windows 专用，便于远程 PowerShell，但依赖 pywinrm/端口策略）
3. `utmctl exec`（兜底，在 guest 内直接执行；在部分后端/场景可能受限）

## 2. 关键组件与职责

### 2.1 utmctl

默认路径：`/Applications/UTM.app/Contents/MacOS/utmctl`

可通过环境变量覆盖：

- `TRUSTINSTALL_UTMCTL`：自定义 utmctl 路径

本方案主要使用：

- `utmctl start [--hide] <vm>`：启动 VM（best-effort，可能重试 hide/非 hide 两种模式）
- `utmctl ip-address --hide <vm>`：获取 VM IP（用于 SSH/WinRM 连接）
- `utmctl exec <vm> <cmd...>`：在 guest 内执行命令（作为兜底路径）

注意：在某些 macOS guest 后端，`ip-address/exec` 可能返回 `Operation not supported by the backend.` 或 AppleEvent/OSStatus 类错误，需走 SSH 或其它发现机制。

### 2.2 IP 发现与 VM 选择

优先级（以本仓库实现为准，见 `integration/utmctl.go`）：

1. 显式指定 VM 标识：
   - `TRUSTINSTALL_UTM_LINUX_VM`
   - `TRUSTINSTALL_UTM_WINDOWS_VM`
   - `TRUSTINSTALL_UTM_DARWIN_VM`
   - 或通用 `TRUSTINSTALL_UTM_VM`
2. 若未指定：尝试 `utmctl list` 并按 CI 约定选择
   - 名称前缀优先：`ci-os*`，其次 `ci-*`
   - 再按 OS 关键字倾向选择（Windows/Linux/macOS）
3. 若 `utmctl list` 不可用（常见于无登录/SSH session/TCC 限制）：
   - 从 UTM 默认 Documents 路径“猜测”常见 VM bundle 是否存在：
     - `~/Library/Containers/com.utmapp.UTM/Data/Documents/<name>.utm`
4. 若仍不可用：按端口扫描/网段扫描做兜底（不同 OS 使用不同端口特征）

建议：CI 环境尽量显式设置 `TRUSTINSTALL_UTM_*_VM`，降低自动发现的不确定性。

## 3. 前置条件

### 3.1 宿主机（macOS）

- 已安装 UTM（包含 `utmctl`）
- 可执行 Go 测试（宿主机 Go 版本不一定要与 guest 一致，但需要能跑 `go test ./integration`）
- 推荐安装/具备：
  - `ssh`（Windows SSH/Linus SSH 路径会用到；Linux 也支持纯 Go SSH 客户端）
  - `python3` + `pywinrm`（走 WinRM 时）
  - `git`（WinRM 路径需要 `git archive` 打包代码做 zip 分发）

### 3.2 Linux guest

- Go 版本满足 `go.mod`（本仓库为 Go `1.25.5`）
- 代码目录存在并可访问，例如 `/home/ci/src/trustinstall`
- 能以 root 执行系统信任库写入：
  - 推荐为测试用户配置免密 sudo（`sudo -n true` 可通过）
  - 或允许通过 stdin 向 `sudo -S` 提供密码（由宿主机注入）
- 推荐启用 SSH（便于宿主机触发执行与传输）；如果没有 SSH，至少保证 `utmctl exec` 可用

### 3.3 Windows guest

两种常见路径：

- SSH 路径（推荐）：Windows OpenSSH Server 启用，宿主机可 `ssh user@host`
- WinRM 路径：启用 WinRM HTTP 5985 + NTLM，宿主机可用 pywinrm 执行 PowerShell

其他要求：

- Go 版本满足 `go.mod`（本仓库为 Go `1.25.5`）
  - 本仓库 WinRM/utmctl 兜底脚本会在缺少 Go 时尝试下载并安装到 `C:\go`
- 代码目录存在，例如 `C:\src\trustinstall`
  - 若不存在，WinRM 路径支持宿主机启动临时 HTTP server，让 guest 拉取 zip 解压

### 3.4 macOS guest（可选）

用于 `all_platform` 三平台验证时，macOS guest 主要通过 SSH 运行（避开 utmctl 在部分后端的限制）。

## 4. 运行方式（按场景）

本仓库的集成测试入口在 `integration/`，用 build tags 区分平台或编排模式：

- `linux_integration`：Linux guest 内执行的系统级验证
- `windows_integration`：Windows guest 内执行的系统级验证
- `integration`：宿主机编排触发（含 UTM/SSH/WinRM/utmctl 相关测试）
- `all_platform`：宿主机编排三平台子测试（Linux/Windows/darwin）

### 4.1 UTM Linux：宿主机触发 guest 执行（SSH 优先，utmctl exec 兜底）

宿主机运行：

```bash
TRUSTINSTALL_LINUX_INTEGRATION=1 \
TRUSTINSTALL_LINUX_REPO_DIR=/home/ci/src/trustinstall \
go test ./integration -tags integration -run TestUTMLinuxIntegration -count=1 -v
```

常用可选环境变量：

- `TRUSTINSTALL_LINUX_SSH_HOST`：直接指定 Linux guest IP（可跳过 utmctl/ip 发现）
- `TRUSTINSTALL_LINUX_SSH_USER`：默认 `ci`
- `TRUSTINSTALL_LINUX_SSH_PORT`：默认 `22`
- `TRUSTINSTALL_LINUX_SSH_PASSWORD`：SSH 密码（CI 里默认兜底 `ci/cipass`）
- `TRUSTINSTALL_LINUX_SSH_KEY`：SSH 私钥路径（推荐）
- `TRUSTINSTALL_LINUX_SUDO_PASSWORD`：sudo 密码（若 `sudo -n` 不可用时兜底）
- `TRUSTINSTALL_UTM_LINUX_VM` / `TRUSTINSTALL_UTM_VM`：指定 UTM VM 标识

运行时行为摘要（便于理解失败/排障）：

- 若未提供 `TRUSTINSTALL_LINUX_SSH_HOST`，会优先用 `utmctl ip-address` 获取 IP
- 会等待 TCP 22 端口短暂就绪；不就绪且 utmctl 存在则 fallback 到 `utmctl exec`
- 若发现 guest 侧 `go.mod` 不存在，会从宿主机打包并上传仓库到 guest（避免 VM 预置代码的强依赖）
- 执行命令会以 root 运行：先尝试 `sudo -n`，失败则尝试 `sudo -S`（配合 stdin 密码）

### 4.2 UTM Windows：宿主机触发 guest 执行（SSH）

宿主机运行：

```bash
TRUSTINSTALL_WINDOWS_SSH_INTEGRATION=1 \
TRUSTINSTALL_WINDOWS_SSH_USER=youruser \
TRUSTINSTALL_WINDOWS_REPO_DIR='C:\\src\\trustinstall' \
go test ./integration -tags integration -run TestUTMWindowsSSHIntegration -count=1 -v
```

常用可选环境变量：

- `TRUSTINSTALL_WINDOWS_SSH_HOST`：直接指定 Windows guest IP
- `TRUSTINSTALL_WINDOWS_SSH_PORT`：默认 `22`
- `TRUSTINSTALL_WINDOWS_SSH_KEY`：SSH 私钥路径（推荐）
- `TRUSTINSTALL_WINDOWS_SSH_EXTRA_ARGS`：额外 ssh 参数（空格分隔）
- `TRUSTINSTALL_UTM_WINDOWS_VM` / `TRUSTINSTALL_UTM_VM`

兜底：若宿主机缺少 `ssh`，会尝试 `utmctl exec` 在 guest 内执行 PowerShell。

### 4.3 UTM Windows：宿主机触发 guest 执行（WinRM HTTP 5985 + NTLM）

宿主机运行：

```bash
TRUSTINSTALL_WINDOWS_WINRM_INTEGRATION=1 \
TRUSTINSTALL_WINDOWS_WINRM_USER='youruser' \
TRUSTINSTALL_WINDOWS_WINRM_PASSWORD='yourpassword' \
go test ./integration -tags integration -run TestUTMWindowsWinRMIntegration -count=1 -v
```

要点：

- 若未设置 `TRUSTINSTALL_WINDOWS_WINRM_ENDPOINT`，会尝试用 `utmctl ip-address` 发现 IP 并拼接 `http://<ip>:5985/wsman`
- 若未设置 `TRUSTINSTALL_WINDOWS_REPO_DIR`，宿主机会启动临时 HTTP 服务分发 `git archive` 生成的 zip；guest 用 `curl.exe` 下载解压后执行 `go test`
- 若 WinRM 不可用，会 fallback 到 `utmctl exec`（并 best-effort 启用 WinRM/放行防火墙），以便下一次能走 WinRM

额外环境变量：

- `TRUSTINSTALL_WINDOWS_REPO_DIR`：guest 内已有代码则优先使用
- `TRUSTINSTALL_WINDOWS_HOST_IP`：宿主机在 UTM 网段的 IP（自动识别失败时手动指定，例如 `192.168.64.1`）

### 4.4 三平台编排（all_platform）：宿主机一次触发 Linux/Windows/darwin guest

宿主机运行：

```bash
go test ./integration -tags all_platform -run TestMITMDynamicLeafCertificate -count=1 -v
```

只跑单个平台（子测试过滤）：

```bash
go test ./integration -tags all_platform -run '^TestMITMDynamicLeafCertificate/linux$' -count=1 -v
go test ./integration -tags all_platform -run '^TestMITMDynamicLeafCertificate/windows$' -count=1 -v
go test ./integration -tags all_platform -run '^TestMITMDynamicLeafCertificate/darwin$' -count=1 -v
```

常用环境变量：

- `TRUSTINSTALL_UTM_LINUX_VM` / `TRUSTINSTALL_UTM_WINDOWS_VM` / `TRUSTINSTALL_UTM_DARWIN_VM`
- `TRUSTINSTALL_LINUX_REPO_DIR` / `TRUSTINSTALL_WINDOWS_REPO_DIR` / `TRUSTINSTALL_DARWIN_REPO_DIR`
- `TRUSTINSTALL_DARWIN_SSH_HOST` / `TRUSTINSTALL_DARWIN_SSH_USER` / `TRUSTINSTALL_DARWIN_SSH_PORT`

macOS guest 的 IP 发现可兜底通过网段扫描与 DHCP leases（当 utmctl 不支持时）。

## 5. CI 落地建议（稳定性优先）

### 5.1 运行形态

UTM 及 `utmctl` 在一些情况下会受到 TCC/AppleEvent 权限、是否有登录会话等影响。

建议两种稳定落地方式：

1. CI agent 作为“已登录 GUI 用户”的 LaunchAgent 运行
   - `utmctl list/ip-address/exec` 成功率更高
   - 避免纯 SSH/no-login 场景下的权限与枚举限制
2. 若必须在无登录/SSH 会话跑：
   - 显式设置 `TRUSTINSTALL_UTM_*_VM` 与各 guest 的 `*_SSH_HOST`/`*_WINRM_ENDPOINT`
   - 依赖本仓库的“磁盘猜测 + 扫描兜底”能力

### 5.2 命名规范

强烈建议将 VM 命名与仓库约定对齐，降低自动选择成本：

- `ci-Linux`、`ci-Windows`、`ci-macOS`
- 或 `ci-os-linux`、`ci-os-windows`、`ci-os-macos`

### 5.3 观测与超时

- 统一在 CI 使用 `-v`，并在必要时对集成测试单独跑 `-count=1`
- Linux SSH 路径会做 heartbeat log（长跑任务 30s 输出一次进度）
- 若遇到 VM 冷启动慢：优先提升 VM 资源（CPU/RAM），其次延长外层 CI job timeout

## 6. 常见故障与排查

- `utmctl: no such file or directory`
  - 设置 `TRUSTINSTALL_UTMCTL` 或确认 UTM 安装路径
- `utmctl ip-address ... Operation not supported by the backend.`
  - 常见于 macOS guest：改用 `TRUSTINSTALL_DARWIN_SSH_HOST` 直连或让扫描/leases 兜底
- `OSStatus error -2700` / `Virtual machine is not running`
  - VM 未启动；本仓库会 best-effort `utmctl start` 并重试获取 IP
- SSH 连接失败（`connection refused`/`auth failed`）
  - 检查 guest 是否启用 sshd/OpenSSH Server
  - 优先使用 key：`TRUSTINSTALL_*_SSH_KEY`
  - Linux 可设置 `TRUSTINSTALL_LINUX_SSH_PASSWORD`；Windows SSH 当前脚本主要走 key + BatchMode
- Linux sudo 失败
  - 推荐配置免密 sudo（`sudo -n true` 可通过）
  - 或设置 `TRUSTINSTALL_LINUX_SUDO_PASSWORD` 允许 `sudo -S` 兜底
- WinRM 不通（5985 连接失败/认证失败）
  - 确认 WinRM 已启用、允许 NTLM、Windows 防火墙放行 5985
  - 确认宿主机已安装 `pywinrm`
  - 兜底用 `utmctl exec` 先在 guest 内 `Enable-PSRemoting` 并添加防火墙规则

## 7. 安全注意事项

- 不要在日志中打印明文密码（本仓库的日志已尽量避免输出敏感信息）
- CI 中优先使用 SSH key/受限账号，并尽量缩小 VM 网络可达范围
- 该方案会在 guest 中执行“修改系统信任库”的测试，务必在隔离环境与可控 VM 上使用

