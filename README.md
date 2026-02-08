# trustinstall

一个基于 [`github.com/smallstep/truststore`](https://github.com/smallstep/truststore) 的最小封装，用于：

- 生成自签名根证书（CA）
- 安装到 macOS 系统钥匙串并设置为“始终信任”
- 基于该 CA 动态签发指定 host 的叶子证书（用于 HTTPS MITM/调试）

注意：本项目仅面向开发/调试用途。拦截与解密他人流量可能违法，请确保只在你有权限的环境中使用。

## 安装

```bash
go get github.com/LubyRuffy/trustinstall
```

## Package 接口

### New（推荐）

为了减少重复参数传递，可以先创建一个带默认值的客户端，然后调用方法：

```go
ti, err := trustinstall.New(trustinstall.Options{
  Dir:          "~/.trustinstall",
  FileBaseName: "trustinstall-ca",
  CommonName:   "trustinstall-ca",
  // DeleteSame: 可选，默认 true
})
if err != nil { /* ... */ }

if err := ti.InstallCA(); err != nil { /* ... */ }
certPEM, keyPEM, err := ti.LeafCertificate("example.com")
_, _ = certPEM, keyPEM
_, _ = ti.UninstallCA(true)
```

### Client.InstallCA

```go
func (c *Client) InstallCA() error
```

- 如果 `dir` 下不存在 `<fileBaseName>.crt/.key`：生成自签名根 CA 并写入文件
- 如果文件存在：复用并校验“证书与私钥匹配”
- 然后检查系统钥匙串中是否已安装同名（CommonName 相同）的证书：
  - 未安装：安装到系统证书并写入“始终信任”（需要 sudo）
  - 已安装：检查是否已设置为“始终信任”，如果没有则补齐信任设置（需要 sudo）
  - 若系统中存在多个同名证书且 `DeleteSame=true`：删除与本地证书文件不一致的系统证书

文件输出：

- `<dir>/<fileBaseName>.crt`（PEM）
- `<dir>/<fileBaseName>.key`（PEM, PKCS#8）

#### macOS GUI 场景说明（自动）

在 macOS 新版本中，如果当前进程没有可交互的 TTY（常见于 GUI 应用或 `wails3 dev` 这类场景），直接执行需要提权的 `sudo security ...` 可能会卡在 `Password:` 或报错（例如 “no user interaction was possible”）。

本库在 macOS 下会自动检测当前是否存在可交互 TTY：

- 有 TTY：直接在当前进程执行 `sudo security ...`
- 无 TTY：自动弹出一个新的 Terminal 窗口执行需要提权的命令，让用户在该窗口里输入管理员密码；当前调用会轮询等待安装/信任生效

#### Linux/Windows 说明

Linux 下支持 `InstallCA/UninstallCA`（底层依赖 `github.com/smallstep/truststore` 写入系统信任库，通常需要管理员权限）。

Windows 下同样支持 `InstallCA/UninstallCA`，但默认写入 **系统** 根证书存储（`Cert:\LocalMachine\Root`），通常需要管理员权限。

说明：部分 Windows 环境会禁用/不支持写入用户根证书存储（`Cert:\CurrentUser\Root`，可能出现 `ERROR_NOT_SUPPORTED`），因此本库在 Windows 上选择写入 `LocalMachine\Root` 以保证一致性。

### Client.LeafCertificate

```go
func (c *Client) LeafCertificate(host string) (certPEM, keyPEM []byte, err error)
```

基于 `InstallCA` 生成的 CA 私钥，动态生成 `host` 的叶子证书：

- `host` 是域名：写入 `DNS SAN`
- `host` 是 IP：写入 `IP SAN`
- 返回 `certPEM` 为 `leaf + CA` 的证书链，`keyPEM` 为叶子私钥（PKCS#8）

### Client.UninstallCA

```go
func (c *Client) UninstallCA(deleteLocal bool) (UninstallCAResult, error)
```

- 删除系统钥匙串里 `CommonName` 匹配的证书（可能需要管理员权限）
- `deleteLocal=true` 时同时删除本地 `<dir>/<fileBaseName>.crt/.key`（便于重新生成）

## 最简单的 HTTPS 明文代理（cmd/proxy）

`cmd/proxy` 是一个最小的 HTTP 代理服务器：

- 普通 HTTP：转发并打印请求/响应（明文）
- HTTPS：支持 `CONNECT` 并进行 MITM，打印解密后的请求/响应明文

### 运行

```bash
go run ./cmd/proxy -listen 127.0.0.1:8080 -ca-dir ~/.trustinstall -ca-name trustinstall-ca -ca-common-name trustinstall-ca -delete-same=true
```

首次运行会调用系统命令安装 CA 并设置“始终信任”，macOS 通常会要求输入管理员密码（因为底层会调用 `sudo security ...`）。

### 用 curl 验证（打印 HTTPS 明文）

```bash
curl -x http://127.0.0.1:8080 https://example.com/ -v
```

如果你的 curl 没有使用系统钥匙串或仍然不信任该 CA，可以临时指定 CA 文件：

```bash
curl -x http://127.0.0.1:8080 --cacert ~/.trustinstall/trustinstall-ca.crt https://example.com/ -v
```

## 命令行工具（cmd/trustinstall）

用于快速在终端里验证“安装并设置信任/删除证书”：

```bash
go run ./cmd/trustinstall -install-ca -ca-common-name trustinstall-ca -ca-name trustinstall-ca -delete-same=true
go run ./cmd/trustinstall -uninstall-ca -ca-common-name trustinstall-ca -delete-local=true
```

## 桌面验证程序（desktop/trustinstall-desktop）

这是一个 Wails3 桌面程序，用于在 GUI 里验证：

- 安装并设置信任 CA
- 删除系统证书（可选删除本地 `.crt/.key`）

运行（开发）：

```bash
cd desktop/trustinstall-desktop
wails3 dev
```

更多说明见：`desktop/trustinstall-desktop/README.md`。

## Docker 集成测试（Linux 系统信任库）

本仓库包含一个“调用本地 Docker”的集成测试，用于在 Linux 容器里真实验证 `InstallCA/UninstallCA` 的系统信任库流程。

运行方式（宿主机需要安装并启动 Docker）：

```bash
TRUSTINSTALL_INTEGRATION=1 go test ./... -tags integration -run TestDockerLinuxIntegration -count=1
```

## Docker 集成测试（Windows via dockur/windows）

使用 [`dockur/windows`](https://github.com/dockur/windows) 在 Linux + KVM 上启动 Windows VM，在 VM 内运行 `go test` 以验证：

- `InstallCA` 安装成功
- `IsCertTrusted` 为 true（可信成功）
- `UninstallCA` 卸载成功并能再次扫描为 0

前置条件：

- 宿主机必须是 Linux
- 需要 KVM（`/dev/kvm` 存在）
- 需要 Docker，并允许容器访问 `/dev/kvm` 与 `/dev/net/tun`

运行：

```bash
TRUSTINSTALL_WINDOWS_INTEGRATION=1 go test ./integration -tags integration -run TestDockerWindowsDockurIntegration -count=1 -v
```

可选环境变量（调参）：

- `TRUSTINSTALL_DOCKUR_WINDOWS_IMAGE`：默认 `dockurr/windows:latest`
- `TRUSTINSTALL_DOCKUR_WINDOWS_VERSION`：默认 `11`
- `TRUSTINSTALL_DOCKUR_WINDOWS_RAM`：默认 `6G`
- `TRUSTINSTALL_DOCKUR_WINDOWS_CPU`：默认 `4`

## 集成测试（UTM Windows via SSH，适用于 Apple Silicon）

在 Apple Silicon 上，更推荐用 UTM 跑一个 Windows VM（Windows ARM64），然后通过 SSH 远程触发 VM 内执行 `go test` 完成集成测试。

更完整的“UTM 调用 VM 完成跨平台集成测试”技术方案文档见：`docs/utm-vm-cross-platform-integration-test.md`。

前置条件：

- Windows VM 内安装并启用 OpenSSH Server（确保 macOS 能 `ssh user@host` 连接）
- Windows VM 内已安装 Go（需满足本仓库 `go.mod` 的 Go 版本）
- Windows VM 内有本仓库代码（例如 `C:\src\trustinstall`）

运行（在 macOS 上）：

```bash
TRUSTINSTALL_WINDOWS_SSH_INTEGRATION=1 \
TRUSTINSTALL_WINDOWS_SSH_USER=youruser \
TRUSTINSTALL_WINDOWS_REPO_DIR='C:\\src\\trustinstall' \
go test ./integration -tags integration -run TestUTMWindowsSSHIntegration -count=1 -v
```

如果不设置 `TRUSTINSTALL_WINDOWS_SSH_HOST`，测试会尝试通过 `utmctl ip-address` 自动获取 IP（VM 标识优先来自 `TRUSTINSTALL_UTM_WINDOWS_VM`/`TRUSTINSTALL_UTM_VM`，否则会按下文 CI 约定自动选择）。

可选环境变量：

- `TRUSTINSTALL_WINDOWS_SSH_PORT`：默认 22
- `TRUSTINSTALL_WINDOWS_SSH_KEY`：ssh 私钥路径（推荐）
- `TRUSTINSTALL_WINDOWS_SSH_EXTRA_ARGS`：额外 ssh 参数（空格分隔）
- `TRUSTINSTALL_UTM_WINDOWS_VM`：UTM VM 标识（完整名称或 UUID），用于自动获取 IP
- `TRUSTINSTALL_UTMCTL`：utmctl 路径覆盖（默认 `/Applications/UTM.app/Contents/MacOS/utmctl`）

CI 约定：

- 若未设置 `TRUSTINSTALL_UTM_WINDOWS_VM`，会优先从 `utmctl list` 里自动选择名称以 `ci-os` 或 `ci-` 开头的 VM，并优先选择名称包含 Windows 的 VM（例如 `ci-Windows`）。
- 若 `utmctl list` 在 SSH/无登录场景不可用，会尝试从 UTM 默认 Documents 目录中识别常用名称（例如 `~/Library/Containers/com.utmapp.UTM/Data/Documents/ci-Windows.utm`）。
- 若宿主机缺少 `ssh` 或 `pywinrm`，测试会自动 fallback 到 `utmctl exec` 在 guest 内执行（并做 best-effort 的 WinRM 配置）。

## 集成测试（UTM Linux via SSH/utmctl exec，适用于 Apple Silicon）

当你希望在 UTM 里的 Linux VM（例如 `ci-Linux`）上跑 `linux_integration`（需要 root 修改系统信任库）时，可通过宿主机触发 VM 内执行 `go test` 完成集成测试。

前置条件：

- Linux VM 内已安装 Go（需满足本仓库 `go.mod` 的 Go 版本）
- Linux VM 内有本仓库代码（例如 `/home/ci/src/trustinstall`）
- `linux_integration` 需要 root：建议为测试用户配置免密 sudo（`sudo -n true` 可通过）

运行（在 macOS 上）：

```bash
TRUSTINSTALL_LINUX_INTEGRATION=1 \
TRUSTINSTALL_LINUX_REPO_DIR=/home/ci/src/trustinstall \
go test ./integration -tags integration -run TestUTMLinuxIntegration -count=1 -v
```

如果不设置 `TRUSTINSTALL_LINUX_SSH_HOST`，测试会尝试通过 `utmctl ip-address` 自动获取 IP（VM 标识优先来自 `TRUSTINSTALL_UTM_LINUX_VM`/`TRUSTINSTALL_UTM_VM`，否则会按 CI 约定自动选择）。

可选环境变量：

- `TRUSTINSTALL_LINUX_SSH_HOST`：Linux VM IP
- `TRUSTINSTALL_LINUX_SSH_USER`：默认 `ci`
- `TRUSTINSTALL_LINUX_SSH_PORT`：默认 22
- `TRUSTINSTALL_LINUX_SSH_KEY`：ssh 私钥路径（推荐）
- `TRUSTINSTALL_LINUX_SSH_EXTRA_ARGS`：额外 ssh 参数（空格分隔）
- `TRUSTINSTALL_UTM_LINUX_VM`：UTM VM 标识（完整名称或 UUID），用于自动获取 IP
- `TRUSTINSTALL_UTMCTL`：utmctl 路径覆盖（默认 `/Applications/UTM.app/Contents/MacOS/utmctl`）

CI 约定：

- 若未设置 `TRUSTINSTALL_UTM_LINUX_VM`，会优先从 `utmctl list` 里自动选择名称以 `ci-os` 或 `ci-` 开头的 VM，并优先选择名称包含 Linux/Ubuntu/Debian 的 VM（例如 `ci-Linux`）。
- 若 `utmctl list` 在 SSH/无登录场景不可用，会尝试从 UTM 默认 Documents 目录中识别常用名称（例如 `~/Library/Containers/com.utmapp.UTM/Data/Documents/ci-Linux.utm`）。
- 若宿主机缺少 `ssh`，测试会自动 fallback 到 `utmctl exec` 在 guest 内执行。

## 集成测试（UTM Windows via WinRM(HTTP 5985 + NTLM)，适用于 Apple Silicon）

如果你更倾向用 WinRM，也可以通过 NTLM 在 5985 端口执行远程 PowerShell 来跑集成测试。

前置条件：

- Windows VM 已启用 WinRM（HTTP 5985）并允许 NTLM 认证
- Windows VM 能访问宿主机的 UTM 网段地址（默认会启动一个临时 HTTP 服务，用于让 VM 拉取本仓库 zip；必要时可设置 `TRUSTINSTALL_WINDOWS_HOST_IP`）
- Windows VM 内如果未安装 Go，测试会尝试从 `go.dev` 下载并安装到 `C:\go`（需能访问外网）
- macOS 需要 `python3`，并安装 `pywinrm`（包名：`pywinrm`）

运行（在 macOS 上）：

```bash
TRUSTINSTALL_WINDOWS_WINRM_INTEGRATION=1 \
TRUSTINSTALL_WINDOWS_WINRM_USER='youruser' \
TRUSTINSTALL_WINDOWS_WINRM_PASSWORD='yourpassword' \
go test ./integration -tags integration -run TestUTMWindowsWinRMIntegration -count=1 -v
```

可选环境变量：

- `TRUSTINSTALL_WINDOWS_REPO_DIR`：如果 Windows VM 里已存在本仓库代码，可指定路径（优先使用该路径，不再走 zip 分发）
- `TRUSTINSTALL_WINDOWS_HOST_IP`：宿主机在 UTM 网段的 IP（自动识别失败时手动指定，例如 `192.168.64.1`）

如果不设置 `TRUSTINSTALL_WINDOWS_WINRM_ENDPOINT`，测试会尝试通过 `utmctl ip-address` 自动获取 IP 并拼出 `http://<ip>:5985/wsman`（VM 标识优先来自 `TRUSTINSTALL_UTM_WINDOWS_VM`/`TRUSTINSTALL_UTM_VM`，否则会按上文 CI 约定自动选择）。

默认启用规则（CI）：

- 在 hostname 以 `ci` 或 `ci-` 开头、或环境变量 `CI` 存在时，即使不设置 `TRUSTINSTALL_WINDOWS_WINRM_INTEGRATION` 也会默认运行。
- 如需关闭：设置 `TRUSTINSTALL_WINDOWS_WINRM_INTEGRATION=0`（或 `false/no/off`）。

## 集成测试（HTTPS MITM 动态 Leaf 证书）

该集成测试会启动一个本地 HTTP 代理（支持 `CONNECT`），对指定 HTTPS 站点进行 MITM：

- 代理侧用 `Client.LeafCertificate(host)` 动态签发叶子证书
- Go `http.Client` 走代理访问 `https://ip.bmh.im/c`
- 断言代理侧能拿到解密后的明文请求/响应（至少包含 URL 和响应 body）

### 本机集成测试（默认）

运行（需要外网访问 `ip.bmh.im`）：

```bash
TRUSTINSTALL_INTEGRATION=1 \
go test ./integration -tags integration -run TestMITMDynamicLeafCertificate -count=1 -v
```

### 三平台集成测试（all_platform，经由 UTM）

当启用 `all_platform` tag 时，同一个测试会在 macOS 宿主机上通过 UTM 分别在 Linux/Windows/macOS guest 内执行：

- Linux guest：`utmctl exec`
- Windows guest：`utmctl exec`
- macOS guest：通过 SSH 执行（避免 `utmctl ip-address/exec` 在部分后端返回 “Operation not supported by the backend.” 或 AppleEvent/OSStatus 错误）

运行（在 macOS 宿主机上）：

```bash
go test ./integration -tags all_platform -run TestMITMDynamicLeafCertificate -count=1 -v
```

只跑单个平台（使用子测试名过滤）：

```bash
go test ./integration -tags all_platform -run '^TestMITMDynamicLeafCertificate/linux$' -count=1 -v
go test ./integration -tags all_platform -run '^TestMITMDynamicLeafCertificate/windows$' -count=1 -v
go test ./integration -tags all_platform -run '^TestMITMDynamicLeafCertificate/darwin$' -count=1 -v
```

常用可选环境变量（不设置也会尝试默认路径/自动发现）：

- `TRUSTINSTALL_UTM_LINUX_VM` / `TRUSTINSTALL_UTM_WINDOWS_VM` / `TRUSTINSTALL_UTM_DARWIN_VM`：指定 UTM VM 标识（名称或 UUID）
- `TRUSTINSTALL_LINUX_REPO_DIR` / `TRUSTINSTALL_WINDOWS_REPO_DIR` / `TRUSTINSTALL_DARWIN_REPO_DIR`：guest 内仓库路径覆盖（默认会尝试若干常见路径并校验 `go.mod`）
- `TRUSTINSTALL_DARWIN_SSH_HOST` / `TRUSTINSTALL_DARWIN_SSH_USER` / `TRUSTINSTALL_DARWIN_SSH_PORT`：macOS guest SSH 连接参数（默认 user=ci, port=22）
- `TRUSTINSTALL_DARWIN_DISCOVERY_CIDRS`：macOS guest IP 端口扫描网段（默认 `192.168.64.0/24`，扫描 22 端口）
- `TRUSTINSTALL_DARWIN_DHCP_NAMES`：从宿主机 `/var/db/dhcpd_leases` 中匹配的 hostname 列表（逗号分隔），用于在 utmctl ip-address 不支持时定位 macOS guest IP（默认 `cidexuniji,ci-macOS`）

## 关于 SSL Pinning / 证书绑定（后续支持说明）

很多 App/SDK 会做“证书绑定”（SSL Pinning），常见形式包括：

- 固定服务端证书公钥/指纹（SPKI pin / cert pin）
- 固定整条证书链或中间证书
- 在应用内自带一套信任库，不使用系统证书存储

这类场景下，MITM 代理即使在系统中安装了自签名 CA，客户端也可能仍然会拒绝连接（握手失败或校验失败）。

后续准备支持的方向（先写文档，后续再实现）：

1. `passthrough` 模式：不做 MITM，仅转发 TCP（无法打印 HTTPS 明文，但可保证可用性）
2. `upstream pin mirror`（可选）：配置目标站点的 pin 信息，用于诊断“为什么 pinning 失败”（仍不能无修改绕过）
3. `导出/分发 CA`：便于将 CA 导入到应用自身的信任库（若应用允许）
4. `可插拔 hook` 方案说明：例如 Frida/Objection 等手段（属于应用侧改造/调试范畴，不在本库直接实现）

### SecTrustEvaluateWithError Hook（后续实现思路）

在 iOS/macOS 的部分应用里，TLS 校验最终会走到 Security.framework 的 `SecTrustEvaluateWithError`。当应用使用系统验证路径时，可以通过“hook 该函数”来观察/修改证书校验结果，从而绕过或诊断部分证书绑定行为。

后续计划补充的内容（先写文档，后续再实现/落地脚本）：

1. 动态 hook（推荐用于调试）：通过 Frida 等工具 hook `SecTrustEvaluateWithError`，打印被校验证书链与域名，并在满足条件时强制返回成功
2. 仅观测模式：不改返回值，只记录失败原因，定位是 pinning、链不完整还是域名不匹配
3. 条件化策略：仅对指定 bundle id/进程名、指定域名、或指定证书指纹生效，避免影响其他网络请求

注意：这类手段属于“应用侧调试/逆向”范畴，可能违反应用条款或法律法规；请仅在你有权限的设备与目标上使用。
