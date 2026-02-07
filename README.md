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

Linux/Windows 下同样支持 `InstallCA/UninstallCA`（底层依赖 `github.com/smallstep/truststore` 写入系统信任库，通常需要管理员权限）。

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
