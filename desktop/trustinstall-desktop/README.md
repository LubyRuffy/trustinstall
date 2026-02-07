# trustinstall-desktop

一个用于验证 `github.com/LubyRuffy/trustinstall` 的 Wails3 桌面程序：

- GUI：安装并设置信任 CA、删除系统证书（可选删除本地 `.crt/.key`）
- 本地 API：GUI 通过 `http://127.0.0.1:<port>/api/*` 调用后端（不依赖 Wails bindings）
- CLI：提供 `-install-ca/-uninstall-ca` 参数，便于纯终端验证

## macOS（GUI）提权说明

macOS 新版本在“无可交互 TTY”的 GUI 场景下，直接执行需要 `sudo` 的 `security` 命令可能会失败或卡在 `Password:`（例如 `SecTrustSettingsSetTrustSettings: ... no user interaction was possible`）。

本项目底层库 `trustinstall` 在 macOS 下会自动检测是否存在可交互 TTY：

- 有 TTY：直接在当前进程执行 `sudo security ...`
- 无 TTY：自动弹出一个新的 Terminal 窗口执行提权命令，让用户在该窗口输入管理员密码；当前调用会轮询等待安装/信任生效

因此，在 `wails3 dev` 或双击 `.app` 运行时，看到弹出 Terminal 属于预期行为。

## 运行（开发）

```bash
cd desktop/trustinstall-desktop
wails3 dev
```

GUI 会自动探测本地 API 地址（默认端口范围 `127.0.0.1:34115-34125`）。

## 构建（发布）

```bash
cd desktop/trustinstall-desktop
wails3 build
```

## 命令行模式（不启动 GUI）

```bash
cd desktop/trustinstall-desktop
go run . -install-ca -ca-common-name trustinstall-ca -ca-name trustinstall-ca -delete-same=true
```

删除系统证书（可选删除本地文件）：

```bash
cd desktop/trustinstall-desktop
go run . -uninstall-ca -ca-common-name trustinstall-ca -delete-local=true
```

更多参数：

```bash
cd desktop/trustinstall-desktop
go run . -h
```
