//go:build integration || all_platform

package integration

// 说明：
// - 默认（仅启用 integration tag）时：测试按“本机集成测试”执行。
// - 启用 all_platform tag 时：部分测试会在 macOS 宿主机上通过 UTM 分别在 Linux/Windows/macOS guest 内执行，
//   用于做三平台验证（避免在宿主机重复安装系统证书等副作用）。
