package cli

import (
	"flag"
)

type InstallCAOptions struct {
	Dir          string
	FileBaseName string
	CommonName   string
	DeleteSame   bool
}

type UninstallCAOptions struct {
	CommonName  string
	DeleteLocal bool

	Dir          string
	FileBaseName string
}

type Parsed struct {
	InstallCA   *InstallCAOptions
	UninstallCA *UninstallCAOptions

	APIAddr          string
	APIFallbackPorts int
}

func Parse(args []string) (Parsed, error) {
	fs := flag.NewFlagSet("trustinstall-desktop", flag.ContinueOnError)

	var out Parsed
	var installCA bool
	var uninstallCA bool

	fs.BoolVar(&installCA, "install-ca", false, "仅执行安装/设置信任 CA（需要管理员权限），不启动 GUI")
	fs.BoolVar(&uninstallCA, "uninstall-ca", false, "仅执行删除系统证书（需要管理员权限），不启动 GUI")
	fs.StringVar(&out.APIAddr, "api-addr", "127.0.0.1:34115", "本地 API 监听地址")
	fs.IntVar(&out.APIFallbackPorts, "api-fallback-ports", 10, "当端口占用时，向后尝试的端口数量")

	var caDir string
	var caName string
	var caCommonName string
	var deleteSame bool
	var deleteLocal bool

	fs.StringVar(&caDir, "ca-dir", "", "CA 文件目录（默认 ~/.trustinstall）")
	fs.StringVar(&caName, "ca-name", "trustinstall-ca", "CA 文件名前缀（生成 .crt/.key）")
	fs.StringVar(&caCommonName, "ca-common-name", "trustinstall-ca", "CA 证书 CommonName")
	fs.BoolVar(&deleteSame, "delete-same", true, "删除系统中与本地 CA 不一致的同名证书")
	fs.BoolVar(&deleteLocal, "delete-local", true, "删除本地 .crt/.key 文件（配合 -uninstall-ca 使用）")

	if err := fs.Parse(args); err != nil {
		return Parsed{}, err
	}

	if installCA && uninstallCA {
		return Parsed{}, flag.ErrHelp
	}

	if installCA {
		out.InstallCA = &InstallCAOptions{
			Dir:          caDir,
			FileBaseName: caName,
			CommonName:   caCommonName,
			DeleteSame:   deleteSame,
		}
	}

	if uninstallCA {
		out.UninstallCA = &UninstallCAOptions{
			CommonName:   caCommonName,
			DeleteLocal:  deleteLocal,
			Dir:          caDir,
			FileBaseName: caName,
		}
	}

	return out, nil
}
