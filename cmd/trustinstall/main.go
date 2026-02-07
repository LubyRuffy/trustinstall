package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/LubyRuffy/trustinstall"
)

func main() {
	fs := flag.NewFlagSet("trustinstall", flag.ExitOnError)

	var installCA bool
	var uninstallCA bool

	var caDir string
	var caName string
	var caCommonName string
	var deleteSame bool
	var deleteLocal bool

	fs.BoolVar(&installCA, "install-ca", false, "仅执行安装/设置信任 CA（需要管理员权限）")
	fs.BoolVar(&uninstallCA, "uninstall-ca", false, "仅执行删除系统证书（需要管理员权限）")

	fs.StringVar(&caDir, "ca-dir", "", "CA 文件目录（默认 ~/.trustinstall）")
	fs.StringVar(&caName, "ca-name", "trustinstall-ca", "CA 文件基名（生成 .crt/.key）")
	fs.StringVar(&caCommonName, "ca-common-name", "trustinstall-ca", "CA 证书 CommonName")
	fs.BoolVar(&deleteSame, "delete-same", true, "系统中存在多个同名证书时，是否删除与本地证书不一致的那些（仅安装时生效）")
	fs.BoolVar(&deleteLocal, "delete-local", true, "删除本地 .crt/.key 文件（配合 -uninstall-ca 使用）")

	_ = fs.Parse(os.Args[1:])

	if installCA && uninstallCA {
		fs.Usage()
		os.Exit(2)
	}
	if !installCA && !uninstallCA {
		fs.Usage()
		os.Exit(2)
	}

	if installCA {
		ti, err := trustinstall.New(trustinstall.Options{
			Dir:          caDir,
			FileBaseName: caName,
			CommonName:   caCommonName,
			DeleteSame:   &deleteSame,
		})
		if err != nil {
			log.Fatal(err)
		}
		if err := ti.InstallCA(); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("完成。\n")
		fmt.Printf("dir: %s\n", ti.Dir())
		fmt.Printf("fileBaseName: %s\n", ti.FileBaseName())
		fmt.Printf("commonName: %s\n", ti.CommonName())
		return
	}

	ti, err := trustinstall.New(trustinstall.Options{
		Dir:          caDir,
		FileBaseName: caName,
		CommonName:   caCommonName,
	})
	if err != nil {
		log.Fatal(err)
	}
	res, err := ti.UninstallCA(deleteLocal)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("完成。\n")
	fmt.Printf("commonName: %s\n", ti.CommonName())
	fmt.Printf("deleted: %d\n", res.Deleted)
	if res.CertPath != "" {
		fmt.Printf("local cert removed: %s\n", res.CertPath)
	}
	if res.KeyPath != "" {
		fmt.Printf("local key removed: %s\n", res.KeyPath)
	}
}
