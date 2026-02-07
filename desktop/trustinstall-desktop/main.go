package main

import (
	"context"
	"embed"
	_ "embed"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/LubyRuffy/trustinstall"
	"github.com/LubyRuffy/trustinstall/desktop/trustinstall-desktop/internal/api"
	"github.com/LubyRuffy/trustinstall/desktop/trustinstall-desktop/internal/cli"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// Wails uses Go's `embed` package to embed the frontend files into the binary.
// Any files in the frontend/dist folder will be embedded into the binary and
// made available to the frontend.
// See https://pkg.go.dev/embed for more information.

//go:embed all:frontend/dist
var assets embed.FS

type realInstaller struct{}

func (realInstaller) InstallCA(dir, fileBaseName, commonName string, deleteSame bool) error {
	ti, err := trustinstall.New(trustinstall.Options{
		Dir:          dir,
		FileBaseName: fileBaseName,
		CommonName:   commonName,
		DeleteSame:   &deleteSame,
	})
	if err != nil {
		return err
	}
	return ti.InstallCA()
}

func (realInstaller) UninstallCA(dir, fileBaseName, commonName string, deleteLocal bool) (int, string, string, error) {
	ti, err := trustinstall.New(trustinstall.Options{
		Dir:          dir,
		FileBaseName: fileBaseName,
		CommonName:   commonName,
	})
	if err != nil {
		return 0, "", "", err
	}
	res, err := ti.UninstallCA(deleteLocal)
	if err != nil {
		return 0, "", "", err
	}
	return res.Deleted, res.CertPath, res.KeyPath, nil
}

// main function serves as the application's entry point. It initializes the application, creates a window,
// and starts a goroutine that emits a time-based event every second. It subsequently runs the application and
// logs any error that might occur.
func main() {
	parsed, err := cli.Parse(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	if parsed.InstallCA != nil {
		res, err := cli.RunInstallCA(realInstaller{}, *parsed.InstallCA)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("完成。\n")
		fmt.Printf("dir: %s\n", res.Dir)
		fmt.Printf("fileBaseName: %s\n", res.FileBaseName)
		fmt.Printf("commonName: %s\n", res.CommonName)
		fmt.Printf("cert: %s\n", res.CertPath)
		fmt.Printf("key: %s\n", res.KeyPath)
		fmt.Printf("attempts: %d\n", res.Attempts)
		return
	}

	if parsed.UninstallCA != nil {
		res, err := cli.RunUninstallCA(realInstaller{}, *parsed.UninstallCA)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("完成。\n")
		fmt.Printf("commonName: %s\n", res.CommonName)
		fmt.Printf("deleted: %d\n", res.Deleted)
		if res.CertPath != "" {
			fmt.Printf("local cert removed: %s\n", res.CertPath)
		}
		if res.KeyPath != "" {
			fmt.Printf("local key removed: %s\n", res.KeyPath)
		}
		return
	}

	apiSrv, err := api.Start(api.Options{
		Addr:            parsed.APIAddr,
		FallbackPorts:   parsed.APIFallbackPorts,
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    30 * time.Second,
		ShutdownTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Wails application by providing the necessary options.
	// Variables 'Name' and 'Description' are for application metadata.
	// 'Assets' configures the asset server with the 'FS' variable pointing to the frontend files.
	// 'Bind' is a list of Go struct instances. The frontend has access to the methods of these instances.
	// 'Mac' options tailor the application when running an macOS.
	app := application.New(application.Options{
		Name:        "trustinstall-desktop",
		Description: "验证 trustinstall 安装并设置信任证书",
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
		OnShutdown: func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = apiSrv.Shutdown(ctx)
		},
	})

	// Create a new window with the necessary options.
	// 'Title' is the title of the window.
	// 'Mac' options tailor the window when running on macOS.
	// 'BackgroundColour' is the background colour of the window.
	// 'URL' is the URL that will be loaded into the webview.
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title: "trustinstall Desktop",
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(27, 38, 54),
		URL:              "/",
	})

	// Run the application. This blocks until the application has been exited.
	err = app.Run()

	// If an error occurred while running the application, log it and exit.
	if err != nil {
		log.Fatal(err)
	}
}
