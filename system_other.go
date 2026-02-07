//go:build !darwin && !linux && !windows

package trustinstall

import "fmt"

func newSystemOps() (systemOps, error) {
	return nil, fmt.Errorf("当前系统不支持: 仅支持 macOS/Linux/Windows")
}
