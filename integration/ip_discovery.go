//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func discoverWindowsVMIPv4ByScan(port int) (string, error) {
	// Allow override for special networks.
	cidrs := strings.TrimSpace(os.Getenv("TRUSTINSTALL_WINDOWS_DISCOVERY_CIDRS"))
	if cidrs == "" {
		// UTM/Virtualization.framework commonly uses this shared network.
		cidrs = "192.168.64.0/24"
	}

	var networks []string
	for _, item := range strings.Split(cidrs, ",") {
		s := strings.TrimSpace(item)
		if s != "" {
			networks = append(networks, s)
		}
	}
	if len(networks) == 0 {
		return "", fmt.Errorf("TRUSTINSTALL_WINDOWS_DISCOVERY_CIDRS 为空")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type candidate struct {
		ip string
	}

	var cands []candidate
	for _, cidr := range networks {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return "", fmt.Errorf("解析 CIDR 失败: %s: %w", cidr, err)
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			continue
		}
		hosts := 1 << uint32(32-ones)
		// Avoid accidental huge scans.
		if hosts > 1024 {
			return "", fmt.Errorf("CIDR 过大（%s），请缩小或显式设置 TRUSTINSTALL_WINDOWS_DISCOVERY_CIDRS", cidr)
		}

		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); ip = nextIPv4(ip) {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			cands = append(cands, candidate{ip: ip4.String()})
		}
	}

	if len(cands) == 0 {
		return "", fmt.Errorf("未生成任何扫描候选 IP")
	}

	sem := make(chan struct{}, 64)
	found := make(chan string, 1)
	var wg sync.WaitGroup

	for _, c := range cands {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			d := net.Dialer{Timeout: 200 * time.Millisecond}
			conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
			if err == nil {
				_ = conn.Close()
				select {
				case found <- ip:
				default:
				}
			}
		}(c.ip)
	}

	go func() {
		wg.Wait()
		close(found)
	}()

	if ip, ok := <-found; ok && strings.TrimSpace(ip) != "" {
		return ip, nil
	}
	return "", fmt.Errorf("扫描未发现可用目标（port=%d, cidrs=%s）", port, strings.Join(networks, ","))
}

func discoverLinuxVMIPv4ByScan(port int) (string, error) {
	// Allow override for special networks.
	cidrs := strings.TrimSpace(os.Getenv("TRUSTINSTALL_LINUX_DISCOVERY_CIDRS"))
	if cidrs == "" {
		// UTM/Virtualization.framework commonly uses this shared network.
		cidrs = "192.168.64.0/24"
	}

	var networks []string
	for _, item := range strings.Split(cidrs, ",") {
		s := strings.TrimSpace(item)
		if s != "" {
			networks = append(networks, s)
		}
	}
	if len(networks) == 0 {
		return "", fmt.Errorf("TRUSTINSTALL_LINUX_DISCOVERY_CIDRS 为空")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type candidate struct {
		ip string
	}

	var cands []candidate
	for _, cidr := range networks {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return "", fmt.Errorf("解析 CIDR 失败: %s: %w", cidr, err)
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			continue
		}
		hosts := 1 << uint32(32-ones)
		// Avoid accidental huge scans.
		if hosts > 1024 {
			return "", fmt.Errorf("CIDR 过大（%s），请缩小或显式设置 TRUSTINSTALL_LINUX_DISCOVERY_CIDRS", cidr)
		}

		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); ip = nextIPv4(ip) {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			cands = append(cands, candidate{ip: ip4.String()})
		}
	}

	if len(cands) == 0 {
		return "", fmt.Errorf("未生成任何扫描候选 IP")
	}

	sem := make(chan struct{}, 64)
	found := make(chan string, 1)
	var wg sync.WaitGroup

	for _, c := range cands {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			d := net.Dialer{Timeout: 200 * time.Millisecond}
			conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
			if err == nil {
				_ = conn.Close()
				select {
				case found <- ip:
				default:
				}
			}
		}(c.ip)
	}

	go func() {
		wg.Wait()
		close(found)
	}()

	if ip, ok := <-found; ok && strings.TrimSpace(ip) != "" {
		return ip, nil
	}
	return "", fmt.Errorf("扫描未发现可用目标（port=%d, cidrs=%s）", port, strings.Join(networks, ","))
}

func nextIPv4(ip net.IP) net.IP {
	ip = append(net.IP(nil), ip.To4()...)
	if ip == nil {
		return nil
	}
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
	return ip
}
