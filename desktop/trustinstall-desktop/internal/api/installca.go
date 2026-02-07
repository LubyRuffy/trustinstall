package api

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

type apiHandlers struct {
	mgr Manager
}

type installCARequest struct {
	Dir          string `json:"dir"`
	FileBaseName string `json:"fileBaseName"`
	CommonName   string `json:"commonName"`
	DeleteSame   bool   `json:"deleteSame"`
}

type installCAResponse struct {
	OK           bool   `json:"ok"`
	Dir          string `json:"dir"`
	FileBaseName string `json:"fileBaseName"`
	CommonName   string `json:"commonName"`
	CertPath     string `json:"certPath"`
	KeyPath      string `json:"keyPath"`
	Attempts     int    `json:"attempts"`
	Note         string `json:"note,omitempty"`
}

func (a *apiHandlers) installCA(c *gin.Context) {
	var req installCARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "请求 JSON 无效: " + err.Error()})
		return
	}

	dir := strings.TrimSpace(req.Dir)
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "获取用户目录失败: " + err.Error()})
			return
		}
		dir = filepath.Join(home, ".trustinstall")
	}
	fileBaseName := strings.TrimSpace(req.FileBaseName)
	if fileBaseName == "" {
		fileBaseName = "trustinstall-ca"
	}
	commonName := strings.TrimSpace(req.CommonName)
	if commonName == "" {
		commonName = "trustinstall-ca"
	}

	// 如果用户在 GUI 里修改了 commonName，但本地证书文件已存在，则默认复用旧证书（commonName 以文件为准）。
	// 这会让用户认为“修改不生效”。这里做一个更符合直觉的行为：
	// 当检测到本地已存在 CA 且 CN 与请求不一致时，自动删除本地 .crt/.key 让后续重新生成。
	certPath := filepath.Join(dir, fileBaseName+".crt")
	keyPath := filepath.Join(dir, fileBaseName+".key")
	var note string
	if b, err := os.ReadFile(certPath); err == nil {
		if block, _ := pem.Decode(b); block != nil && block.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" && cn != commonName {
					_ = os.Remove(certPath)
					_ = os.Remove(keyPath)
					note = "检测到本地 CA CommonName 变化，已自动删除旧的 .crt/.key 并重新生成。"
				}
			}
		}
	}

	attempts := 1
	if err := a.mgr.InstallCA(dir, fileBaseName, commonName, req.DeleteSame); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	// 返回实际写入的 CN（以文件为准）。
	actualCN := commonName
	if b, err := os.ReadFile(certPath); err == nil {
		if block, _ := pem.Decode(b); block != nil && block.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
					actualCN = cn
				}
			}
		}
	}

	c.JSON(http.StatusOK, installCAResponse{
		OK:           true,
		Dir:          dir,
		FileBaseName: fileBaseName,
		CommonName:   actualCN,
		CertPath:     certPath,
		KeyPath:      keyPath,
		Attempts:     attempts,
		Note:         note,
	})
}
