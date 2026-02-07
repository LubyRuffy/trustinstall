package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type uninstallCARequest struct {
	CommonName   string `json:"commonName"`
	DeleteLocal  bool   `json:"deleteLocal"`
	Dir          string `json:"dir"`
	FileBaseName string `json:"fileBaseName"`
}

type uninstallCAResponse struct {
	OK      bool   `json:"ok"`
	Deleted int    `json:"deleted"`
	Note    string `json:"note,omitempty"`
}

func (a *apiHandlers) uninstallCA(c *gin.Context) {
	var req uninstallCARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "请求 JSON 无效: " + err.Error()})
		return
	}

	cn := strings.TrimSpace(req.CommonName)
	if cn == "" {
		cn = "trustinstall-ca"
	}

	deleted, certPath, keyPath, err := a.mgr.UninstallCA(req.Dir, req.FileBaseName, cn, req.DeleteLocal)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	note := ""
	if req.DeleteLocal && (certPath != "" || keyPath != "") {
		note = "已尝试删除本地 .crt/.key 文件。"
	}

	c.JSON(http.StatusOK, uninstallCAResponse{
		OK:      true,
		Deleted: deleted,
		Note:    note,
	})
}
