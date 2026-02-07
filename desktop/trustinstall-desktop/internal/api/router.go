package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func newRouter(mgr Manager) http.Handler {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(cors())

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	api := &apiHandlers{mgr: mgr}
	r.POST("/api/installca", api.installCA)
	r.POST("/api/uninstallca", api.uninstallCA)

	return r
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		// Keep this simple: local-only API, allow any origin for desktop/dev.
		if strings.TrimSpace(origin) != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
		} else {
			c.Header("Access-Control-Allow-Origin", "*")
		}
		c.Header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		c.Header("Access-Control-Max-Age", "600")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
