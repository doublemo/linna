package linna

import (
	"crypto/sha1"
	"fmt"
	"net"
	"net/http"

	"github.com/doublemo/linna/internal/logger"
	"github.com/doublemo/linna/internal/metrics"
	"github.com/gofrs/uuid"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

func NewWebsocketAcceptor(c Configuration, metric metrics.Metrics) func(http.ResponseWriter, *http.Request) {
	log := logger.StartupLogger()
	upgrader := &websocket.Upgrader{
		ReadBufferSize:  c.Api.ReadBufferSizeBytes,
		WriteBufferSize: c.Api.WriteBufferSizeBytes,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}

	sessionIdGen := uuid.NewGenWithHWAF(func() (net.HardwareAddr, error) {
		hash := NodeToHash(c.Name)
		return hash[:], nil
	})

	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			// http.Error is invoked automatically from within the Upgrade function.
			log.Debug("Could not upgrade to WebSocket", zap.Error(err))
			return
		}

		metric.CountWebsocketOpened(1)
		sessionID := uuid.Must(sessionIdGen.NewV1())
		fmt.Println(sessionID, conn)
		metric.CountWebsocketClosed(1)
	}
}

func NodeToHash(node string) [6]byte {
	hash := sha1.Sum([]byte(node))
	var hashArr [6]byte
	copy(hashArr[:], hash[:6])
	return hashArr
}
