package outputs

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/config"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/snapshot"
)

type WebsocketOutput struct {
	port     int
	server   *http.Server
	upgrader websocket.Upgrader
	mu       sync.RWMutex
	clients  map[*websocket.Conn]bool
	snap     *snapshot.SnapshotJSON
}

func NewWebsocketOutput(cfg *config.WebsocketConfig) *WebsocketOutput {
	return &WebsocketOutput{
		port:    cfg.Port,
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (w *WebsocketOutput) Init() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", w.handleConnection)

	w.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", w.port),
		Handler: mux,
	}

	go func() {
		log.Printf("Websocket server listening on :%d/ws", w.port)
		if err := w.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("websocket server error: %v", err)
		}
	}()

	return nil
}

func (w *WebsocketOutput) handleConnection(rw http.ResponseWriter, r *http.Request) {
	conn, err := w.upgrader.Upgrade(rw, r, nil)
	if err != nil {
		log.Printf("websocket upgrade error: %v", err)
		return
	}

	w.mu.Lock()
	w.clients[conn] = true
	currentSnap := w.snap
	w.mu.Unlock()

	if currentSnap != nil {
		data, _ := json.Marshal(currentSnap)
		conn.WriteMessage(websocket.TextMessage, data)
	}

	go func() {
		defer func() {
			w.mu.Lock()
			delete(w.clients, conn)
			w.mu.Unlock()
			conn.Close()
		}()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()
}

func (w *WebsocketOutput) SendSnapshot(snap *snapshot.SnapshotJSON) error {
	w.mu.Lock()
	w.snap = snap
	w.mu.Unlock()
	return nil
}

func (w *WebsocketOutput) SendEvent(ev models.EventJSON) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	for conn := range w.clients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("websocket write error: %v", err)
			conn.Close()
			delete(w.clients, conn)
		}
	}
	return nil
}

func (w *WebsocketOutput) Close() error {
	w.mu.Lock()
	for conn := range w.clients {
		conn.Close()
	}
	w.mu.Unlock()

	if w.server != nil {
		return w.server.Close()
	}
	return nil
}
