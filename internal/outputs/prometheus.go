package outputs

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/config"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/snapshot"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusOutput struct {
	port   int
	events *prometheus.CounterVec
	server *http.Server
}

func NewPrometheusOutput(cfg *config.PrometheusConfig) *PrometheusOutput {
	return &PrometheusOutput{
		port: cfg.Port,
		events: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kwatch_events_total",
				Help: "Total eBPF events by type and command",
			},
			[]string{"type", "command"},
		),
	}
}

func (p *PrometheusOutput) Init() error {
	prometheus.MustRegister(p.events)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	p.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", p.port),
		Handler: mux,
	}

	go func() {
		log.Printf("Prometheus metrics available at :%d/metrics", p.port)
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("prometheus server error: %v", err)
		}
	}()

	return nil
}

func (p *PrometheusOutput) SendSnapshot(_ *snapshot.SnapshotJSON) error {
	return nil
}

func (p *PrometheusOutput) SendEvent(ev models.EventJSON) error {
	p.events.WithLabelValues(ev.Type, ev.Command).Inc()
	return nil
}

func (p *PrometheusOutput) Close() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}
