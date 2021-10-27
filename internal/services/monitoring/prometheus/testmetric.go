package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupTestMetric() error {
	s.testCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "charon",
		Subsystem: "test",
		Name:      "test_numbers_counted",
		Help:      "The number of test numbers counted by our incrementer.",
	})

	return prometheus.Register(s.testCounter)
}

// NumberCounted is called when a test number is counted.
func (s *Service) NumberCounted() {
	s.testCounter.Inc()
	return
}
