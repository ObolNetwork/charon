// Package tracer provides a global OpenTelemetry tracer.
package tracer

import (
	"context"
	"io"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

var (
	// tracer is the global app level tracer, it defaults to a noop tracer.
	tracer = trace.NewNoopTracerProvider().Tracer("")
)

// Start creates a span and a context.Context containing the newly-created span from the global tracer.
// See go.opentelemetry.io/otel/trace#Start for more details.
func Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return tracer.Start(ctx, spanName, opts...)
}

// Init initialises the global tracer via the option(s) defaulting to a noop tracer.
func Init(opts ...func(*options)) (func(context.Context) error, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	if o.expFunc == nil {
		return func(context.Context) error {
			return nil
		}, nil
	}

	exp, err := o.expFunc()
	if err != nil {
		return nil, err
	}

	tp := newTraceProvider(exp)

	// Set globals
	otel.SetTracerProvider(tp)
	tracer = tp.Tracer("")

	return tp.Shutdown, nil
}

type options struct {
	expFunc func() (sdktrace.SpanExporter, error)
}

// WithStdOut returns an option to configure an OpenTelemetry exporter for tracing
// telemetry to be written to an output destination as JSON.
func WithStdOut(w io.Writer) func(*options) {
	return func(o *options) {
		o.expFunc = func() (sdktrace.SpanExporter, error) {
			return stdouttrace.New(stdouttrace.WithWriter(w))
		}
	}
}

// WithJaegerOrNoop returns an option to configure an OpenTelemetry tracing exporter for Jaeger
// if the address is not empty, else the default noop tracer is retained.
func WithJaegerOrNoop(jaegerAddr string) func(*options) {
	if jaegerAddr == "" {
		return func(o *options) {}
	}
	return WithJaeger(jaegerAddr)
}

// WithJaeger returns an option to configure an OpenTelemetry tracing exporter for Jaeger.
func WithJaeger(addr string) func(*options) {
	return func(o *options) {
		o.expFunc = func() (sdktrace.SpanExporter, error) {
			return jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(addr)))
		}
	}
}

func newTraceProvider(exp sdktrace.SpanExporter) *sdktrace.TracerProvider {
	r := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String("charon"),
	)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()), // TODO(corver): Reconsider 100% sampling.
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
	)

	return tp
}
