package transform

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

const instrumentationName = "iron-proxy/audit"

// NewOTELAuditFunc returns an AuditFunc that emits structured OTEL log records
// for every proxied request. The log records use the schema:
//
//	{
//	  "host": "httpbin.org",
//	  "method": "GET",
//	  "path": "/headers",
//	  "action": "allow",
//	  "status_code": 200,
//	  "duration_ms": 142,
//	  "request_transforms": [...],
//	  "response_transforms": [...]
//	}
func NewOTELAuditFunc(provider *sdklog.LoggerProvider) AuditFunc {
	logger := provider.Logger(instrumentationName)

	return func(result *PipelineResult) {
		action := actionString(result.Action)
		if result.Err != nil {
			action = "error"
		}

		var rec log.Record
		rec.SetTimestamp(result.StartedAt)
		rec.SetObservedTimestamp(time.Now())
		rec.SetBody(attribute.StringValue("request"))
		rec.SetSeverity(otelSeverity(result))
		rec.SetSeverityText(otelSeverityText(result))

		attrs := []attribute.KeyValue{
			attribute.String("host", result.Host),
			attribute.String("method", result.Method),
			attribute.String("path", result.Path),
			attribute.String("remote_addr", result.RemoteAddr),
			attribute.String("sni", result.SNI),
			attribute.String("mode", result.Mode.String()),
			attribute.String("action", action),
			attribute.Int("status_code", result.StatusCode),
			attribute.Float64("duration_ms", float64(result.Duration.Microseconds())/1000.0),
		}

		if result.Action == ActionReject {
			for _, tr := range result.RequestTransforms {
				if tr.Action == ActionReject {
					attrs = append(attrs, attribute.String("rejected_by", tr.Name))
					break
				}
			}
		}
		if result.Action == ActionStub {
			for _, tr := range result.RequestTransforms {
				if tr.Action == ActionStub {
					attrs = append(attrs, attribute.String("stubbed_by", tr.Name))
					break
				}
			}
		}

		if result.Err != nil {
			attrs = append(attrs, attribute.String("error", result.Err.Error()))
		}

		if len(result.RequestTransforms) > 0 {
			attrs = append(attrs, attribute.KeyValue{
				Key:   "request_transforms",
				Value: transformTracesValue(result.RequestTransforms),
			})
		}
		if len(result.ResponseTransforms) > 0 {
			attrs = append(attrs, attribute.KeyValue{
				Key:   "response_transforms",
				Value: transformTracesValue(result.ResponseTransforms),
			})
		}
		if result.MCP != nil && result.MCP.MCPServer() != "" {
			mcpKVs := []attribute.KeyValue{attribute.String("server", result.MCP.MCPServer())}
			if msgs := result.MCP.MCPMessages(); len(msgs) > 0 {
				vals := make([]attribute.Value, len(msgs))
				for i, m := range msgs {
					vals[i] = toLogValue(m)
				}
				mcpKVs = append(mcpKVs, attribute.KeyValue{Key: "messages", Value: attribute.SliceValue(vals...)})
			}
			if gateway := result.MCP.MCPGateway(); len(gateway) > 0 {
				mcpKVs = append(mcpKVs, attribute.KeyValue{Key: "gateway", Value: toLogValue(gateway)})
			}
			attrs = append(attrs, attribute.KeyValue{Key: "mcp", Value: attribute.MapValue(mcpKVs...)})
		}
		if result.BodyCapture != nil && result.BodyCapture.RequestBody() != "" {
			attrs = append(attrs, attribute.KeyValue{Key: "body_capture", Value: attribute.MapValue(
				attribute.String("request_body", result.BodyCapture.RequestBody()),
				attribute.Bool("request_body_truncated", result.BodyCapture.RequestBodyTruncated()),
			)})
		}

		rec.AddAttributes(attrs...)
		logger.Emit(context.Background(), rec)
	}
}

// ChainAuditFuncs returns an AuditFunc that calls all provided funcs in order.
func ChainAuditFuncs(funcs ...AuditFunc) AuditFunc {
	return func(result *PipelineResult) {
		for _, f := range funcs {
			f(result)
		}
	}
}

func otelSeverity(result *PipelineResult) log.Severity {
	switch {
	case result.Err != nil:
		return log.SeverityError1
	case result.Action == ActionReject:
		return log.SeverityWarn1
	default:
		return log.SeverityInfo1
	}
}

func otelSeverityText(result *PipelineResult) string {
	switch {
	case result.Err != nil:
		return "ERROR"
	case result.Action == ActionReject:
		return "WARN"
	default:
		return "INFO"
	}
}

// transformTracesValue converts a slice of TransformTrace into an OTEL log
// Slice of Maps, preserving the nested structure for downstream analysis.
func transformTracesValue(traces []TransformTrace) attribute.Value {
	vals := make([]attribute.Value, len(traces))
	for i, tr := range traces {
		kvs := []attribute.KeyValue{
			attribute.String("name", tr.Name),
			attribute.String("action", traceActionString(tr)),
			attribute.Float64("duration_ms", float64(tr.Duration.Microseconds())/1000.0),
		}

		if tr.Err != nil {
			kvs = append(kvs, attribute.String("error", tr.Err.Error()))
		}

		if len(tr.Annotations) > 0 {
			kvs = append(kvs, attribute.KeyValue{
				Key:   "annotations",
				Value: annotationsValue(tr.Annotations),
			})
		}

		vals[i] = attribute.MapValue(kvs...)
	}
	return attribute.SliceValue(vals...)
}

// annotationsValue converts an arbitrary map[string]any into an OTEL log Value,
// preserving nested structure. Annotation values may be arbitrary Go types
// (structs, slices, maps), so we round-trip through JSON to normalize everything
// into primitives, maps, and slices before building the attribute.Value tree.
func annotationsValue(annotations map[string]any) attribute.Value {
	data, err := json.Marshal(annotations)
	if err != nil {
		return attribute.StringValue("{}")
	}
	var normalized any
	if err := json.Unmarshal(data, &normalized); err != nil {
		return attribute.StringValue("{}")
	}
	return toLogValue(normalized)
}

func toLogValue(v any) attribute.Value {
	switch x := v.(type) {
	case nil:
		return attribute.Value{}
	case bool:
		return attribute.BoolValue(x)
	case string:
		return attribute.StringValue(x)
	case int:
		return attribute.Int64Value(int64(x))
	case int64:
		return attribute.Int64Value(x)
	case float64:
		return attribute.Float64Value(x)
	case []any:
		vals := make([]attribute.Value, len(x))
		for i, item := range x {
			vals[i] = toLogValue(item)
		}
		return attribute.SliceValue(vals...)
	case map[string]any:
		kvs := make([]attribute.KeyValue, 0, len(x))
		for k, val := range x {
			kvs = append(kvs, attribute.KeyValue{Key: attribute.Key(k), Value: toLogValue(val)})
		}
		return attribute.MapValue(kvs...)
	default:
		return attribute.StringValue(fmt.Sprintf("%v", x))
	}
}
