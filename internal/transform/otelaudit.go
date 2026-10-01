package transform

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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
		rec.SetBody(log.StringValue("request"))
		rec.SetSeverity(otelSeverity(result))
		rec.SetSeverityText(otelSeverityText(result))

		attrs := []log.KeyValue{
			log.String("host", result.Host),
			log.String("method", result.Method),
			log.String("path", result.Path),
			log.String("remote_addr", result.RemoteAddr),
			log.String("sni", result.SNI),
			log.String("mode", result.Mode.String()),
			log.String("action", action),
			log.Int("status_code", result.StatusCode),
			log.Float64("duration_ms", float64(result.Duration.Microseconds())/1000.0),
		}

		if result.Action == ActionReject {
			for _, tr := range result.RequestTransforms {
				if tr.Action == ActionReject {
					attrs = append(attrs, log.String("rejected_by", tr.Name))
					break
				}
			}
		}
		if result.Action == ActionStub {
			for _, tr := range result.RequestTransforms {
				if tr.Action == ActionStub {
					attrs = append(attrs, log.String("stubbed_by", tr.Name))
					break
				}
			}
		}

		if result.Err != nil {
			attrs = append(attrs, log.String("error", result.Err.Error()))
		}

		if len(result.RequestTransforms) > 0 {
			attrs = append(attrs, log.KeyValue{
				Key:   "request_transforms",
				Value: transformTracesValue(result.RequestTransforms),
			})
		}
		if len(result.ResponseTransforms) > 0 {
			attrs = append(attrs, log.KeyValue{
				Key:   "response_transforms",
				Value: transformTracesValue(result.ResponseTransforms),
			})
		}
		if result.MCP != nil && result.MCP.MCPServer() != "" {
			mcpKVs := []log.KeyValue{log.String("server", result.MCP.MCPServer())}
			if msgs := result.MCP.MCPMessages(); len(msgs) > 0 {
				vals := make([]log.Value, len(msgs))
				for i, m := range msgs {
					vals[i] = toLogValue(m)
				}
				mcpKVs = append(mcpKVs, log.KeyValue{Key: "messages", Value: log.SliceValue(vals...)})
			}
			if gateway := result.MCP.MCPGateway(); len(gateway) > 0 {
				mcpKVs = append(mcpKVs, log.KeyValue{Key: "gateway", Value: toLogValue(gateway)})
			}
			attrs = append(attrs, log.KeyValue{Key: "mcp", Value: log.MapValue(mcpKVs...)})
		}
		if result.BodyCapture != nil {
			var bodyKVs []log.KeyValue
			if body := result.BodyCapture.RequestBody(); body != "" {
				bodyKVs = append(bodyKVs,
					log.String("request_body", body),
					log.Bool("request_body_truncated", result.BodyCapture.RequestBodyTruncated()),
				)
			}
			// See NewAuditLogger: the response half is only complete by the time
			// this callback runs, which is after the body reached the client.
			if body := result.BodyCapture.ResponseBody(); body != "" {
				bodyKVs = append(bodyKVs,
					log.String("response_body", body),
					log.Bool("response_body_truncated", result.BodyCapture.ResponseBodyTruncated()),
				)
			}
			if len(bodyKVs) > 0 {
				attrs = append(attrs, log.KeyValue{Key: "body_capture", Value: log.MapValue(bodyKVs...)})
			}
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
func transformTracesValue(traces []TransformTrace) log.Value {
	vals := make([]log.Value, len(traces))
	for i, tr := range traces {
		kvs := []log.KeyValue{
			log.String("name", tr.Name),
			log.String("action", traceActionString(tr)),
			log.Float64("duration_ms", float64(tr.Duration.Microseconds())/1000.0),
		}

		if tr.Err != nil {
			kvs = append(kvs, log.String("error", tr.Err.Error()))
		}

		if len(tr.Annotations) > 0 {
			kvs = append(kvs, log.KeyValue{
				Key:   "annotations",
				Value: annotationsValue(tr.Annotations),
			})
		}

		vals[i] = log.MapValue(kvs...)
	}
	return log.SliceValue(vals...)
}

// annotationsValue converts an arbitrary map[string]any into an OTEL log Value,
// preserving nested structure. Annotation values may be arbitrary Go types
// (structs, slices, maps), so we round-trip through JSON to normalize everything
// into primitives, maps, and slices before building the log.Value tree.
func annotationsValue(annotations map[string]any) log.Value {
	data, err := json.Marshal(annotations)
	if err != nil {
		return log.StringValue("{}")
	}
	var normalized any
	if err := json.Unmarshal(data, &normalized); err != nil {
		return log.StringValue("{}")
	}
	return toLogValue(normalized)
}

func toLogValue(v any) log.Value {
	switch x := v.(type) {
	case nil:
		return log.Value{}
	case bool:
		return log.BoolValue(x)
	case string:
		return log.StringValue(x)
	case int:
		return log.Int64Value(int64(x))
	case int64:
		return log.Int64Value(x)
	case float64:
		return log.Float64Value(x)
	case []any:
		vals := make([]log.Value, len(x))
		for i, item := range x {
			vals[i] = toLogValue(item)
		}
		return log.SliceValue(vals...)
	case map[string]any:
		kvs := make([]log.KeyValue, 0, len(x))
		for k, val := range x {
			kvs = append(kvs, log.KeyValue{Key: k, Value: toLogValue(val)})
		}
		return log.MapValue(kvs...)
	default:
		return log.StringValue(fmt.Sprintf("%v", x))
	}
}
