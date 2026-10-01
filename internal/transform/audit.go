package transform

import (
	"log/slog"
)

// traceEntry is a JSON-serializable representation of a TransformTrace.
type traceEntry struct {
	Name        string         `json:"name"`
	Action      string         `json:"action"`
	DurationMS  float64        `json:"duration_ms"`
	Error       string         `json:"error,omitempty"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

// NewAuditLogger returns an AuditFunc that writes structured JSON log lines
// for every request. Log level is INFO for allowed and stubbed, WARN for
// rejected, ERROR for errored requests.
func NewAuditLogger(logger *slog.Logger) AuditFunc {
	return func(result *PipelineResult) {
		action := actionString(result.Action)
		if result.Err != nil {
			action = "error"
		}
		if result.ClientCanceled {
			action = "client_cancel"
		}

		attrs := []any{
			slog.Group("audit",
				slog.String("host", result.Host),
				slog.String("method", result.Method),
				slog.String("path", result.Path),
				slog.String("remote_addr", result.RemoteAddr),
				slog.String("sni", result.SNI),
				slog.String("mode", result.Mode.String()),
				slog.String("action", action),
				slog.Int("status_code", result.StatusCode),
				slog.Float64("duration_ms", float64(result.Duration.Microseconds())/1000.0),
			),
		}
		if result.Tunnel != nil {
			tunnelAttrs := []any{slog.String("target", result.Tunnel.Target)}
			if len(result.Tunnel.RequestTransforms) > 0 {
				tunnelAttrs = append(tunnelAttrs,
					slog.Any("request_transforms", buildTraceEntries(result.Tunnel.RequestTransforms)),
				)
			}
			attrs = append(attrs, slog.Group("tunnel", tunnelAttrs...))
		}

		// Add rejected_by / stubbed_by for short-circuit actions
		if result.Action == ActionReject {
			for _, tr := range result.RequestTransforms {
				if tr.Action == ActionReject {
					attrs = append(attrs, slog.String("rejected_by", tr.Name))
					break
				}
			}
		}
		if result.Action == ActionStub {
			for _, tr := range result.RequestTransforms {
				if tr.Action == ActionStub {
					attrs = append(attrs, slog.String("stubbed_by", tr.Name))
					break
				}
			}
		}

		// Add error for error actions
		if result.Err != nil {
			attrs = append(attrs, slog.String("error", result.Err.Error()))
		}

		// Add transform traces as JSON arrays
		if len(result.RequestTransforms) > 0 {
			attrs = append(attrs, slog.Any("request_transforms", buildTraceEntries(result.RequestTransforms)))
		}
		if len(result.ResponseTransforms) > 0 {
			attrs = append(attrs, slog.Any("response_transforms", buildTraceEntries(result.ResponseTransforms)))
		}
		if result.MCP != nil && result.MCP.MCPServer() != "" {
			mcpAttrs := []any{slog.String("server", result.MCP.MCPServer())}
			if msgs := result.MCP.MCPMessages(); len(msgs) > 0 {
				mcpAttrs = append(mcpAttrs, slog.Any("messages", msgs))
			}
			if gateway := result.MCP.MCPGateway(); len(gateway) > 0 {
				mcpAttrs = append(mcpAttrs, slog.Any("gateway", gateway))
			}
			attrs = append(attrs, slog.Group("mcp", mcpAttrs...))
		}
		if result.BodyCapture != nil {
			var bodyAttrs []any
			if body := result.BodyCapture.RequestBody(); body != "" {
				bodyAttrs = append(bodyAttrs,
					slog.String("request_body", body),
					slog.Bool("request_body_truncated", result.BodyCapture.RequestBodyTruncated()),
				)
			}
			// Safe to read the response half here: this callback fires after the
			// response body has been streamed to the client, so the tee has seen
			// everything it is going to see.
			if body := result.BodyCapture.ResponseBody(); body != "" {
				bodyAttrs = append(bodyAttrs,
					slog.String("response_body", body),
					slog.Bool("response_body_truncated", result.BodyCapture.ResponseBodyTruncated()),
				)
			}
			if len(bodyAttrs) > 0 {
				attrs = append(attrs, slog.Group("body_capture", bodyAttrs...))
			}
		}

		switch {
		case result.Err != nil:
			logger.Error("request", attrs...)
		case result.ClientCanceled:
			logger.Info("request", attrs...)
		case result.Action == ActionReject:
			logger.Warn("request", attrs...)
		default:
			logger.Info("request", attrs...)
		}
	}
}

func buildTraceEntries(traces []TransformTrace) []traceEntry {
	entries := make([]traceEntry, len(traces))
	for i, tr := range traces {
		entries[i] = traceEntry{
			Name:        tr.Name,
			Action:      traceActionString(tr),
			DurationMS:  float64(tr.Duration.Microseconds()) / 1000.0,
			Annotations: tr.Annotations,
		}
		if tr.Err != nil {
			entries[i].Error = tr.Err.Error()
		}
	}
	return entries
}

func actionString(a TransformAction) string {
	switch a {
	case ActionContinue:
		return "allow"
	case ActionReject:
		return "reject"
	case ActionStub:
		return "stub"
	default:
		return "unknown"
	}
}

func traceActionString(tr TransformTrace) string {
	if tr.Err != nil {
		return "error"
	}
	return actionString(tr.Action)
}
