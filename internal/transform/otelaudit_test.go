package transform

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// recordProcessor is an in-memory OTEL log processor for testing.
type recordProcessor struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (p *recordProcessor) OnEmit(_ context.Context, r *sdklog.Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, *r)
	return nil
}

func (p *recordProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }
func (p *recordProcessor) Shutdown(context.Context) error              { return nil }
func (p *recordProcessor) ForceFlush(context.Context) error            { return nil }

func (p *recordProcessor) Records() []sdklog.Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]sdklog.Record{}, p.records...)
}

func TestOTELAuditFunc_AllowedRequest(t *testing.T) {
	proc := &recordProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	auditFunc := NewOTELAuditFunc(provider)

	auditFunc(&PipelineResult{
		Host:      "httpbin.org",
		Method:    "GET",
		Path:      "/headers",
		RemoteAddr: "172.20.0.4:54321",
		SNI:       "httpbin.org",
		StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Duration:  142 * time.Millisecond,
		Action:    ActionContinue,
		StatusCode: 200,
		RequestTransforms: []TransformTrace{
			{
				Name:     "allowlist",
				Action:   ActionContinue,
				Duration: 500 * time.Microsecond,
			},
			{
				Name:     "secrets",
				Action:   ActionContinue,
				Duration: 1200 * time.Microsecond,
				Annotations: map[string]any{
					"swapped": []any{
						map[string]any{
							"secret":    "OPENAI_API_KEY",
							"locations": []string{"header:Authorization"},
						},
					},
				},
			},
		},
	})

	records := proc.Records()
	require.Len(t, records, 1)

	rec := records[0]
	assert.Equal(t, log.SeverityInfo1, rec.Severity())
	assert.Equal(t, "INFO", rec.SeverityText())
	assert.Equal(t, "request", rec.Body().AsString())

	attrs := recordAttrs(rec)
	assert.Equal(t, "httpbin.org", attrs["host"].AsString())
	assert.Equal(t, "GET", attrs["method"].AsString())
	assert.Equal(t, "/headers", attrs["path"].AsString())
	assert.Equal(t, "allow", attrs["action"].AsString())
	assert.Equal(t, int64(200), attrs["status_code"].AsInt64())
	assert.InDelta(t, 142.0, attrs["duration_ms"].AsFloat64(), 0.1)

	// Verify request_transforms is a slice
	transforms := attrs["request_transforms"]
	require.Equal(t, log.KindSlice, transforms.Kind())
	transformSlice := transforms.AsSlice()
	require.Len(t, transformSlice, 2)

	// First transform: allowlist
	t0 := mapFromValue(transformSlice[0])
	assert.Equal(t, "allowlist", t0["name"].AsString())
	assert.Equal(t, "allow", t0["action"].AsString())

	// Second transform: secrets with annotations
	t1 := mapFromValue(transformSlice[1])
	assert.Equal(t, "secrets", t1["name"].AsString())

	// annotations should be a nested map, not a JSON string.
	annotations := t1["annotations"]
	require.Equal(t, log.KindMap, annotations.Kind())
	annMap := mapFromValue(annotations)

	swapped := annMap["swapped"]
	require.Equal(t, log.KindSlice, swapped.Kind())
	swappedSlice := swapped.AsSlice()
	require.Len(t, swappedSlice, 1)

	entry := mapFromValue(swappedSlice[0])
	assert.Equal(t, "OPENAI_API_KEY", entry["secret"].AsString())
	locations := entry["locations"]
	require.Equal(t, log.KindSlice, locations.Kind())
	locSlice := locations.AsSlice()
	require.Len(t, locSlice, 1)
	assert.Equal(t, "header:Authorization", locSlice[0].AsString())
}

func TestOTELAuditFunc_RejectedRequest(t *testing.T) {
	proc := &recordProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	auditFunc := NewOTELAuditFunc(provider)

	auditFunc(&PipelineResult{
		Host:       "malicious.example.com",
		Method:     "GET",
		Path:       "/",
		Action:     ActionReject,
		StatusCode: 403,
		Duration:   1 * time.Millisecond,
		RequestTransforms: []TransformTrace{
			{
				Name:   "allowlist",
				Action: ActionReject,
			},
		},
	})

	records := proc.Records()
	require.Len(t, records, 1)

	rec := records[0]
	assert.Equal(t, log.SeverityWarn1, rec.Severity())
	assert.Equal(t, "WARN", rec.SeverityText())

	attrs := recordAttrs(rec)
	assert.Equal(t, "reject", attrs["action"].AsString())
	assert.Equal(t, "allowlist", attrs["rejected_by"].AsString())
}

func TestOTELAuditFunc_StubbedRequest(t *testing.T) {
	proc := &recordProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	auditFunc := NewOTELAuditFunc(provider)

	auditFunc(&PipelineResult{
		Host:       "oauth2.googleapis.com",
		Method:     "POST",
		Path:       "/token",
		Action:     ActionStub,
		StatusCode: 200,
		Duration:   1 * time.Millisecond,
		RequestTransforms: []TransformTrace{
			{
				Name:   "gcp_auth",
				Action: ActionStub,
			},
		},
	})

	records := proc.Records()
	require.Len(t, records, 1)

	rec := records[0]
	assert.Equal(t, log.SeverityInfo1, rec.Severity())
	assert.Equal(t, "INFO", rec.SeverityText())

	attrs := recordAttrs(rec)
	assert.Equal(t, "stub", attrs["action"].AsString())
	assert.Equal(t, "gcp_auth", attrs["stubbed_by"].AsString())
}

func TestOTELAuditFunc_ErroredRequest(t *testing.T) {
	proc := &recordProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	auditFunc := NewOTELAuditFunc(provider)

	auditFunc(&PipelineResult{
		Host:     "api.example.com",
		Method:   "POST",
		Path:     "/v1/test",
		Action:   ActionContinue,
		Duration: 5 * time.Millisecond,
		Err:      errors.New("connection reset"),
	})

	records := proc.Records()
	require.Len(t, records, 1)

	rec := records[0]
	assert.Equal(t, log.SeverityError1, rec.Severity())
	assert.Equal(t, "ERROR", rec.SeverityText())

	attrs := recordAttrs(rec)
	assert.Equal(t, "error", attrs["action"].AsString())
	assert.Equal(t, "connection reset", attrs["error"].AsString())
}

func TestOTELAuditFunc_BodyCapture_PopulatesGroup(t *testing.T) {
	proc := &recordProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	auditFunc := NewOTELAuditFunc(provider)

	auditFunc(&PipelineResult{
		Host:        "api.anthropic.com",
		Method:      "POST",
		Path:        "/v1/messages",
		StartedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Duration:    50 * time.Millisecond,
		Action:      ActionContinue,
		StatusCode:  200,
		BodyCapture: &fakeBodyCapture{body: `{"prompt":"hi"}`, truncated: false},
	})

	records := proc.Records()
	require.Len(t, records, 1)

	attrs := recordAttrs(records[0])
	require.Contains(t, attrs, "body_capture")
	bc := mapFromValue(attrs["body_capture"])
	require.Contains(t, bc, "request_body")
	require.Equal(t, `{"prompt":"hi"}`, bc["request_body"].AsString())
	require.Contains(t, bc, "request_body_truncated")
	require.Equal(t, false, bc["request_body_truncated"].AsBool())
}

func TestOTELAuditFunc_BodyCapture_TruncationFlagPropagates(t *testing.T) {
	proc := &recordProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	auditFunc := NewOTELAuditFunc(provider)

	auditFunc(&PipelineResult{
		Host:        "api.openai.com",
		Method:      "POST",
		Path:        "/v1/chat/completions",
		StartedAt:   time.Now(),
		Duration:    50 * time.Millisecond,
		Action:      ActionContinue,
		StatusCode:  200,
		BodyCapture: &fakeBodyCapture{body: "xxxxxxxxxx", truncated: true},
	})

	records := proc.Records()
	require.Len(t, records, 1)

	attrs := recordAttrs(records[0])
	require.Contains(t, attrs, "body_capture")
	bc := mapFromValue(attrs["body_capture"])
	require.Contains(t, bc, "request_body_truncated")
	require.True(t, bc["request_body_truncated"].AsBool())
}

func TestOTELAuditFunc_BodyCapture_NilOmitsGroup(t *testing.T) {
	proc := &recordProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	auditFunc := NewOTELAuditFunc(provider)

	auditFunc(&PipelineResult{
		Host:       "example.com",
		Method:     "GET",
		Path:       "/",
		StartedAt:  time.Now(),
		Duration:   1 * time.Millisecond,
		Action:     ActionContinue,
		StatusCode: 200,
		// BodyCapture: nil
	})

	records := proc.Records()
	require.Len(t, records, 1)

	attrs := recordAttrs(records[0])
	require.NotContains(t, attrs, "body_capture")
}

func TestChainAuditFuncs(t *testing.T) {
	var calls []string
	f1 := AuditFunc(func(_ *PipelineResult) { calls = append(calls, "f1") })
	f2 := AuditFunc(func(_ *PipelineResult) { calls = append(calls, "f2") })

	chained := ChainAuditFuncs(f1, f2)
	chained(&PipelineResult{})

	assert.Equal(t, []string{"f1", "f2"}, calls)
}

// recordAttrs extracts attributes from an OTEL log record into a map.
func recordAttrs(rec sdklog.Record) map[string]log.Value {
	attrs := make(map[string]log.Value)
	rec.WalkAttributes(func(kv log.KeyValue) bool {
		attrs[kv.Key] = kv.Value
		return true
	})
	return attrs
}

// mapFromValue extracts key-value pairs from a Map log.Value.
func mapFromValue(v log.Value) map[string]log.Value {
	m := make(map[string]log.Value)
	for _, kv := range v.AsMap() {
		m[kv.Key] = kv.Value
	}
	return m
}

func TestOTELAuditFunc_BodyCapture_ResponseFieldsJoinTheSameGroup(t *testing.T) {
	proc := &recordProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	auditFunc := NewOTELAuditFunc(provider)

	auditFunc(&PipelineResult{
		Host:       "api.anthropic.com",
		Method:     "POST",
		Path:       "/v1/messages",
		StartedAt:  time.Now(),
		Duration:   50 * time.Millisecond,
		Action:     ActionContinue,
		StatusCode: 200,
		BodyCapture: &fakeBodyCapture{
			body:              `{"prompt":"hi"}`,
			respBody:          "data: {\"delta\":\"hello\"}\n\n",
			respBodyTruncated: true,
		},
	})

	records := proc.Records()
	require.Len(t, records, 1)

	attrs := recordAttrs(records[0])
	require.Contains(t, attrs, "body_capture")
	bc := mapFromValue(attrs["body_capture"])
	require.Equal(t, `{"prompt":"hi"}`, bc["request_body"].AsString())
	require.Equal(t, "data: {\"delta\":\"hello\"}\n\n", bc["response_body"].AsString())
	require.True(t, bc["response_body_truncated"].AsBool())
}

func TestOTELAuditFunc_BodyCapture_ResponseOnlyStillEmitsGroup(t *testing.T) {
	proc := &recordProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(proc))
	auditFunc := NewOTELAuditFunc(provider)

	auditFunc(&PipelineResult{
		Host:        "api.anthropic.com",
		Method:      "GET",
		Path:        "/v1/models",
		StartedAt:   time.Now(),
		Duration:    50 * time.Millisecond,
		Action:      ActionContinue,
		StatusCode:  200,
		BodyCapture: &fakeBodyCapture{respBody: `{"data":[]}`},
	})

	records := proc.Records()
	require.Len(t, records, 1)

	attrs := recordAttrs(records[0])
	require.Contains(t, attrs, "body_capture")
	bc := mapFromValue(attrs["body_capture"])
	require.NotContains(t, bc, "request_body")
	require.Equal(t, `{"data":[]}`, bc["response_body"].AsString())
	require.False(t, bc["response_body_truncated"].AsBool())
}
