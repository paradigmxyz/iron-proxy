package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"

	// Registers the body_capture transform factory.
	_ "github.com/ironsh/iron-proxy/internal/transform/bodycapture"
)

// newBodyCaptureTransform builds the real body_capture transform from YAML, the
// way cmd/iron-proxy does, so these tests exercise the shipped config path
// rather than a hand-built struct.
func newBodyCaptureTransform(t *testing.T, doc string) transform.Transformer {
	t.Helper()
	factory, err := transform.Lookup("body_capture")
	require.NoError(t, err)
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(doc), &node))
	require.NotEmpty(t, node.Content)
	tr, err := factory(*node.Content[0], testLogger())
	require.NoError(t, err)
	return tr
}

// startProxyWithAudit starts a plain-HTTP proxy whose pipeline runs transforms
// and reports each completed PipelineResult on the returned channel.
func startProxyWithAudit(t *testing.T, transforms []transform.Transformer) (string, <-chan *transform.PipelineResult) {
	t.Helper()

	pipeline := transform.NewPipeline(transforms, transform.BodyLimits{}, testLogger())
	results := make(chan *transform.PipelineResult, 4)
	pipeline.SetAuditFunc(func(r *transform.PipelineResult) { results <- r })

	p := New(Options{
		HTTPAddr: "127.0.0.1:0",
		Pipeline: transform.NewPipelineHolder(pipeline),
		Logger:   testLogger(),
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.httpServer.Serve(ln) }()
	t.Cleanup(func() { _ = p.httpServer.Close() })

	return ln.Addr().String(), results
}

func awaitAudit(t *testing.T, results <-chan *transform.PipelineResult) *transform.PipelineResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("audit record never emitted")
		return nil
	}
}

// TestHTTPProxy_BodyCapture_SSEResponseReachesTheAuditRecord is the end-to-end
// case for the tee: a real streaming upstream, through the real proxy, with the
// real body_capture transform, asserting that (a) the client receives each
// frame as it is flushed — not after the reply completes — and (b) the raw,
// unmerged body lands on the audit record the emitters render as
// `body_capture.response_body`.
//
// This test is the argument for the tee. An implementation that buffered the
// reply before forwarding it cannot pass it: the upstream refuses to flush
// frame 2 until the client has actually read frame 1, so a buffering proxy
// deadlocks until the deadline fires.
func TestHTTPProxy_BodyCapture_SSEResponseReachesTheAuditRecord(t *testing.T) {
	sawFirst := make(chan struct{})
	var releaseUpstream sync.Once
	release := func() { releaseUpstream.Do(func() { close(sawFirst) }) }

	frames := []string{
		"data: {\"delta\":{\"type\":\"text_delta\",\"text\":\"import \"}}\n\n",
		"data: {\"delta\":{\"type\":\"text_delta\",\"text\":\"os\\n\"}}\n\n",
		"data: [DONE]\n\n",
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)

		_, _ = fmt.Fprint(w, frames[0])
		flusher.Flush()
		// Frame 2 is withheld until the client has actually read frame 1. This
		// is what makes the test a regression test rather than a smoke test: a
		// proxy that buffers the reply before forwarding it can never satisfy
		// both sides of this handshake.
		<-sawFirst
		for _, f := range frames[1:] {
			_, _ = fmt.Fprint(w, f)
			flusher.Flush()
		}
	}))
	// Cleanups run LIFO, so registering Close first and the release second means
	// the handler is always released before Close waits on it — including on the
	// failure path below, where the upstream is still holding frame 2.
	t.Cleanup(upstream.Close)
	t.Cleanup(release)

	bc := newBodyCaptureTransform(t, `
max_request_body_bytes: 16384
capture_response_body: true
max_response_body_bytes: 65536
rules:
  - host: "127.0.0.1"
    methods: ["POST"]
    paths: ["/v1/messages"]
`)
	proxyAddr, results := startProxyWithAudit(t, []transform.Transformer{bc})

	reqBody := `{"model":"claude","messages":[{"role":"user","content":"write a script"}],"stream":true}`
	req, err := http.NewRequest("POST", "http://"+proxyAddr+"/v1/messages", strings.NewReader(reqBody))
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	// Send the request and read frame 1, both while the upstream is still
	// holding frame 2. This is the assertion a buffering implementation cannot
	// satisfy: it would be parked in the middle of draining the upstream body,
	// which cannot advance until the client reads — so neither the response
	// headers nor the first frame ever arrive. Both steps sit behind one
	// deadline so that deadlock surfaces as a fast, legible failure instead of
	// hanging the suite.
	type firstFrame struct {
		resp *http.Response
		head string
		err  error
	}
	arrived := make(chan firstFrame, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			arrived <- firstFrame{err: err}
			return
		}
		buf := make([]byte, 32*1024)
		n, err := resp.Body.Read(buf)
		arrived <- firstFrame{resp: resp, head: string(buf[:n]), err: err}
	}()

	var ff firstFrame
	select {
	case ff = <-arrived:
		require.NoError(t, ff.err)
	case <-time.After(5 * time.Second):
		t.Fatal("the first SSE frame never reached the client while the reply was " +
			"still streaming - the response body is being buffered before it is forwarded")
	}
	resp := ff.resp
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, ff.head, "import ",
		"the first frame must arrive before the reply is complete")
	release()

	rest, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	clientSaw := ff.head + string(rest)
	require.Equal(t, strings.Join(frames, ""), clientSaw)

	// The audit record is emitted after the body is written to the client, so by
	// the time it fires the tee has the whole reply.
	result := awaitAudit(t, results)
	require.NotNil(t, result.BodyCapture, "body_capture should have attached a capture")
	require.Equal(t, reqBody, result.BodyCapture.RequestBody())
	require.Equal(t, clientSaw, result.BodyCapture.ResponseBody(),
		"response_body must be the raw bytes the client received, frames unmerged")
	require.False(t, result.BodyCapture.ResponseBodyTruncated())
}

func TestHTTPProxy_BodyCapture_ResponseCapDoesNotTruncateTheClient(t *testing.T) {
	// 200 KiB reply, 4 KiB audit cap. The client must get all of it; the audit
	// record keeps the head and says it was truncated.
	const total = 200 * 1024
	const capBytes = 4 * 1024
	payload := strings.Repeat("z", total)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
	}))
	defer upstream.Close()

	bc := newBodyCaptureTransform(t, fmt.Sprintf(`
capture_response_body: true
max_response_body_bytes: %d
rules:
  - host: "127.0.0.1"
`, capBytes))
	proxyAddr, results := startProxyWithAudit(t, []transform.Transformer{bc})

	req, err := http.NewRequest("POST", "http://"+proxyAddr+"/v1/messages", strings.NewReader("{}"))
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, total, len(body), "the client must receive the whole reply")

	result := awaitAudit(t, results)
	require.NotNil(t, result.BodyCapture)
	require.Equal(t, capBytes, len(result.BodyCapture.ResponseBody()))
	require.True(t, result.BodyCapture.ResponseBodyTruncated())
}

func TestHTTPProxy_BodyCapture_ResponseNotCapturedByDefault(t *testing.T) {
	// The same config without `capture_response_body` must behave exactly as
	// body_capture did before response capture existed.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"content":"reply"}`)
	}))
	defer upstream.Close()

	bc := newBodyCaptureTransform(t, `
rules:
  - host: "127.0.0.1"
`)
	proxyAddr, results := startProxyWithAudit(t, []transform.Transformer{bc})

	req, err := http.NewRequest("POST", "http://"+proxyAddr+"/v1/messages", strings.NewReader(`{"x":1}`))
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, `{"content":"reply"}`, string(body))

	result := awaitAudit(t, results)
	require.NotNil(t, result.BodyCapture)
	require.Equal(t, `{"x":1}`, result.BodyCapture.RequestBody())
	require.Equal(t, "", result.BodyCapture.ResponseBody(),
		"response capture must stay off unless the config asks for it")
	require.False(t, result.BodyCapture.ResponseBodyTruncated())
}

func TestHTTPProxy_BodyCapture_NonMatchingHostNotCaptured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "some other service's reply")
	}))
	defer upstream.Close()

	bc := newBodyCaptureTransform(t, `
capture_response_body: true
rules:
  - host: "api.anthropic.com"
`)
	proxyAddr, results := startProxyWithAudit(t, []transform.Transformer{bc})

	req, err := http.NewRequest("GET", "http://"+proxyAddr+"/anything", nil)
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "some other service's reply", string(body))

	result := awaitAudit(t, results)
	require.Nil(t, result.BodyCapture, "a non-matching host must not be captured at all")
}

// TestHTTPProxy_BodyCapture_SlowReplyDoesNotDelayOtherTraffic is the
// head-of-line-blocking guard at the proxy level: while one request sits on a
// model reply that has not finished, unrelated traffic through the same proxy
// must complete normally.
func TestHTTPProxy_BodyCapture_SlowReplyDoesNotDelayOtherTraffic(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			_, _ = io.WriteString(w, "data: thinking\n\n")
			f.Flush()
		}
		<-release
	}))
	defer slow.Close()

	quick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "pong")
	}))
	defer quick.Close()

	bc := newBodyCaptureTransform(t, `
capture_response_body: true
rules:
  - host: "127.0.0.1"
`)
	proxyAddr, _ := startProxyWithAudit(t, []transform.Transformer{bc})
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr})},
	}

	// Kick off the never-ending reply and wait until its first frame lands, so we
	// know the proxy is genuinely mid-stream on it.
	streaming := make(chan struct{})
	go func() {
		resp, err := client.Get(slow.URL + "/v1/messages")
		if err != nil {
			return
		}
		defer resp.Body.Close()
		buf := make([]byte, 512)
		if _, err := resp.Body.Read(buf); err == nil {
			close(streaming)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
	}()
	select {
	case <-streaming:
	case <-time.After(5 * time.Second):
		t.Fatal("the streaming reply never delivered its first frame")
	}

	done := make(chan string, 1)
	go func() {
		resp, err := client.Get(quick.URL + "/ping")
		if err != nil {
			done <- "error: " + err.Error()
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		done <- string(b)
	}()

	select {
	case got := <-done:
		require.Equal(t, "pong", got)
	case <-time.After(5 * time.Second):
		t.Fatal("unrelated traffic was blocked while an AI reply was still streaming")
	}

	once.Do(func() { close(release) })
}
