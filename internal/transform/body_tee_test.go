package transform

import (
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// countingSink records everything written to it and how many separate Write
// calls it took, so a test can tell an incremental stream from one big flush.
type countingSink struct {
	mu     sync.Mutex
	buf    []byte
	writes int
}

func (s *countingSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	s.writes++
	return len(p), nil
}

func (s *countingSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.buf)
}

func (s *countingSink) Writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func TestBufferedBody_TeeTo_StreamingPathCopies(t *testing.T) {
	sink := &countingSink{}
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello tee")), 1024)
	body.TeeTo(sink)

	// Installing a tee must not buffer: Len() == -1 means "never read".
	require.Equal(t, -1, body.Len(), "TeeTo must not consume the body")

	data, err := io.ReadAll(body.StreamingReader())
	require.NoError(t, err)
	require.Equal(t, "hello tee", string(data))
	require.Equal(t, "hello tee", sink.String())
}

func TestBufferedBody_TeeTo_CopiesIncrementallyNotAtEOF(t *testing.T) {
	// The whole point of a tee: the sink sees each chunk as the consumer reads
	// it, so an observer never has to wait for the stream to finish. A
	// buffer-then-forward implementation could only satisfy this at EOF.
	sink := &countingSink{}
	body := NewBufferedBody(io.NopCloser(strings.NewReader("abcdef")), 1024)
	body.TeeTo(sink)
	reader := body.StreamingReader()

	chunk := make([]byte, 2)
	n, err := reader.Read(chunk)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, "ab", sink.String(), "sink must see the first chunk before EOF")

	_, err = reader.Read(chunk)
	require.NoError(t, err)
	require.Equal(t, "abcd", sink.String())
}

func TestBufferedBody_TeeTo_BufferedPathCopiesExactlyOnce(t *testing.T) {
	// When a transform reads the body (forcing buffering), the tee still fires —
	// but exactly once, not once per consumer. Reading via Read() and then
	// draining StreamingReader() must not double the sink's copy.
	sink := &countingSink{}
	body := NewBufferedBody(io.NopCloser(strings.NewReader("once only")), 1024)
	body.TeeTo(sink)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "once only", string(data))
	require.Equal(t, "once only", sink.String())
	require.Equal(t, 1, sink.Writes())

	body.Reset()
	_, err = io.ReadAll(body.StreamingReader())
	require.NoError(t, err)
	require.Equal(t, "once only", sink.String(), "a second consumer must not duplicate the copy")
	require.Equal(t, 1, sink.Writes())
}

// failingSink always errors, standing in for an observer that has broken.
type failingSink struct{}

func (failingSink) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestBufferedBody_TeeTo_SinkErrorDoesNotBreakTheConsumer(t *testing.T) {
	// A failing audit observer must never surface as a read error on the
	// client's stream. This is why the tee is not io.TeeReader.
	body := NewBufferedBody(io.NopCloser(strings.NewReader("still delivered")), 1024)
	body.TeeTo(failingSink{})

	data, err := io.ReadAll(body.StreamingReader())
	require.NoError(t, err)
	require.Equal(t, "still delivered", string(data))
}

func TestBufferedBody_TeeTo_NeverConsumed_NothingCopied(t *testing.T) {
	sink := &countingSink{}
	body := NewBufferedBody(io.NopCloser(strings.NewReader("unread")), 1024)
	body.TeeTo(sink)

	require.NoError(t, body.Close())
	require.Equal(t, "", sink.String())
	require.Equal(t, 0, sink.Writes())
}

func TestBufferedBody_NoTee_StreamingReaderIsTheOriginal(t *testing.T) {
	// Without a tee installed, StreamingReader must still hand back the
	// original reader untouched — no wrapper, no per-Read indirection for the
	// overwhelmingly common case where nothing is observing.
	body := NewBufferedBody(io.NopCloser(strings.NewReader("passthrough")), 1024)
	_, wrapped := body.StreamingReader().(*teeReader)
	require.False(t, wrapped, "an un-tee'd body must not be wrapped")
}
