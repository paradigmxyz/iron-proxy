package transform

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBufferedBody_Read(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello")), 1024)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestBufferedBody_ResetAndReread(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello")), 1024)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))

	body.Reset()

	data, err = io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestBufferedBody_MultipleResets(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("abc")), 1024)

	for i := 0; i < 5; i++ {
		data, err := io.ReadAll(body)
		require.NoError(t, err)
		require.Equal(t, "abc", string(data))
		body.Reset()
	}
}

func TestBufferedBody_MaxBytesTruncates(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello world")), 5)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))

	// Reset and re-read: same truncated data.
	body.Reset()
	data, err = io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestBufferedBody_Unlimited(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello world")), 0)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))
}

func TestBufferedBody_NilBody(t *testing.T) {
	body := NewBufferedBody(nil, 1024)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Empty(t, data)
}

func TestBufferedBody_Close(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello")), 1024)
	require.NoError(t, body.Close())

	// After consuming, close is a no-op.
	body2 := NewBufferedBody(io.NopCloser(strings.NewReader("hello")), 1024)
	_, _ = io.ReadAll(body2)
	require.NoError(t, body2.Close())
}

func TestBufferedBody_StreamingReader_Unbuffered(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("stream me")), 1024)

	// StreamingReader without any prior Read should return the original.
	reader := body.StreamingReader()
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "stream me", string(data))
}

func TestBufferedBody_StreamingReader_Buffered(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("buffered")), 1024)

	// Read first to trigger buffering.
	_, _ = io.ReadAll(body)
	body.Reset()

	reader := body.StreamingReader()
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "buffered", string(data))
}

func TestBufferedBody_Len(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello")), 1024)

	// Before any read, Len is unknown.
	require.Equal(t, -1, body.Len())

	// After reading, Len returns the buffered size.
	_, _ = io.ReadAll(body)
	require.Equal(t, 5, body.Len())
}

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error {
	c.closed = true
	return nil
}

func TestBufferedBody_BeyondLimit(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		replacement string
		want        string
		wantLen     int
		wantForward int64
	}{
		{name: "over limit", input: "hello world", want: "hello world", wantLen: -1, wantForward: 11},
		{name: "exactly at limit", input: "hello", want: "hello", wantLen: -1, wantForward: 5},
		{name: "under limit", input: "hi", want: "hi", wantLen: 2, wantForward: 2},
		{name: "replaced prefix", input: "hello world", replacement: "goodbye", want: "goodbye world", wantLen: -1, wantForward: 13},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := NewBufferedBody(io.NopCloser(strings.NewReader(tc.input)), 5)

			seen, err := io.ReadAll(body)
			require.NoError(t, err)
			require.LessOrEqual(t, len(seen), 5)
			if tc.replacement != "" {
				body.ReplaceBuffered([]byte(tc.replacement))
			}
			body.Reset()

			require.Equal(t, tc.wantLen, body.Len())
			require.Equal(t, tc.wantForward, body.ForwardedLength(int64(len(tc.input))))
			require.Equal(t, int64(-1), body.ForwardedLength(-1))

			forwarded, err := io.ReadAll(body.StreamingReader())
			require.NoError(t, err)
			require.Equal(t, tc.want, string(forwarded))
		})
	}
}

func TestBufferedBody_CloseReleasesBytesBeyondLimit(t *testing.T) {
	source := &closeTracker{Reader: strings.NewReader("hello world")}
	body := NewBufferedBody(source, 5)

	_, err := io.ReadAll(body)
	require.NoError(t, err)
	require.False(t, source.closed)

	require.NoError(t, body.Close())
	require.True(t, source.closed)
}

func TestBufferedBodyFromBytes(t *testing.T) {
	body := NewBufferedBodyFromBytes([]byte("pre-buffered"))

	require.Equal(t, 12, body.Len())

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "pre-buffered", string(data))

	body.Reset()
	data, err = io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "pre-buffered", string(data))
}
