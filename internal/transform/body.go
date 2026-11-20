package transform

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

// BufferedBody wraps an io.ReadCloser with lazy, all-or-nothing buffering.
//
// When a transform calls Read(), the entire underlying reader is consumed into
// memory on the first call. Subsequent reads and Reset() calls operate on the
// buffer. When no transform reads the body, StreamingReader() returns the
// original reader directly — avoiding buffering for the final response write
// or upstream send.
//
// A maxBytes of 0 means unlimited. When the limit is reached, transforms see
// only the first maxBytes, and StreamingReader() forwards the rest.
type BufferedBody struct {
	once     sync.Once
	mu       sync.Mutex // protects pos only
	original io.ReadCloser
	rest     io.ReadCloser // bytes beyond maxBytes, unread by transforms
	data     []byte
	pos      int
	maxBytes int64
}

// NewBufferedBody wraps an io.ReadCloser for lazy buffering. maxBytes caps
// the buffer size; 0 means unlimited.
func NewBufferedBody(body io.ReadCloser, maxBytes int64) *BufferedBody {
	if body == nil {
		body = io.NopCloser(bytes.NewReader(nil))
	}
	return &BufferedBody{original: body, maxBytes: maxBytes}
}

// NewBufferedBodyFromBytes creates a pre-buffered body from a byte slice.
// Use this when a transform replaces the body with new content.
func NewBufferedBodyFromBytes(data []byte) *BufferedBody {
	b := &BufferedBody{data: data}
	b.once.Do(func() {}) // mark as already buffered
	return b
}

// Read implements io.Reader. On the first call, the entire underlying reader
// is eagerly consumed into an internal buffer. All reads serve from the buffer.
func (b *BufferedBody) Read(p []byte) (int, error) {
	if err := b.buffer(); err != nil {
		return 0, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

// buffer eagerly reads the entire original body into memory exactly once.
func (b *BufferedBody) buffer() error {
	var err error
	b.once.Do(func() {
		var r io.Reader = b.original
		if b.maxBytes > 0 {
			r = io.LimitReader(r, b.maxBytes)
		}
		b.data, err = io.ReadAll(r)
		if err == nil && b.maxBytes > 0 && int64(len(b.data)) == b.maxBytes {
			b.rest = b.original
		} else {
			b.original.Close()
		}
		b.original = nil
	})
	return err
}

// ReplaceBuffered replaces the bytes transforms can see and rewinds the body.
// Bytes beyond maxBytes are kept and still forwarded after data.
func (b *BufferedBody) ReplaceBuffered(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = data
	b.pos = 0
}

// ForwardedLength returns the length StreamingReader will produce for a body
// the client declared as declared bytes. Call it only when Len returns -1.
func (b *BufferedBody) ForwardedLength(declared int64) int64 {
	if b.rest == nil || declared < 0 {
		return declared
	}
	return declared - b.maxBytes + int64(len(b.data))
}

// Reset rewinds the read position to the beginning so the body can be
// re-read by the next transform in the pipeline.
func (b *BufferedBody) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pos = 0
}

// StreamingReader returns a reader for the final output (response write or
// upstream send). If the body was never read by a transform, this returns the
// original reader directly — no buffering occurs. If the body was buffered,
// returns a reader over the buffer from the current position, followed by any
// bytes beyond maxBytes.
func (b *BufferedBody) StreamingReader() io.Reader {
	if b.original != nil {
		r := b.original
		b.original = nil
		return r
	}
	b.mu.Lock()
	pos := b.pos
	b.mu.Unlock()
	buffered := bytes.NewReader(b.data[pos:])
	if b.rest != nil {
		return io.MultiReader(buffered, b.rest)
	}
	return buffered
}

// Len returns the total size of the buffered body, or -1 if the body has not
// been buffered yet or bytes beyond maxBytes may remain.
func (b *BufferedBody) Len() int {
	if b.original != nil || b.rest != nil {
		return -1
	}
	return len(b.data)
}

// Close closes the underlying reader if it has not been consumed.
func (b *BufferedBody) Close() error {
	if b.original != nil {
		err := b.original.Close()
		b.original = nil
		return err
	}
	if b.rest != nil {
		err := b.rest.Close()
		b.rest = nil
		return err
	}
	return nil
}

// RequireBufferedBody asserts that body is a *BufferedBody and returns it.
// Panics otherwise. The proxy must wrap all request and response bodies
// before they enter the pipeline or are forwarded.
func RequireBufferedBody(body io.ReadCloser) *BufferedBody {
	b, ok := body.(*BufferedBody)
	if !ok {
		panic(fmt.Sprintf("expected *BufferedBody, got %T", body))
	}
	return b
}
