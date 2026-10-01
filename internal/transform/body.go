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
// A maxBytes of 0 means unlimited; when the limit is exceeded the body is
// truncated silently.
//
// TeeTo adds a third mode: an observer can take a streaming *copy* of the bytes
// without forcing the all-or-nothing buffering above. See TeeTo.
type BufferedBody struct {
	once     sync.Once
	mu       sync.Mutex // protects pos only
	original io.ReadCloser
	data     []byte
	pos      int
	maxBytes int64
	tee      io.Writer
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

// TeeTo installs sink as a streaming copy of the bytes this body hands to its
// consumer. Installing a tee does not read, buffer, or delay the body: the copy
// happens byte-for-byte as the consumer (the response write or the upstream
// send) pulls them through, so an observer can watch a slow or never-ending
// stream without the consumer ever waiting on it.
//
// Two rules the sink must honor, because it sits inline on the consumer's read
// path:
//
//   - Write must not block. Anything the sink waits for, the client waits for.
//   - Write must bound its own memory. TeeTo imposes no cap; a sink that wants
//     one drops the excess (see internal/transform/bodycapture) rather than
//     applying back-pressure, which would stall the consumer.
//
// A sink write error is discarded: an observer failing must never turn into a
// read error for the consumer.
//
// The copy happens exactly once, on whichever path consumes the underlying
// reader - StreamingReader (which hands off original and clears it) or buffer()
// (which consumes it under sync.Once). Only one of them can win. A body that is
// never consumed is never tee'd, and a body replaced wholesale by a later
// transform (NewBufferedBodyFromBytes) drops the tee with it.
//
// Call before the body is consumed; a later call has no effect on bytes already
// delivered.
func (b *BufferedBody) TeeTo(sink io.Writer) {
	b.tee = sink
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
		b.original.Close()
		b.original = nil
		// The buffering path consumed the reader, so StreamingReader will serve
		// from b.data and never see the tee. Feed the sink here instead, so the
		// copy still happens exactly once whichever path wins.
		if b.tee != nil && len(b.data) > 0 {
			_, _ = b.tee.Write(b.data)
		}
	})
	return err
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
// returns a reader over the buffer from the current position.
func (b *BufferedBody) StreamingReader() io.Reader {
	if b.original != nil {
		r := b.original
		b.original = nil
		if b.tee != nil {
			// Streaming path: the consumer drives the copy. Deliberately not
			// io.TeeReader - that propagates a sink write error to the consumer,
			// which would let a failing observer break the client's stream.
			return &teeReader{r: r, w: b.tee}
		}
		return r
	}
	b.mu.Lock()
	pos := b.pos
	b.mu.Unlock()
	return bytes.NewReader(b.data[pos:])
}

// Len returns the total size of the buffered body, or -1 if the body has not
// been buffered yet.
func (b *BufferedBody) Len() int {
	if b.original != nil {
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
	return nil
}

// teeReader copies what it reads into w, best effort. Unlike io.TeeReader it
// swallows the sink's write errors and short writes: the reader's job is to
// deliver bytes to the consumer, and an observer must never be able to fail
// that. It intentionally implements neither io.WriterTo nor io.ReaderFrom, so
// io.Copy cannot bypass Read and skip the copy.
type teeReader struct {
	r io.Reader
	w io.Writer
}

func (t *teeReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		_, _ = t.w.Write(p[:n])
	}
	return n, err
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
