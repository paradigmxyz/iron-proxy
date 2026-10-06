package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// maxFrontendMessageBodyLen caps every client message after the startup packet.
// pgproto3 otherwise accepts bodies up to the protocol's multi-gigabyte length
// field and allocates the declared size before decoding the message.
const maxFrontendMessageBodyLen = 16 << 20

// runSession owns a single client connection from accept through close. It
// performs the proxy-side handshake under a deadline, selects a route from the
// startup database name, opens an upstream connection through pgconn, issues
// SET ROLE on the upstream session, hijacks the connection, then runs the
// bidirectional relay loop.
func runSession(ctx context.Context, clientConn net.Conn, listener *Listener, logger *slog.Logger) {
	defer clientConn.Close()

	_ = clientConn.SetDeadline(time.Now().Add(handshakeTimeout))

	backend := newClientBackend(clientConn)

	startup, err := receiveStartup(clientConn, backend)
	if err != nil {
		logger.Debug("postgres: startup failed", slog.String("error", err.Error()), slog.String("remote", clientConn.RemoteAddr().String()))
		return
	}
	if startup == nil {
		// CancelRequest was handled and the connection closed.
		return
	}

	// Select the upstream by the requested database. The client must name a
	// database explicitly; the proxy does not infer one from the user.
	dbName := startup.Parameters["database"]
	if dbName == "" {
		writeFatal(backend, "3D000", "no database specified in startup message")
		logger.Info("postgres: no database specified",
			slog.String("listener", listener.Name()),
			slog.String("remote", clientConn.RemoteAddr().String()),
		)
		return
	}
	upstream := listener.Upstream(dbName)
	if upstream == nil {
		writeFatal(backend, "3D000", fmt.Sprintf("no upstream for database %q", dbName))
		logger.Info("postgres: no upstream for database",
			slog.String("database", dbName),
			slog.String("listener", listener.Name()),
			slog.String("remote", clientConn.RemoteAddr().String()),
		)
		return
	}

	if err := authenticateClient(backend, startup, listener); err != nil {
		logger.Info("postgres: client auth failed",
			slog.String("error", err.Error()),
			slog.String("remote", clientConn.RemoteAddr().String()),
		)
		return
	}

	upstreamConn, err := dialUpstream(ctx, upstream)
	if err != nil {
		var cfgErr upstreamConfigError
		if errors.As(err, &cfgErr) {
			// Configuration error, but surface it clearly to the client rather
			// than as a generic connection failure.
			writeFatal(backend, "3D000", cfgErr.Error())
		} else {
			writeFatal(backend, "08006", "upstream connection failed")
		}
		logger.Error("postgres: upstream connect failed", slog.String("error", err.Error()))
		return
	}

	if err := applySessionSetup(ctx, upstreamConn, upstream); err != nil {
		writeFatal(backend, "08006", err.Error())
		logger.Error("postgres: session setup failed",
			slog.String("error", err.Error()),
			slog.String("remote", clientConn.RemoteAddr().String()),
		)
		_ = upstreamConn.Close(ctx)
		return
	}

	hijacked, err := upstreamConn.Hijack()
	if err != nil {
		writeFatal(backend, "08006", "upstream hijack failed")
		logger.Error("postgres: upstream hijack failed", slog.String("error", err.Error()))
		return
	}
	defer hijacked.Conn.Close()

	if err := completeClientHandshake(backend, hijacked); err != nil {
		logger.Error("postgres: client handshake completion failed", slog.String("error", err.Error()))
		return
	}

	// Handshake complete; clear the deadline so long-running queries aren't
	// truncated by it. The relay loop drives I/O end-to-end from here.
	_ = clientConn.SetDeadline(time.Time{})

	relay := newRelay(clientConn, hijacked.Conn, backend, hijacked.Frontend, upstream, logger)
	relay.run()
}

func newClientBackend(conn net.Conn) *pgproto3.Backend {
	backend := pgproto3.NewBackend(conn, conn)
	backend.SetMaxBodyLen(maxFrontendMessageBodyLen)
	return backend
}

// receiveStartup handles the optional SSLRequest / GSSEncRequest preludes and
// returns the StartupMessage that follows. Returns (nil, nil) when the client
// sent a CancelRequest (handled by closing the connection) since the proxy
// does not support cancel forwarding.
func receiveStartup(rawConn net.Conn, backend *pgproto3.Backend) (*pgproto3.StartupMessage, error) {
	for attempt := 0; attempt < 3; attempt++ {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, fmt.Errorf("receiving startup message: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.StartupMessage:
			return m, nil
		case *pgproto3.SSLRequest:
			// Client TLS not terminated. Reply 'N' and let the client reissue
			// an unencrypted StartupMessage.
			if _, err := rawConn.Write([]byte{'N'}); err != nil {
				return nil, fmt.Errorf("writing SSL refusal: %w", err)
			}
		case *pgproto3.GSSEncRequest:
			if _, err := rawConn.Write([]byte{'N'}); err != nil {
				return nil, fmt.Errorf("writing GSS refusal: %w", err)
			}
		case *pgproto3.CancelRequest:
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected startup message type %T", msg)
		}
	}
	return nil, errors.New("startup message preceded by too many SSL/GSS requests")
}

// upstreamConfigError marks a dial failure caused by upstream configuration —
// a DSN that names no database, or one whose database disagrees with the
// upstream's routing database — rather than a transient connection problem. The
// session surfaces these to the client as a clear database error.
type upstreamConfigError interface {
	error
	isUpstreamConfigError()
}

// missingDSNDatabaseError reports that an upstream's DSN does not name a
// database. The DSN must name the database it connects to, both so the upstream
// session lands somewhere deterministic and so it can be validated against the
// upstream's routing database.
type missingDSNDatabaseError struct {
	configured string // the upstream's routing database
}

func (e *missingDSNDatabaseError) Error() string {
	return fmt.Sprintf("upstream DSN for database %q does not name a database; the DSN must specify the database it connects to",
		e.configured)
}

func (*missingDSNDatabaseError) isUpstreamConfigError() {}

// databaseMismatchError reports that an upstream's routing database does not
// match the database its DSN connects to. The two must always be equal: the
// routing database is the name the client connected with, so if the upstream
// session lands on a different database the client's view (current_database(),
// search_path resolution, etc.) silently diverges from what it asked for.
type databaseMismatchError struct {
	configured string // the upstream's routing database (what the client requested)
	dsn        string // the database the DSN actually connects to
}

func (e *databaseMismatchError) Error() string {
	return fmt.Sprintf("upstream database mismatch: client connected to database %q but its DSN connects to %q; the route database and DSN database must match",
		e.configured, e.dsn)
}

func (*databaseMismatchError) isUpstreamConfigError() {}

// dialUpstream opens an authenticated PgConn to the upstream database using
// the DSN resolved from the upstream's configured secret source. It refuses to
// connect when the DSN names no database, or when the DSN's database does not
// match the upstream's routing database, since that would land the client on a
// different database than the one it named.
func dialUpstream(ctx context.Context, upstream *Upstream) (*pgconn.PgConn, error) {
	dsn, err := upstream.DSN(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading upstream DSN: %w", err)
	}
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream DSN: %w", err)
	}
	if cfg.Database == "" {
		return nil, &missingDSNDatabaseError{configured: upstream.Database()}
	}
	if cfg.Database != upstream.Database() {
		return nil, &databaseMismatchError{configured: upstream.Database(), dsn: cfg.Database}
	}
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting upstream: %w", err)
	}
	return conn, nil
}

// applySessionSetup prepares the upstream session before the relay starts: it
// applies the upstream's pinned settings, then issues `SET ROLE "<role>"`.
//
// Settings are applied first, while the session still runs as the connecting
// (login) user, so a setting that requires elevated privilege isn't blocked by
// an already-downgraded role. Each is applied through set_config(name, value,
// false) via the extended protocol so the value is a bound parameter — no SQL
// quoting of the configured value is needed.
//
// The proxy assumes the role and settings persist for the lifetime of the
// connection, which requires PgBouncer (if present) to be running in
// session-pool mode. Transaction or statement pool modes silently swap backends
// between queries and would defeat the policy; that constraint is enforced by
// deployment configuration rather than by a runtime probe.
func applySessionSetup(ctx context.Context, conn *pgconn.PgConn, upstream *Upstream) error {
	for _, s := range upstream.Settings() {
		rr := conn.ExecParams(ctx, "SELECT set_config($1, $2, false)",
			[][]byte{[]byte(s.Name), []byte(s.Value)}, nil, nil, nil)
		if _, err := rr.Close(); err != nil {
			return fmt.Errorf("upstream rejected setting %q: %w", s.Name, err)
		}
	}
	if upstream.Role() != "" {
		setSQL := "SET ROLE " + QuoteIdent(upstream.Role())
		if _, err := conn.Exec(ctx, setSQL).ReadAll(); err != nil {
			return fmt.Errorf("upstream rejected SET ROLE %s: %w", QuoteIdent(upstream.Role()), err)
		}
	}
	return nil
}

// completeClientHandshake finishes the client-facing handshake by sending
// AuthenticationOk + ParameterStatus + BackendKeyData + ReadyForQuery. The
// ParameterStatus values are taken from the upstream's hijacked state so the
// client sees a coherent view of the server's runtime parameters.
//
// BackendKeyData is fabricated: the proxy does not support CancelRequest
// forwarding and must not leak the upstream's real key.
func completeClientHandshake(backend *pgproto3.Backend, hj *pgconn.HijackedConn) error {
	pid, secret, err := randomBackendKey()
	if err != nil {
		return fmt.Errorf("generating synthetic backend key: %w", err)
	}

	backend.Send(&pgproto3.AuthenticationOk{})
	for name, value := range hj.ParameterStatuses {
		backend.Send(&pgproto3.ParameterStatus{Name: name, Value: value})
	}
	backend.Send(&pgproto3.BackendKeyData{ProcessID: pid, SecretKey: secret})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	return backend.Flush()
}

// relay drives the bidirectional message pump between client and upstream
// after the role has been set on the upstream session.
//
// Two goroutines do socket I/O: c2s reads client messages and applies the
// statement and protocol policy before forwarding; s2c is a pure passthrough.
//
// Writes to the client serialize through clientWriteMu since both goroutines
// may write — c2s when synthesizing a reject, s2c when forwarding the normal
// upstream reply stream.
type relay struct {
	clientConn   net.Conn
	upstreamConn net.Conn

	backend  *pgproto3.Backend
	frontend *pgproto3.Frontend

	upstream *Upstream
	logger   *slog.Logger

	clientWriteMu sync.Mutex
	// txStatus is the last ReadyForQuery status received from upstream. It is
	// protected by clientWriteMu so synthetic ReadyForQuery messages preserve
	// the upstream transaction state.
	txStatus byte

	// skipExtended, when true, drops client Bind/Describe/Execute/Close
	// messages until a Sync is observed. Set when a Parse is rejected: per the
	// PostgreSQL Extended Query protocol, all messages between an error and a
	// Sync are ignored by the server. We mirror that so the proxy doesn't
	// forward orphaned messages upstream after our synthetic ErrorResponse.
	//
	// Read and written only by the c2s goroutine.
	skipExtended bool
}

func newRelay(clientConn, upstreamConn net.Conn, backend *pgproto3.Backend, frontend *pgproto3.Frontend, upstream *Upstream, logger *slog.Logger) *relay {
	return &relay{
		clientConn:   clientConn,
		upstreamConn: upstreamConn,
		backend:      backend,
		frontend:     frontend,
		upstream:     upstream,
		logger:       logger,
		txStatus:     'I',
	}
}

func (r *relay) run() {
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		r.clientToServer()
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		r.serverToClient()
	}()

	<-done
	// Closing the underlying conns interrupts the other goroutine's blocking
	// read and lets it exit.
	_ = r.clientConn.Close()
	_ = r.upstreamConn.Close()
	<-done
}

// clientToServer reads frontend messages from the client and forwards those
// permitted by the statement and protocol policy upstream.
func (r *relay) clientToServer() {
	for {
		msg, err := r.backend.Receive()
		if err != nil {
			if !isClosedConnErr(err) {
				r.logger.Debug("postgres: client read error", slog.String("error", err.Error()))
			}
			return
		}

		switch m := msg.(type) {
		case *pgproto3.Terminate:
			r.frontend.Send(m)
			_ = r.frontend.Flush()
			return

		case *pgproto3.Query:
			if r.skipExtended {
				// Unexpected mid-batch; treat the Simple Query as a fresh statement.
				r.skipExtended = false
			}
			if allowed, reason := ClassifyClientStatement(m.String, r.upstream.PinnedGUCs()); !allowed {
				r.writeReject(reason, true)
				continue
			}
			r.frontend.Send(m)
			if err := r.frontend.Flush(); err != nil {
				return
			}

		case *pgproto3.Parse:
			if allowed, reason := ClassifyClientStatement(m.Query, r.upstream.PinnedGUCs()); !allowed {
				r.writeReject(reason, false)
				r.skipExtended = true
				continue
			}
			r.frontend.Send(m)
			if err := r.frontend.Flush(); err != nil {
				return
			}

		case *pgproto3.FunctionCall:
			if r.skipExtended {
				continue
			}
			// FunctionCall invokes a function by OID without carrying SQL text,
			// so the proxy cannot apply its statement policy. The protocol is a
			// legacy fast path; reject it rather than forwarding an opaque call.
			r.writeReject(RejectFunctionCall, true)
			continue

		case *pgproto3.Sync:
			if r.skipExtended {
				// We rejected an earlier Parse in this extended-query batch.
				// Synthesize a ReadyForQuery for the client and consume the
				// Sync without forwarding upstream.
				r.skipExtended = false
				r.writeReadyForQuery()
				continue
			}
			r.frontend.Send(m)
			if err := r.frontend.Flush(); err != nil {
				return
			}

		default:
			if r.skipExtended {
				continue
			}
			r.frontend.Send(msg)
			if err := r.frontend.Flush(); err != nil {
				return
			}
		}
	}
}

// writeReject writes a synthetic ErrorResponse to the client. When
// withReadyForQuery is true (the Simple Query case) it also writes a
// ReadyForQuery so the client knows the proxy is again ready; the Extended
// Query case omits it because the client must drive to a Sync first.
func (r *relay) writeReject(reason RejectReason, withReadyForQuery bool) {
	r.clientWriteMu.Lock()
	defer r.clientWriteMu.Unlock()

	r.backend.Send(rejectError(reason))
	if withReadyForQuery {
		r.backend.Send(&pgproto3.ReadyForQuery{TxStatus: r.txStatus})
	}
	_ = r.backend.Flush()
}

// writeReadyForQuery writes a synthetic ReadyForQuery carrying the most recent
// transaction status observed from upstream.
func (r *relay) writeReadyForQuery() {
	r.clientWriteMu.Lock()
	defer r.clientWriteMu.Unlock()
	r.backend.Send(&pgproto3.ReadyForQuery{TxStatus: r.txStatus})
	_ = r.backend.Flush()
}

// writeClient writes one or more BackendMessages to the client under the
// shared write mutex.
func (r *relay) writeClient(msgs ...pgproto3.BackendMessage) {
	r.clientWriteMu.Lock()
	defer r.clientWriteMu.Unlock()
	for _, m := range msgs {
		if ready, ok := m.(*pgproto3.ReadyForQuery); ok {
			r.txStatus = ready.TxStatus
		}
		r.backend.Send(m)
	}
	_ = r.backend.Flush()
}

// rejectError builds the ErrorResponse synthesized for a policy denial.
func rejectError(reason RejectReason) *pgproto3.ErrorResponse {
	switch reason {
	case RejectDoBlock:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "0A000",
			Message:  "blocked by iron-proxy policy: DO blocks are not supported (their plpgsql body cannot be inspected for embedded role changes)",
		}
	case RejectPinnedSetting:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42501",
			Message:  "blocked by iron-proxy policy: this session setting is managed by the proxy; clients may not SET or RESET it",
		}
	case RejectResetAll:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42501",
			Message:  "blocked by iron-proxy policy: RESET ALL would reset the proxy-managed role and session settings",
		}
	case RejectDiscardAll:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42501",
			Message:  "blocked by iron-proxy policy: DISCARD ALL would reset the proxy-managed role and session settings",
		}
	case RejectSetConfig:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42501",
			Message:  "blocked by iron-proxy policy: set_config is not supported because session settings are managed by the proxy",
		}
	case RejectSettingsCatalogWrite:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42501",
			Message:  "blocked by iron-proxy policy: writing to pg_settings, or defining a view or rule over it, is not supported because session settings are managed by the proxy",
		}
	case RejectCallbackDefinition:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "0A000",
			Message:  "blocked by iron-proxy policy: definitions that bind functions as callbacks (aggregates, operators, types, casts, and similar) are not supported",
		}
	case RejectFunctionCall:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "0A000",
			Message:  "blocked by iron-proxy policy: the legacy FunctionCall protocol is not supported",
		}
	case RejectUninspectableRoutine:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "0A000",
			Message:  "blocked by iron-proxy policy: function and procedure definitions must use inspectable SQL or PL/pgSQL without dynamic SQL",
		}
	case RejectClientRoleChange:
		fallthrough
	default:
		return &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42501",
			Message:  "blocked by iron-proxy policy: role is managed by the proxy; clients may not issue SET ROLE / SET SESSION AUTHORIZATION / RESET ROLE",
		}
	}
}

// serverToClient reads backend messages from the upstream and forwards them
// to the client unchanged.
func (r *relay) serverToClient() {
	for {
		msg, err := r.frontend.Receive()
		if err != nil {
			if !isClosedConnErr(err) {
				r.logger.Debug("postgres: upstream read error", slog.String("error", err.Error()))
			}
			return
		}
		r.writeClient(msg)
	}
}

func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}
