package integration_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const (
	pgImage          = "postgres:16-alpine"
	pgUpstreamUser   = "iron_test"
	pgUpstreamPass   = "iron_test_pw"
	pgUpstreamDB     = "appdb"
	pgClientUser     = "app_user"
	pgClientPassword = "proxy_secret"
	pgRole           = "tenant_role"
)

// TestPostgresPolicy boots a real PostgreSQL container via testcontainers-go
// and an iron-proxy with the postgres listener configured, then drives real
// pgconn and pgx clients through the proxy to assert the v3 design:
//
//   - The proxy SETs ROLE upstream at session start so clients don't have to.
//   - Both Simple and Extended Query protocols pass through transparently.
//   - Client-issued role-change statements are rejected.
//   - Multi-statement Simple Queries are rejected.
//   - Auth failures are rejected before any upstream contact.
//
// Skipped when no Docker daemon is reachable.
func TestPostgresPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	initScript, err := filepath.Abs(filepath.Join("testdata", "postgres_init.sql"))
	require.NoError(t, err)

	container, err := tcpostgres.Run(ctx, pgImage,
		tcpostgres.WithDatabase(pgUpstreamDB),
		tcpostgres.WithUsername(pgUpstreamUser),
		tcpostgres.WithPassword(pgUpstreamPass),
		tcpostgres.WithInitScripts(initScript),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("postgres testcontainers unavailable (is Docker running?): %v", err)
	}
	testcontainers.CleanupContainer(t, container)

	upstreamHost, err := container.Host(ctx)
	require.NoError(t, err)
	upstreamPort, err := container.MappedPort(ctx, "5432/tcp")
	require.NoError(t, err)

	cfgPath := renderConfig(t, t.TempDir(), "postgres_pipeline.yaml", nil)

	upstreamDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		pgUpstreamUser, pgUpstreamPass, upstreamHost, upstreamPort.Num(), pgUpstreamDB)
	env := []string{
		"PG_UPSTREAM_DSN=" + upstreamDSN,
		"PG_PROXY_PASSWORD=" + pgClientPassword,
	}
	proxy := startProxy(t, proxyBinary(t), cfgPath, env)
	pgAddr := proxy.AddrFor(t, "postgres proxy starting")

	connStr := func(password string) string {
		host, port, _ := net.SplitHostPort(pgAddr)
		return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			pgClientUser, password, host, port, pgUpstreamDB)
	}

	dial := func(t *testing.T, password string) *pgconn.PgConn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgconn.Connect(ctx, connStr(password))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		return conn
	}

	exec := func(t *testing.T, conn *pgconn.PgConn, sql string) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := conn.Exec(ctx, sql).ReadAll()
		return err
	}

	currentRole := func(t *testing.T, conn *pgconn.PgConn) string {
		t.Helper()
		results, err := conn.Exec(context.Background(), "SELECT current_role").ReadAll()
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Len(t, results[0].Rows, 1)
		return string(results[0].Rows[0][0])
	}

	t.Run("role is set at session start", func(t *testing.T) {
		// Client did nothing special; the proxy injected SET ROLE during
		// handshake, so the very first query already sees the right role.
		conn := dial(t, pgClientPassword)
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("rls scopes rows to the proxy-injected role", func(t *testing.T) {
		// This is the load-bearing test: the whole reason this feature exists
		// is so that PostgreSQL row-level security can use current_role to
		// scope access per tenant, even though the application connects as a
		// shared service-account superuser. The init script enables RLS on
		// `items` with a policy of `USING (owner = current_role)`; we assert
		// the client only sees rows where owner='tenant_role'.

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Sanity: connect directly to the container (no proxy) as the
		// superuser and confirm all 5 rows are present. This rules out a
		// fixture problem if the through-proxy assertion later sees 0 rows.
		directURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			pgUpstreamUser, pgUpstreamPass, upstreamHost, upstreamPort.Num(), pgUpstreamDB)
		direct, err := pgx.Connect(ctx, directURL)
		require.NoError(t, err)
		t.Cleanup(func() { _ = direct.Close(ctx) })
		var total int
		require.NoError(t, direct.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&total))
		require.Equal(t, 5, total, "fixture: items table should contain 5 rows directly")

		// Through the proxy: SET ROLE tenant_role was injected at handshake,
		// so RLS scopes us to tenant_role's rows.
		client, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close(ctx) })

		var visible int
		require.NoError(t, client.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&visible))
		require.Equal(t, 2, visible, "RLS should hide other_role's rows from tenant_role")

		rows, err := client.Query(ctx, "SELECT owner FROM items ORDER BY id")
		require.NoError(t, err)
		var owners []string
		for rows.Next() {
			var owner string
			require.NoError(t, rows.Scan(&owner))
			owners = append(owners, owner)
		}
		require.NoError(t, rows.Err())
		require.Equal(t, []string{"tenant_role", "tenant_role"}, owners,
			"every visible row's owner must be the proxy-injected role")

		// WITH CHECK on the policy must block inserts that try to write rows
		// belonging to another tenant.
		_, err = client.Exec(ctx, "INSERT INTO items (owner, data) VALUES ('other_role', 'sneaky')")
		require.Error(t, err, "RLS WITH CHECK should reject insert with owner = other_role")
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Equal(t, "42501", pgErr.Code,
			"WITH CHECK violation should surface as insufficient_privilege (42501)")

		// And inserting a row belonging to the right tenant works.
		_, err = client.Exec(ctx, "INSERT INTO items (owner, data) VALUES ('tenant_role', 'mine-new')")
		require.NoError(t, err)
		require.NoError(t, client.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&visible))
		require.Equal(t, 3, visible)

		// Cross-tenant rows remain invisible (and untouched) — UPDATE
		// targeting another tenant's data affects zero rows.
		tag, err := client.Exec(ctx, "UPDATE items SET data = 'pwned' WHERE owner = 'other_role'")
		require.NoError(t, err)
		require.EqualValues(t, 0, tag.RowsAffected(),
			"UPDATE through proxy must not be able to touch other tenants' rows")

		// Confirm directly that other_role's data is unchanged.
		require.NoError(t, direct.QueryRow(ctx, "SELECT count(*) FROM items WHERE owner = 'other_role' AND data = 'pwned'").Scan(&visible))
		require.Equal(t, 0, visible, "other tenant's rows should be untouched")
	})

	t.Run("autocommit simple query works", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		results, err := conn.Exec(context.Background(), "SELECT 1").ReadAll()
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Equal(t, "1", string(results[0].Rows[0][0]))
		// Role still correct.
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("extended query parameterized works", func(t *testing.T) {
		// pgx by default uses Extended Query with prepared-statement caching,
		// which is the path nearly every modern driver takes. Verify it works
		// end-to-end through the proxy.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })

		var n int
		require.NoError(t, conn.QueryRow(ctx, "SELECT $1::int", 42).Scan(&n))
		require.Equal(t, 42, n)

		var role string
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
	})

	t.Run("explicit transaction works and keeps role", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })

		tx, err := conn.Begin(ctx)
		require.NoError(t, err)
		var role string
		require.NoError(t, tx.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
		var sum int
		require.NoError(t, tx.QueryRow(ctx, "SELECT 1 + 2").Scan(&sum))
		require.Equal(t, 3, sum)
		require.NoError(t, tx.Commit(ctx))

		// After commit, still correct.
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
	})

	t.Run("client set role is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "SET ROLE other_role")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Contains(t, pgErr.Message, "managed by the proxy")
		// Subsequent query still works with the configured role.
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("client reset role is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "RESET ROLE")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "managed by the proxy")
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("client set session authorization is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "SET SESSION AUTHORIZATION other_role")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "managed by the proxy")
	})

	t.Run("clean multi statement is allowed", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "SELECT 1; SELECT 2")
		require.NoError(t, err)
		// Role policy still holds after a batch executes.
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("multi statement with role change is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "SELECT 1; SET ROLE other_role")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "managed by the proxy")
		// The batch was rejected before forwarding, so nothing took effect.
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("set_config function call bypass is rejected", func(t *testing.T) {
		// The headline case for the AST-based classifier: a client trying to
		// change the role via SELECT set_config('role', 'x', false) must be
		// rejected. Without parsing this would slip through because the wire
		// shows a SELECT, not a SET.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })

		_, err = conn.Exec(ctx, "SELECT set_config('role', 'other_role', false)")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Contains(t, pgErr.Message, "managed by the proxy")

		// Confirm the bypass didn't take effect upstream.
		var role string
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
	})

	t.Run("parameterized set_config target is rejected", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, conn.Close(context.Background())) })

		_, err = conn.Exec(ctx, "SELECT set_config($1, $2, false)", "role", "other_role")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "set_config is not supported")

		var role string
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
	})

	t.Run("set_config for other gucs is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		_, err := conn.Exec(context.Background(), "SELECT set_config('application_name', 'iron-test', false)").ReadAll()
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "set_config is not supported")
	})

	t.Run("session setting is injected at session start", func(t *testing.T) {
		// The proxy applied SET via set_config for app.tenant_label during the
		// handshake, so the client's first query already sees the value.
		conn := dial(t, pgClientPassword)
		results, err := conn.Exec(context.Background(), "SELECT current_setting('app.tenant_label')").ReadAll()
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Len(t, results[0].Rows, 1)
		require.Equal(t, "centaur", string(results[0].Rows[0][0]))
	})

	t.Run("client cannot override a pinned setting", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		currentLabel := func() string {
			results, err := conn.Exec(context.Background(), "SELECT current_setting('app.tenant_label')").ReadAll()
			require.NoError(t, err)
			return string(results[0].Rows[0][0])
		}

		// Direct SET, the set_config bypass, RESET, and RESET ALL are all
		// blocked, and none of them perturbs the injected value.
		for _, sql := range []string{
			"SET app.tenant_label = 'evil'",
			"SELECT set_config('app.tenant_label', 'evil', false)",
			"RESET app.tenant_label",
			"RESET ALL",
			"DISCARD ALL",
		} {
			err := exec(t, conn, sql)
			require.Errorf(t, err, "expected %q to be rejected", sql)
			var pgErr *pgconn.PgError
			require.Truef(t, errors.As(err, &pgErr), "want PgError for %q, got %T: %v", sql, err, err)
			require.Equalf(t, "42501", pgErr.Code, "reject code for %q", sql)
			require.Equal(t, "centaur", currentLabel(), "injected setting must survive %q", sql)
		}
		// Role is also still intact after the blocked statements.
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("pg_settings writes are rejected", func(t *testing.T) {
		// pg_settings' update rule calls set_config, and an auto-updatable
		// view over it forwards updates, so both would bypass pinned settings.
		conn := dial(t, pgClientPassword)
		for _, sql := range []string{
			"UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout'",
			"CREATE TEMP VIEW settings_view AS SELECT * FROM pg_settings",
		} {
			err := exec(t, conn, sql)
			require.Error(t, err)
			var pgErr *pgconn.PgError
			require.True(t, errors.As(err, &pgErr))
			require.Contains(t, pgErr.Message, "writing to pg_settings")
		}
	})

	t.Run("callback definition aliasing set_config is rejected", func(t *testing.T) {
		// An aggregate whose SFUNC is set_config would let the client invoke
		// set_config under another name, bypassing the FuncCall check.
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "CREATE AGGREGATE pg_temp.cfg(text, boolean) (SFUNC = pg_catalog.set_config, STYPE = text, INITCOND = 'role')")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "bind functions as callbacks")
		require.Equal(t, pgRole, currentRole(t, conn))
	})

	t.Run("do block is rejected", func(t *testing.T) {
		conn := dial(t, pgClientPassword)
		err := exec(t, conn, "DO $$ BEGIN PERFORM 1; END $$")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		require.Contains(t, pgErr.Message, "DO blocks are not supported")
	})

	t.Run("client set role via extended query is rejected", func(t *testing.T) {
		// Verifies the Parse-SQL classifier path: pgx uses Extended Query, so
		// SET ROLE issued through it must hit ClassifyClientStatement on the
		// Parse message and get rejected before reaching upstream.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })

		_, err = conn.Exec(ctx, "SET ROLE other_role")
		require.Error(t, err)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Contains(t, pgErr.Message, "managed by the proxy")

		// Connection still usable, role still correct.
		var role string
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
		require.Equal(t, pgRole, role)
	})

	t.Run("client auth failure", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := pgconn.Connect(ctx, connStr("wrong_password"))
		require.Error(t, err, "wrong proxy password must fail at the proxy")
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Equal(t, "28P01", pgErr.Code)
	})

	t.Run("hundred autocommit queries role stable", func(t *testing.T) {
		// Stress: simulates asyncpg-style pool.execute() usage. Same connection
		// running many autocommit queries; role must stay correct on every one.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, connStr(pgClientPassword))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close(context.Background()) })

		for i := 0; i < 100; i++ {
			var role string
			require.NoError(t, conn.QueryRow(ctx, "SELECT current_role").Scan(&role))
			require.Equalf(t, pgRole, role, "iteration %d", i)
		}
	})
}

// TestPostgresMultipleUpstreams boots one Postgres container (with two
// databases) and an iron-proxy whose single listener fronts two upstreams —
// each routing to a distinct database with its own injected role. The client
// selects between them by the database name it requests. Verifies routing lands
// on the right database and role, that an upstream whose DSN database does not
// match its routing database is rejected, and that an unknown database is
// rejected.
func TestPostgresMultipleUpstreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	initScript, err := filepath.Abs(filepath.Join("testdata", "postgres_init.sql"))
	require.NoError(t, err)

	container, err := tcpostgres.Run(ctx, pgImage,
		tcpostgres.WithDatabase(pgUpstreamDB),
		tcpostgres.WithUsername(pgUpstreamUser),
		tcpostgres.WithPassword(pgUpstreamPass),
		tcpostgres.WithInitScripts(initScript),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("postgres testcontainers unavailable (is Docker running?): %v", err)
	}
	testcontainers.CleanupContainer(t, container)

	upstreamHost, err := container.Host(ctx)
	require.NoError(t, err)
	upstreamPort, err := container.MappedPort(ctx, "5432/tcp")
	require.NoError(t, err)

	cfgPath := renderConfig(t, t.TempDir(), "postgres_multi_pipeline.yaml", nil)

	dsnFor := func(database string) string {
		return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			pgUpstreamUser, pgUpstreamPass, upstreamHost, upstreamPort.Num(), database)
	}
	env := []string{
		"PG_UPSTREAM_DSN=" + dsnFor(pgUpstreamDB), // appdb
		"PG_OTHER_DSN=" + dsnFor("otherdb"),
		"PG_PROXY_PASSWORD=" + pgClientPassword,
	}
	proxy := startProxy(t, proxyBinary(t), cfgPath, env)

	pgAddr := proxy.AddrFor(t, "postgres proxy starting")

	// connStrTo selects an upstream by the database name the client requests.
	// Every upstream lives on the same listener; only the database differs.
	connStrTo := func(database string) string {
		host, port, _ := net.SplitHostPort(pgAddr)
		return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			pgClientUser, pgClientPassword, host, port, database)
	}

	queryScalar := func(t *testing.T, database, sql string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := pgconn.Connect(ctx, connStrTo(database))
		require.NoError(t, err)
		defer func() { _ = conn.Close(context.Background()) }()
		results, err := conn.Exec(ctx, sql).ReadAll()
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Len(t, results[0].Rows, 1)
		return string(results[0].Rows[0][0])
	}

	t.Run("each upstream routes to its own database and role", func(t *testing.T) {
		require.Equal(t, "appdb", queryScalar(t, "appdb", "SELECT current_database()"))
		require.Equal(t, "tenant_role", queryScalar(t, "appdb", "SELECT current_role"))

		require.Equal(t, "otherdb", queryScalar(t, "otherdb", "SELECT current_database()"))
		require.Equal(t, "other_role", queryScalar(t, "otherdb", "SELECT current_role"))
	})

	t.Run("role scopes rows via rls on the appdb upstream", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// The appdb upstream injects tenant_role, so RLS scopes the client to
		// tenant_role's rows.
		client, err := pgx.Connect(ctx, connStrTo("appdb"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close(ctx) })
		var count int
		require.NoError(t, client.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&count))
		require.Equal(t, 2, count, "appdb upstream should see only tenant_role's rows")
	})

	t.Run("database not matching the dsn is rejected", func(t *testing.T) {
		// The "mismatch" upstream routes database "mismatch" to a DSN that
		// connects to appdb. The proxy must refuse it rather than silently land
		// the client on appdb.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := pgconn.Connect(ctx, connStrTo("mismatch"))
		require.Error(t, err, "an upstream whose DSN database differs from its route database must be rejected")
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Equal(t, "3D000", pgErr.Code)
		require.Contains(t, pgErr.Message, "mismatch")
	})

	t.Run("unknown database is rejected", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := pgconn.Connect(ctx, connStrTo("nonexistent"))
		require.Error(t, err, "a database with no matching upstream must be rejected")
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "want PgError, got %T: %v", err, err)
		require.Equal(t, "3D000", pgErr.Code)
	})
}
