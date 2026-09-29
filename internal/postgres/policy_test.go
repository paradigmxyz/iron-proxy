package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyClientStatement(t *testing.T) {
	// pinned models an upstream that pins one custom setting; nil means an
	// upstream that pins nothing beyond the always-on role policy.
	pinned := map[string]struct{}{
		"centaur.slack_channel_id": {},
		"centaur.slack_user":       {},
	}

	tests := []struct {
		name    string
		sql     string
		pinned  map[string]struct{}
		allowed bool
		reason  RejectReason
	}{
		{name: "select allowed", sql: "SELECT 1", allowed: true},
		{name: "update allowed", sql: "UPDATE t SET x = 1 WHERE id = 2", allowed: true},
		{name: "begin allowed", sql: "BEGIN", allowed: true},
		{name: "commit allowed", sql: "COMMIT", allowed: true},
		{name: "rollback allowed", sql: "ROLLBACK", allowed: true},
		{name: "empty allowed", sql: "", allowed: true},

		{name: "set role rejected", sql: "SET ROLE other", reason: RejectClientRoleChange},
		{name: "set local role rejected", sql: "SET LOCAL ROLE other", reason: RejectClientRoleChange},
		{name: "set session role rejected", sql: "SET SESSION ROLE other", reason: RejectClientRoleChange},
		{name: "reset role rejected", sql: "RESET ROLE", reason: RejectClientRoleChange},
		{name: "set session authorization rejected", sql: "SET SESSION AUTHORIZATION admin", reason: RejectClientRoleChange},
		{name: "reset session authorization rejected", sql: "RESET SESSION AUTHORIZATION", reason: RejectClientRoleChange},

		// RESET ALL / DISCARD ALL reset the managed role, so they are blocked
		// even when the upstream pins no custom settings.
		{name: "reset all rejected", sql: "RESET ALL", reason: RejectResetAll},
		{name: "discard all rejected", sql: "DISCARD ALL", reason: RejectDiscardAll},
		{name: "discard plans allowed", sql: "DISCARD PLANS", allowed: true},
		{name: "discard temp allowed", sql: "DISCARD TEMP", allowed: true},

		// Multi-statement batches are allowed when every statement passes the
		// role policy, and rejected per-statement otherwise.
		{name: "clean multi statement allowed", sql: "SELECT 1; SELECT 2", allowed: true},
		{name: "multi statement with set role rejected", sql: "SET ROLE x; SELECT 1", reason: RejectClientRoleChange},
		{name: "multi statement with trailing set role rejected", sql: "SELECT 1; SET ROLE x", reason: RejectClientRoleChange},
		{name: "multi statement with do block rejected", sql: "SELECT 1; DO $$ BEGIN END $$", reason: RejectDoBlock},

		// SET of other GUCs is fine — only role-changing statements are rejected.
		{name: "set search_path allowed", sql: "SET search_path = public", allowed: true},
		{name: "set local search_path allowed", sql: "SET LOCAL search_path = public", allowed: true},

		// A pinned setting may not be mutated by the client through any form.
		{name: "set pinned rejected", sql: "SET centaur.slack_channel_id = 'C999'", pinned: pinned, reason: RejectPinnedSetting},
		{name: "set local pinned rejected", sql: "SET LOCAL centaur.slack_channel_id = 'C999'", pinned: pinned, reason: RejectPinnedSetting},
		{name: "reset pinned rejected", sql: "RESET centaur.slack_channel_id", pinned: pinned, reason: RejectPinnedSetting},
		{name: "set_config pinned rejected", sql: "SELECT set_config('centaur.slack_channel_id', 'C999', false)", pinned: pinned, reason: RejectSetConfig},
		{name: "set pinned buried in batch rejected", sql: "SELECT 1; SET centaur.slack_channel_id = 'C999'", pinned: pinned, reason: RejectPinnedSetting},
		{name: "reset all rejected even with pin", sql: "RESET ALL", pinned: pinned, reason: RejectResetAll},
		// Reading a pinned setting is fine; only writes are blocked.
		{name: "current_setting pinned allowed", sql: "SELECT current_setting('centaur.slack_channel_id')", pinned: pinned, allowed: true},
		// A setting that isn't pinned passes through.
		{name: "set unpinned allowed", sql: "SET centaur.other = 'x'", pinned: pinned, allowed: true},
		// Without a pin, the same SET is allowed.
		{name: "set formerly-pinned allowed without pin", sql: "SET centaur.slack_channel_id = 'C999'", allowed: true},

		// Inspectable SQL-language routine bodies are checked recursively. Calls
		// to routines already installed by the database remain the operator's
		// responsibility; definitions in opaque languages are rejected.
		{
			name:    "benign sql function allowed",
			sql:     "CREATE FUNCTION f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$",
			allowed: true,
		},
		{
			name:   "sql function cannot change pinned guc",
			sql:    "CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $$ SELECT set_config('centaur.slack_user', 'U999', false) $$",
			pinned: pinned,
			reason: RejectSetConfig,
		},
		{
			name:   "sql function set clause cannot change pinned guc",
			sql:    "CREATE FUNCTION f() RETURNS integer LANGUAGE sql SET centaur.slack_user = 'U999' AS $$ SELECT 1 $$",
			pinned: pinned,
			reason: RejectPinnedSetting,
		},
		{
			name:   "sql procedure cannot reset settings",
			sql:    "CREATE PROCEDURE p() LANGUAGE sql AS $$ RESET ALL $$",
			reason: RejectResetAll,
		},
		{
			name:    "benign plpgsql function allowed",
			sql:     "CREATE FUNCTION f() RETURNS text LANGUAGE plpgsql AS $$ BEGIN RETURN 'ok'; END $$",
			allowed: true,
		},
		{
			name:   "plpgsql function cannot change pinned guc",
			sql:    "CREATE FUNCTION f() RETURNS text LANGUAGE plpgsql AS $$ BEGIN RETURN set_config('centaur.slack_user', 'U999', false); END $$",
			pinned: pinned,
			reason: RejectSetConfig,
		},
		{
			name:   "plpgsql procedure cannot set pinned guc",
			sql:    "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ BEGIN SET centaur.slack_user = 'U999'; END $$",
			pinned: pinned,
			reason: RejectPinnedSetting,
		},
		{
			name:   "plpgsql dynamic sql rejected",
			sql:    "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE 'SELECT 1'; END $$",
			reason: RejectUninspectableRoutine,
		},
		{
			name:    "sql function may call existing routine",
			sql:     "CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $$ SELECT existing_wrapper() $$",
			allowed: true,
		},

		// Function-call bypass attempts — caught by AST walker.
		{name: "set_config role rejected", sql: "SELECT set_config('role', 'admin', false)", reason: RejectSetConfig},
		{name: "pg_catalog set_config role rejected", sql: "SELECT pg_catalog.set_config('role', 'admin', false)", reason: RejectSetConfig},
		{name: "set_config session_authorization rejected", sql: "SELECT set_config('session_authorization', 'admin', false)", reason: RejectSetConfig},
		{name: "set_config role in cte rejected", sql: "WITH x AS (SELECT set_config('role', 'admin', false)) SELECT * FROM x", reason: RejectSetConfig},
		{name: "set_config non-role setting rejected", sql: "SELECT set_config('search_path', 'public', false)", reason: RejectSetConfig},
		{name: "set_config parameter target rejected", sql: "SELECT set_config($1, $2, false)", reason: RejectSetConfig},
		{name: "set_config cast target rejected", sql: "SELECT set_config('role'::text, 'admin', false)", reason: RejectSetConfig},
		{name: "current_setting role allowed", sql: "SELECT current_setting('role')", allowed: true},

		// DO blocks rejected outright.
		{name: "do block rejected", sql: "DO $$ BEGIN END $$", reason: RejectDoBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := ClassifyClientStatement(tt.sql, tt.pinned)
			if tt.allowed {
				require.Truef(t, allowed, "ClassifyClientStatement(%q) returned (false, %v); want allowed", tt.sql, reason)
				return
			}
			require.Falsef(t, allowed, "ClassifyClientStatement(%q) returned (true, _); want reject reason %v", tt.sql, tt.reason)
			require.Equalf(t, tt.reason, reason, "ClassifyClientStatement(%q) reason", tt.sql)
		})
	}
}

func TestNewManagedUpstream(t *testing.T) {
	dsn := staticDSN{name: "dsn", value: "host=db"}

	u, err := NewManagedUpstream("analytics", dsn, "readonly", nil)
	require.NoError(t, err)
	require.Equal(t, "analytics", u.Database())
	require.Equal(t, "readonly", u.Role())

	// Absent role is allowed (no SET ROLE issued).
	u, err = NewManagedUpstream("main", dsn, "", nil)
	require.NoError(t, err)
	require.Empty(t, u.Role())

	// Settings are carried through and pinned.
	u, err = NewManagedUpstream("centaur", dsn, "reader", []Setting{{Name: "centaur.slack_channel_id", Value: "C123"}})
	require.NoError(t, err)
	require.Equal(t, []Setting{{Name: "centaur.slack_channel_id", Value: "C123"}}, u.Settings())
	require.Contains(t, u.PinnedGUCs(), "centaur.slack_channel_id")

	// Settings are validated identically to the YAML path.
	_, err = NewManagedUpstream("centaur", dsn, "", []Setting{{Name: "role", Value: "x"}})
	require.ErrorContains(t, err, "managed by the proxy")

	// Required fields.
	_, err = NewManagedUpstream("", dsn, "", nil)
	require.ErrorContains(t, err, "database is required")
	_, err = NewManagedUpstream("d", nil, "", nil)
	require.ErrorContains(t, err, "dsn source is required")
}

func TestNewListener(t *testing.T) {
	dsn := staticDSN{name: "dsn", value: "host=db"}
	mustUpstream := func(database string) *Upstream {
		u, err := NewManagedUpstream(database, dsn, "", nil)
		require.NoError(t, err)
		return u
	}

	l, err := NewListener("127.0.0.1:0", "app", "pw", []*Upstream{mustUpstream("a"), mustUpstream("b")})
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:0", l.Listen())
	require.Equal(t, "a", l.Upstream("a").Database())
	require.Equal(t, "b", l.Upstream("b").Database())
	require.Nil(t, l.Upstream("missing"))
	require.Len(t, l.Upstreams(), 2)
	// The client credential is on the listener, shared across upstreams.
	require.True(t, l.VerifyClient("app", "pw"))

	// Required fields and duplicate-database guard.
	_, err = NewListener("", "app", "pw", []*Upstream{mustUpstream("a")})
	require.ErrorContains(t, err, "listen is required")
	_, err = NewListener("127.0.0.1:0", "", "pw", []*Upstream{mustUpstream("a")})
	require.ErrorContains(t, err, "client user is required")
	_, err = NewListener("127.0.0.1:0", "app", "", []*Upstream{mustUpstream("a")})
	require.ErrorContains(t, err, "client password is required")
	_, err = NewListener("127.0.0.1:0", "app", "pw", nil)
	require.ErrorContains(t, err, "at least one upstream is required")
	_, err = NewListener("127.0.0.1:0", "app", "pw", []*Upstream{mustUpstream("a"), mustUpstream("a")})
	require.ErrorContains(t, err, `duplicate upstream database "a"`)
}

func TestListenerWithUpstreams(t *testing.T) {
	dsn := staticDSN{name: "dsn", value: "host=db"}
	mustUpstream := func(database string) *Upstream {
		u, err := NewManagedUpstream(database, dsn, "", nil)
		require.NoError(t, err)
		return u
	}

	base, err := NewListener("127.0.0.1:0", "app", "pw", []*Upstream{mustUpstream("a")})
	require.NoError(t, err)

	merged, dropped := base.WithUpstreams([]*Upstream{mustUpstream("b"), mustUpstream("a")})
	require.Equal(t, []string{"a"}, dropped, "existing database wins")
	require.Len(t, merged.Upstreams(), 2)
	require.NotNil(t, merged.Upstream("a"))
	require.NotNil(t, merged.Upstream("b"))
	require.Equal(t, "127.0.0.1:0", merged.Listen())
	require.True(t, merged.VerifyClient("app", "pw"), "client credential is carried over")
}

func TestQuoteIdent(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"tenant_role", `"tenant_role"`},
		{"Tenant Role", `"Tenant Role"`},
		{`weird"name`, `"weird""name"`},
		{"", `""`},
	}
	for _, c := range cases {
		require.Equalf(t, c.out, QuoteIdent(c.in), "QuoteIdent(%q)", c.in)
	}
}
