package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want OpKind
	}{
		// Empty / whitespace / comments
		{name: "empty", sql: "", want: OpEmpty},
		{name: "whitespace only", sql: "   \n\t", want: OpEmpty},
		{name: "comment only", sql: "-- nothing\n", want: OpEmpty},

		// Direct SET ROLE / SESSION AUTHORIZATION (the regex classifier's
		// core cases — must still work after the AST swap).
		{name: "set role unquoted", sql: "SET ROLE tenant_a", want: OpSetRole},
		{name: "set role lowercase", sql: "set role tenant_a", want: OpSetRole},
		{name: "set role quoted", sql: `SET ROLE "Tenant-A"`, want: OpSetRole},
		{name: "set local role", sql: "SET LOCAL ROLE tenant_a", want: OpSetRole},
		{name: "set session role", sql: "SET SESSION ROLE tenant_a", want: OpSetRole},
		{name: "set session authorization", sql: "SET SESSION AUTHORIZATION admin", want: OpSetSessionAuthorization},
		{name: "set local session auth", sql: "SET LOCAL SESSION AUTHORIZATION admin", want: OpSetSessionAuthorization},
		{name: "reset role", sql: "RESET ROLE", want: OpResetRole},
		{name: "reset session authorization", sql: "RESET SESSION AUTHORIZATION", want: OpResetSessionAuthorization},

		// Non-role SET / RESET — must not be classified as role change.
		{name: "set search_path is other", sql: "SET search_path = public", want: OpOther},
		{name: "reset search_path is other", sql: "RESET search_path", want: OpOther},
		{name: "set local search_path is other", sql: "SET LOCAL search_path = public", want: OpOther},

		// Plain user queries
		{name: "select is other", sql: "SELECT 1", want: OpOther},
		{name: "update is other", sql: "UPDATE t SET x = 1", want: OpOther},
		{name: "insert is other", sql: "INSERT INTO t VALUES (1)", want: OpOther},

		// Transaction control — not a role change; the relay forwards.
		{name: "begin", sql: "BEGIN", want: OpOther},
		{name: "commit", sql: "COMMIT", want: OpOther},
		{name: "rollback", sql: "ROLLBACK", want: OpOther},
		{name: "start transaction", sql: "START TRANSACTION", want: OpOther},
		{name: "savepoint", sql: "SAVEPOINT a", want: OpOther},

		// Multi-statement — classified per statement; the batch takes the
		// verdict of its first rejectable statement, else OpOther.
		{name: "multi set then select rejects on set role", sql: "SET ROLE tenant; SELECT 1", want: OpSetRole},
		{name: "multi select then select allowed", sql: "SELECT 1; SELECT 2", want: OpOther},
		{name: "multi benign then set role", sql: "SELECT 1; SET ROLE tenant", want: OpSetRole},
		{name: "multi benign then do block", sql: "SELECT 1; DO $$ BEGIN END $$", want: OpDoBlock},
		{name: "multi benign then set_config role", sql: "SELECT 1; SELECT set_config('role', 'admin', false)", want: OpSetConfig},
		{name: "multi non-role sets allowed", sql: "SET search_path = public; SELECT 1", want: OpOther},
		// Trailing semicolon alone is *not* multi (pg_query collapses it).
		{name: "trailing semicolon not multi", sql: "SET ROLE tenant;", want: OpSetRole},

		// set_config function-call bypass attempts
		{name: "set_config role top level", sql: "SELECT set_config('role', 'admin', false)", want: OpSetConfig},
		{name: "set_config role local flag", sql: "SELECT set_config('role', 'admin', true)", want: OpSetConfig},
		{name: "pg_catalog set_config role", sql: "SELECT pg_catalog.set_config('role', 'admin', false)", want: OpSetConfig},
		{name: "set_config session_authorization", sql: "SELECT set_config('session_authorization', 'admin', false)", want: OpSetConfig},
		{name: "set_config case insensitive name", sql: "SELECT set_config('ROLE', 'admin', false)", want: OpSetConfig},
		{name: "set_config nested in select", sql: "SELECT 1, set_config('role', 'admin', false), 2", want: OpSetConfig},
		{name: "set_config in subquery", sql: "SELECT * FROM (SELECT set_config('role', 'admin', false)) s", want: OpSetConfig},
		{name: "set_config in cte", sql: "WITH x AS (SELECT set_config('role', 'admin', false)) SELECT * FROM x", want: OpSetConfig},
		{name: "set_config in where clause", sql: "SELECT 1 WHERE set_config('role', 'admin', false) = 'admin'", want: OpSetConfig},
		{name: "set_config inside insert", sql: "INSERT INTO t SELECT set_config('role', 'admin', false)", want: OpSetConfig},
		{name: "set_config non-role setting", sql: "SELECT set_config('search_path', 'public', false)", want: OpSetConfig},
		{name: "set_config parameter target", sql: "SELECT set_config($1, $2, false)", want: OpSetConfig},
		{name: "set_config cast target", sql: "SELECT set_config('role'::text, 'admin', false)", want: OpSetConfig},
		{name: "set_config computed target", sql: "SELECT set_config(concat('ro', 'le'), 'admin', false)", want: OpSetConfig},
		{name: "current_setting role is read only", sql: "SELECT current_setting('role')", want: OpOther},

		// PREPARE wrapping a SELECT that calls set_config — caught by the
		// walker through the nested SelectStmt.
		{name: "prepare wrapping set_config caught", sql: "PREPARE p AS SELECT set_config('role', 'admin', false)", want: OpSetConfig},

		// pg_settings writes reach set_config through its update rule; an
		// auto-updatable view or a rule over it forwards writes the same way.
		{name: "update pg_settings", sql: "UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout'", want: OpSettingsCatalogWrite},
		{name: "update qualified pg_settings", sql: "UPDATE pg_catalog.pg_settings SET setting = '0' WHERE name = 'statement_timeout'", want: OpSettingsCatalogWrite},
		{name: "update pg_settings in cte", sql: "WITH x AS (UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout') SELECT 1", want: OpSettingsCatalogWrite},
		{name: "prepare update pg_settings", sql: "PREPARE p AS UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout'", want: OpSettingsCatalogWrite},
		{name: "insert pg_settings", sql: "INSERT INTO pg_settings (name, setting) VALUES ('statement_timeout', '0')", want: OpSettingsCatalogWrite},
		{name: "view over pg_settings", sql: "CREATE TEMP VIEW v AS SELECT * FROM pg_settings", want: OpSettingsCatalogWrite},
		{name: "view over pg_settings subquery", sql: "CREATE VIEW v AS SELECT * FROM (SELECT name, setting FROM pg_catalog.pg_settings) s", want: OpSettingsCatalogWrite},
		{name: "rule updating pg_settings", sql: "CREATE RULE r AS ON INSERT TO t DO ALSO UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout'", want: OpSettingsCatalogWrite},
		{name: "multi benign then update pg_settings", sql: "SELECT 1; UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout'", want: OpSettingsCatalogWrite},
		{name: "select pg_settings is other", sql: "SELECT setting FROM pg_settings WHERE name = 'statement_timeout'", want: OpOther},
		{name: "update reading pg_settings is other", sql: "UPDATE t SET x = (SELECT setting FROM pg_settings WHERE name = 'work_mem')", want: OpOther},
		{name: "view not over pg_settings is other", sql: "CREATE VIEW v AS SELECT * FROM t", want: OpOther},

		// Definitions that bind existing functions as implicitly invoked
		// callbacks create executable aliases the FuncCall check cannot see.
		{name: "aggregate with set_config sfunc", sql: "CREATE AGGREGATE pg_temp.a(text, boolean) (SFUNC = pg_catalog.set_config, STYPE = text)", want: OpCallbackDefinition},
		{name: "aggregate with benign sfunc", sql: "CREATE AGGREGATE a(integer) (SFUNC = int4pl, STYPE = integer)", want: OpCallbackDefinition},
		{name: "operator definition", sql: "CREATE OPERATOR === (LEFTARG = text, RIGHTARG = text, FUNCTION = texteq)", want: OpCallbackDefinition},
		{name: "base type definition", sql: "CREATE TYPE t (INPUT = t_in, OUTPUT = t_out)", want: OpCallbackDefinition},
		{name: "range type definition", sql: "CREATE TYPE r AS RANGE (SUBTYPE = integer, SUBTYPE_DIFF = f)", want: OpCallbackDefinition},
		{name: "cast with function", sql: "CREATE CAST (text AS t) WITH FUNCTION f(text)", want: OpCallbackDefinition},
		{name: "operator class support function", sql: "CREATE OPERATOR CLASS c FOR TYPE t USING btree AS FUNCTION 1 f(t, t)", want: OpCallbackDefinition},
		{name: "alter operator family add function", sql: "ALTER OPERATOR FAMILY fam USING btree ADD FUNCTION 1 f(t, t)", want: OpCallbackDefinition},
		{name: "alter operator restrict", sql: "ALTER OPERATOR === (text, text) SET (RESTRICT = f)", want: OpCallbackDefinition},
		{name: "alter type set callbacks", sql: "ALTER TYPE t SET (SEND = f)", want: OpCallbackDefinition},
		{name: "conversion definition", sql: "CREATE CONVERSION c FOR 'UTF8' TO 'LATIN1' FROM f", want: OpCallbackDefinition},
		{name: "multi benign then aggregate", sql: "SELECT 1; CREATE AGGREGATE a(text, boolean) (SFUNC = set_config, STYPE = text)", want: OpCallbackDefinition},
		{name: "composite type is other", sql: "CREATE TYPE t AS (a integer, b text)", want: OpOther},
		{name: "enum type is other", sql: "CREATE TYPE e AS ENUM ('a', 'b')", want: OpOther},
		{name: "collation is other", sql: "CREATE COLLATION c (provider = icu, locale = 'und')", want: OpOther},

		// DO blocks — rejected regardless of contents.
		{name: "do block empty", sql: "DO $$ BEGIN END $$", want: OpDoBlock},
		{name: "do block with set role", sql: "DO $$ BEGIN EXECUTE 'SET ROLE admin'; END $$", want: OpDoBlock},

		// SQL function and procedure bodies are parsed recursively. Other
		// languages remain opaque and are rejected fail-closed.
		{
			name: "benign sql function",
			sql:  "CREATE FUNCTION f() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$",
			want: OpOther,
		},
		{
			name: "sql function calls set_config",
			sql:  "CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $$ SELECT set_config('centaur.slack_user', 'U999', false) $$",
			want: OpSetConfig,
		},
		{
			name: "sql function changes role",
			sql:  "CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $$ SET ROLE none; SELECT current_role::text $$",
			want: OpSetRole,
		},
		{
			name: "sql procedure resets all",
			sql:  "CREATE PROCEDURE p() LANGUAGE sql AS $$ RESET ALL $$",
			want: OpOther,
		},
		{
			name: "sql standard body calls set_config",
			sql:  "CREATE FUNCTION f() RETURNS text LANGUAGE sql RETURN set_config('centaur.slack_user', 'U999', false)",
			want: OpSetConfig,
		},
		{
			name: "sql function delegates to existing function",
			sql:  "CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $$ SELECT existing_wrapper() $$",
			want: OpOther,
		},
		{
			name: "benign plpgsql function",
			sql:  "CREATE FUNCTION f() RETURNS text LANGUAGE plpgsql AS $$ BEGIN RETURN 'ok'; END $$",
			want: OpOther,
		},
		{
			name: "plpgsql return calls set_config",
			sql:  "CREATE FUNCTION f() RETURNS text LANGUAGE plpgsql AS $$ BEGIN RETURN set_config('centaur.slack_user', 'U999', false); END $$",
			want: OpSetConfig,
		},
		{
			name: "plpgsql assignment calls set_config",
			sql:  "CREATE FUNCTION f() RETURNS text LANGUAGE plpgsql AS $$ DECLARE x text; BEGIN x := set_config('centaur.slack_user', 'U999', false); RETURN x; END $$",
			want: OpSetConfig,
		},
		{
			name: "plpgsql perform calls set_config",
			sql:  "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN PERFORM set_config('centaur.slack_user', 'U999', false); END $$",
			want: OpSetConfig,
		},
		{
			name: "sql function updates pg_settings",
			sql:  "CREATE FUNCTION f() RETURNS void LANGUAGE sql AS $$ UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout' $$",
			want: OpSettingsCatalogWrite,
		},
		{
			name: "plpgsql function updates pg_settings",
			sql:  "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN UPDATE pg_settings SET setting = '0' WHERE name = 'statement_timeout'; END $$",
			want: OpSettingsCatalogWrite,
		},
		{
			name: "plpgsql procedure sets pinned guc",
			sql:  "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ BEGIN SET centaur.slack_user = 'U999'; END $$",
			want: OpOther,
		},
		{
			name: "plpgsql dynamic execute is uninspectable",
			sql:  "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE 'SET centaur.slack_user = ''U999'''; END $$",
			want: OpUninspectableRoutine,
		},
		{
			name: "plpgsql dynamic cursor is uninspectable",
			sql:  "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ DECLARE c refcursor; BEGIN OPEN c FOR EXECUTE 'SELECT 1'; END $$",
			want: OpUninspectableRoutine,
		},
		{
			name: "plpgsql routine after another statement uses its own source",
			sql:  "SELECT 1; CREATE FUNCTION f() RETURNS text LANGUAGE plpgsql AS $$ BEGIN RETURN set_config('centaur.slack_user', 'U999', false); END $$",
			want: OpSetConfig,
		},
		{
			name: "native function is uninspectable",
			sql:  "CREATE FUNCTION f(integer) RETURNS integer AS 'module', 'symbol' LANGUAGE C STRICT",
			want: OpUninspectableRoutine,
		},
		{
			name: "invalid sql body is uninspectable",
			sql:  "CREATE FUNCTION f() RETURNS integer LANGUAGE sql AS $$ this is not sql $$",
			want: OpUninspectableRoutine,
		},

		// Parse errors — forwarded.
		{name: "syntax error", sql: "INSERT FROM WHERE", want: OpParseError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := Classify(tt.sql)
			require.Equalf(t, tt.want, op.Kind, "Classify(%q).Kind", tt.sql)
		})
	}
}

// TestClassifyMutationFacts covers the generic GUC-mutation facts Classify
// reports (independent of the role-specific Kind): the names written, and the
// reset-everything statements RESET ALL / DISCARD ALL.
func TestClassifyMutationFacts(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		setGUCs  []string
		resetAll bool
		discard  bool
	}{
		{name: "set custom guc", sql: "SET centaur.slack_channel_id = 'C123'", setGUCs: []string{"centaur.slack_channel_id"}},
		{name: "set local custom guc", sql: "SET LOCAL centaur.slack_channel_id = 'C123'", setGUCs: []string{"centaur.slack_channel_id"}},
		{name: "reset custom guc", sql: "RESET centaur.slack_channel_id", setGUCs: []string{"centaur.slack_channel_id"}},
		{name: "set_config custom guc", sql: "SELECT set_config('centaur.slack_channel_id', 'C123', false)", setGUCs: []string{"centaur.slack_channel_id"}},
		{name: "name lowercased", sql: "SET Centaur.Slack_Channel_ID = 'C123'", setGUCs: []string{"centaur.slack_channel_id"}},
		{name: "search_path collected", sql: "SET search_path = public", setGUCs: []string{"search_path"}},
		{name: "multi statement collects all", sql: "SET a.x = '1'; SET a.y = '2'", setGUCs: []string{"a.x", "a.y"}},
		{name: "reset all flagged", sql: "RESET ALL", resetAll: true},
		{name: "discard all flagged", sql: "DISCARD ALL", discard: true},
		{name: "discard plans not flagged", sql: "DISCARD PLANS"},
		{
			name:     "sql procedure body reset all",
			sql:      "CREATE PROCEDURE p() LANGUAGE sql AS $$ RESET ALL $$",
			resetAll: true,
		},
		{
			name:    "sql function set clause collected",
			sql:     "CREATE FUNCTION f() RETURNS integer LANGUAGE sql SET centaur.slack_user = 'U999' AS $$ SELECT 1 $$",
			setGUCs: []string{"centaur.slack_user"},
		},
		{
			name:    "plpgsql procedure body set collected",
			sql:     "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ BEGIN SET centaur.slack_user = 'U999'; END $$",
			setGUCs: []string{"centaur.slack_user"},
		},
		{name: "select writes nothing", sql: "SELECT 1"},
		{name: "current_setting writes nothing", sql: "SELECT current_setting('centaur.slack_channel_id')"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := Classify(tt.sql)
			require.ElementsMatchf(t, tt.setGUCs, op.SetGUCs, "Classify(%q).SetGUCs", tt.sql)
			require.Equalf(t, tt.resetAll, op.ResetAll, "Classify(%q).ResetAll", tt.sql)
			require.Equalf(t, tt.discard, op.Discard, "Classify(%q).Discard", tt.sql)
		})
	}
}
