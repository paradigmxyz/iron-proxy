package postgres

import (
	"strings"

	// The wasilibs package is a pure-Go (wazero-based) drop-in for pg_query_go's
	// Parse function, sparing us from a CGO build dependency. AST node types
	// still come from the pganalyze package; wasilibs re-uses them.
	pg_query "github.com/pganalyze/pg_query_go/v6"
	pgparse "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/reflect/protoreflect"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Op classifies a Postgres query string for the role-policy relay.
//
// The classifier uses the actual PostgreSQL parser (via libpg_query) to walk
// the AST, which lets it catch indirect role-change attempts that a regex
// lexer would miss — e.g. `SELECT set_config('role', 'admin', false)`,
// `WITH x AS (SELECT pg_catalog.set_config('role', ...)) SELECT * FROM x`,
// or `PREPARE p AS SET ROLE admin`.
type Op struct {
	// Kind is the classified statement kind. It captures the role-policy verdict
	// (OpSetRole and friends), DO blocks, parse errors, and empties — the cases
	// that don't depend on which custom GUCs a given upstream pins.
	Kind OpKind

	// SetGUCs is the lowercased set of GUC names the statement writes through
	// SET / RESET <name> / set_config(<name>, ...). Role and
	// session_authorization are reported here too, but those are already
	// covered by Kind; the per-upstream policy uses this for custom pinned
	// names. Nil when the statement writes no GUC.
	SetGUCs []string

	// ResetAll is true when the statement contains RESET ALL, which resets every
	// session variable — including the proxy-managed role and any pinned GUC.
	ResetAll bool

	// Discard is true when the statement contains DISCARD ALL, which (among
	// other things) resets every session variable like RESET ALL.
	Discard bool
}

// OpKind enumerates the statement classes the policy reasons about.
type OpKind int

const (
	// OpOther is any statement not matched by a more specific case.
	OpOther OpKind = iota
	// OpSetRole is `SET ROLE <ident>` or anything anywhere in the AST that
	// changes the `role` GUC through SET, including SET LOCAL and SET SESSION.
	OpSetRole
	// OpSetSessionAuthorization is the equivalent for `session_authorization`.
	OpSetSessionAuthorization
	// OpResetRole is `RESET ROLE` or any equivalent reset of the role GUC.
	OpResetRole
	// OpResetSessionAuthorization is the same for session_authorization.
	OpResetSessionAuthorization
	// OpEmpty indicates a whitespace/comment-only input or no statements.
	OpEmpty
	// OpDoBlock is a DO $$ ... $$ block. The plpgsql body is opaque to our
	// AST walker (the SQL parser produces a single DoStmt with the body as a
	// string literal; analyzing plpgsql requires a separate parser), so we
	// reject DO blocks rather than risk missing an embedded role change.
	OpDoBlock
	// OpParseError indicates pg_query rejected the input. We forward to
	// upstream so Postgres produces the canonical syntax error; the proxy
	// doesn't try to second-guess.
	OpParseError
	// OpSetConfig is any call to set_config, regardless of schema qualification
	// or whether its target setting is a string literal. Dynamic targets cannot
	// be proven safe at Parse time, so the policy rejects the function wholesale.
	OpSetConfig
)

// GUC names whose mutation we treat as a role change for policy purposes.
// Case-insensitive comparison; Postgres treats GUC names case-insensitively.
var roleGUCs = map[string]OpKind{
	"role":                  OpSetRole,
	"session_authorization": OpSetSessionAuthorization,
}

// classifyCache memoizes Classify results so repeated queries (the common
// case in ORM workloads where the same parameterized SQL fires hundreds of
// times per connection) don't re-parse on the hot path. Bounded so a
// pathological client sending unique SQL per query can't exhaust memory.
var classifyCache *lru.Cache[string, Op]

func init() {
	c, err := lru.New[string, Op](1024)
	if err != nil {
		// lru.New only errors on size <= 0; 1024 is fixed and safe.
		panic(err)
	}
	classifyCache = c
}

// Classify returns the Op describing sql.
func Classify(sql string) Op {
	if op, ok := classifyCache.Get(sql); ok {
		return op
	}
	op := classifyUncached(sql)
	classifyCache.Add(sql, op)
	return op
}

func classifyUncached(sql string) Op {
	if strings.TrimSpace(sql) == "" {
		return Op{Kind: OpEmpty}
	}

	result, err := pgparse.Parse(sql)
	if err != nil {
		return Op{Kind: OpParseError}
	}
	stmts := result.GetStmts()
	if len(stmts) == 0 {
		return Op{Kind: OpEmpty}
	}

	// Multi-statement Simple Queries are classified per statement and the batch
	// carries the union of what its statements do. Kind takes the first
	// role-changing or DO-block statement (so the relay can reject it as before);
	// the GUC-mutation facts accumulate across the batch so the per-upstream
	// policy can reject a batch touching any pinned setting wherever it appears.
	op := Op{Kind: OpOther}
	for _, s := range stmts {
		root := s.GetStmt()
		if root == nil {
			continue
		}
		m := classifyStmt(root)
		if op.Kind == OpOther {
			op.Kind = m.kind
		}
		op.SetGUCs = append(op.SetGUCs, m.setGUCs...)
		op.ResetAll = op.ResetAll || m.resetAll
		op.Discard = op.Discard || m.discard
	}
	return op
}

// mutations is what a single statement does that the policy cares about: its
// role-policy kind (OpSetRole and friends, or OpDoBlock), the GUC names it
// writes, and whether it resets every variable via RESET ALL / DISCARD ALL.
type mutations struct {
	kind     OpKind
	setGUCs  []string
	resetAll bool
	discard  bool
}

// classifyStmt classifies a single statement's root node.
func classifyStmt(root *pg_query.Node) mutations {
	// Top-level shape gives us a fast path for the common DDL/DML cases.
	switch root.Node.(type) {
	case *pg_query.Node_TransactionStmt:
		// BEGIN / COMMIT / ROLLBACK / SAVEPOINT etc. — no GUC mutation.
		return mutations{kind: OpOther}
	case *pg_query.Node_DoStmt:
		// The plpgsql body is opaque to the SQL AST walker; we can't see GUC
		// writes inside it, so the statement is rejected wholesale via Kind.
		return mutations{kind: OpDoBlock}
	}
	return scanMutations(root)
}

// scanMutations walks the AST rooted at node and reports every GUC-affecting
// construct it finds: SET / RESET / RESET ALL, DISCARD ALL, and set_config(...)
// calls, wherever they're nested (CTEs, subqueries, PREPARE bodies, function
// arguments, ...).
//
// The walk uses protoreflect for generic descent so we don't have to maintain a
// hand-rolled case statement for every Node subtype as Postgres adds syntax.
func scanMutations(node *pg_query.Node) mutations {
	var m mutations
	walkProto(node.ProtoReflect(), func(msg protoreflect.Message) bool {
		switch n := msg.Interface().(type) {
		case *pg_query.VariableSetStmt:
			if n.GetKind() == pg_query.VariableSetKind_VAR_RESET_ALL {
				m.resetAll = true
				break
			}
			// SET, SET LOCAL, and RESET <name> all name a single GUC.
			name := strings.ToLower(n.GetName())
			if name != "" {
				m.setGUCs = append(m.setGUCs, name)
			}
			if rk := roleKindFor(name, n.GetKind()); rk != 0 && m.kind == 0 {
				m.kind = rk
			}
		case *pg_query.DiscardStmt:
			// Only DISCARD ALL resets session variables; the PLANS / SEQUENCES /
			// TEMP variants leave GUCs (and the role) intact.
			if n.GetTarget() == pg_query.DiscardMode_DISCARD_ALL {
				m.discard = true
			}
		case *pg_query.VariableShowStmt:
			// SHOW is read-only; ignore.
		case *pg_query.FuncCall:
			if name, ok := setConfigTarget(n); ok {
				if name != "" {
					m.setGUCs = append(m.setGUCs, name)
				}
				if m.kind == 0 {
					m.kind = OpSetConfig
				}
			}
		}
		return true
	})
	return m
}

// roleKindFor returns the role-policy OpKind for a SET/RESET of the named GUC,
// or 0 when the GUC is not role-affecting. kind distinguishes a write
// (OpSetRole) from a reset (OpResetRole).
func roleKindFor(name string, kind pg_query.VariableSetKind) OpKind {
	base, ok := roleGUCs[name]
	if !ok {
		return 0
	}
	if kind == pg_query.VariableSetKind_VAR_RESET {
		if base == OpSetRole {
			return OpResetRole
		}
		return OpResetSessionAuthorization
	}
	return base
}

// setConfigTarget inspects fc and reports whether it is a call to set_config,
// including schema-qualified forms. When the first argument is a string
// literal, name is its lowercased value; dynamic targets return an empty name
// with ok=true so the policy can still reject the call.
func setConfigTarget(fc *pg_query.FuncCall) (name string, ok bool) {
	names := fc.GetFuncname()
	if len(names) == 0 {
		return "", false
	}
	// Funcname is a list of String nodes: ["set_config"] for unqualified
	// or ["pg_catalog", "set_config"] for schema-qualified. We accept any
	// schema qualifier and trust that user-defined set_config functions
	// are also suspicious — better a rare false positive than a bypass.
	last := names[len(names)-1]
	lastStr, isString := last.Node.(*pg_query.Node_String_)
	if !isString {
		return "", false
	}
	if !strings.EqualFold(lastStr.String_.GetSval(), "set_config") {
		return "", false
	}
	args := fc.GetArgs()
	if len(args) < 1 {
		return "", true
	}
	param, isConst := stringConst(args[0])
	if !isConst {
		return "", true
	}
	return strings.ToLower(param), true
}

// stringConst returns the string value of node if it's an A_Const with a
// string value, else ("", false). set_config's first argument is the GUC
// name. Literal targets are retained for mutation metadata; non-literal
// targets are still classified as OpSetConfig and rejected by policy.
func stringConst(node *pg_query.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	c, ok := node.Node.(*pg_query.Node_AConst)
	if !ok {
		return "", false
	}
	sval, ok := c.AConst.Val.(*pg_query.A_Const_Sval)
	if !ok {
		return "", false
	}
	return sval.Sval.GetSval(), true
}

// walkProto invokes visit on every message in the tree rooted at m, including
// m itself, descending through any singular message or list-of-message fields.
// Returning false from visit short-circuits the walk.
func walkProto(m protoreflect.Message, visit func(protoreflect.Message) bool) bool {
	if !visit(m) {
		return false
	}
	var stop bool
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind {
			return true
		}
		switch {
		case fd.IsList():
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				if !walkProto(list.Get(i).Message(), visit) {
					stop = true
					return false
				}
			}
		case fd.IsMap():
			// pg_query has no map-of-message fields; skip for simplicity.
		default:
			if !walkProto(v.Message(), visit) {
				stop = true
				return false
			}
		}
		return true
	})
	return !stop
}
