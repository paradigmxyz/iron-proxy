package postgres

// RejectReason categorizes why the proxy is refusing a client message in the
// relay loop. Surfaced as the synthetic ErrorResponse's Message and on
// structured logs.
type RejectReason int

const (
	// RejectClientRoleChange — the client tried to issue
	// SET ROLE / RESET ROLE / SET SESSION AUTHORIZATION / RESET SESSION AUTHORIZATION.
	// The proxy sets the role at session start and forbids overrides.
	RejectClientRoleChange RejectReason = iota + 1
	// RejectDoBlock — the client sent a DO $$ ... $$ anonymous code block.
	// The plpgsql body is opaque to our SQL-level AST walker; rejecting
	// avoids the risk of an embedded role change.
	RejectDoBlock
	// RejectPinnedSetting — the client tried to SET or RESET a session variable
	// the upstream pins. The proxy sets these at session start and forbids
	// overrides so a setting used as a security boundary can't be changed.
	RejectPinnedSetting
	// RejectResetAll — the client tried RESET ALL, which would reset the
	// proxy-managed role and every pinned setting.
	RejectResetAll
	// RejectDiscardAll — the client tried DISCARD ALL, which (like RESET ALL)
	// resets the proxy-managed role and every pinned setting.
	RejectDiscardAll
	// RejectSetConfig — the client called set_config. Dynamic targets cannot be
	// inspected safely, so all calls are rejected regardless of the GUC name.
	RejectSetConfig
	// RejectFunctionCall — the client used the legacy wire-level FunctionCall
	// protocol, which invokes a function by OID without inspectable SQL text.
	RejectFunctionCall
)

// ClassifyClientStatement inspects sql and returns whether the relay should
// reject it before forwarding upstream. (reason == 0) means "allow". pinned is
// the lowercased set of setting names this upstream forbids the client from
// mutating; pass nil when the upstream pins nothing.
//
// Beyond the role policy, the proxy rejects every set_config call, any SET or
// RESET of a pinned setting, and any RESET ALL / DISCARD ALL (which would reset
// the managed role and every pinned setting at once).
//
// Multi-statement Simple Queries are allowed when every statement passes;
// Classify aggregates the batch, so a single offending statement anywhere
// rejects the whole batch.
//
// Used for both Simple Query bodies and the SQL string carried by Extended
// Query Parse messages.
func ClassifyClientStatement(sql string, pinned map[string]struct{}) (allowed bool, reason RejectReason) {
	op := Classify(sql)
	switch op.Kind {
	case OpSetRole, OpSetSessionAuthorization, OpResetRole, OpResetSessionAuthorization:
		return false, RejectClientRoleChange
	case OpSetConfig:
		return false, RejectSetConfig
	case OpDoBlock:
		// DO blocks contain opaque plpgsql we can't introspect from the SQL
		// AST. Rather than risk an embedded role change slipping through,
		// we reject them outright.
		return false, RejectDoBlock
	}
	// RESET ALL / DISCARD ALL reset the proxy-managed role regardless of which
	// settings the upstream pins, so they are always rejected.
	if op.ResetAll {
		return false, RejectResetAll
	}
	if op.Discard {
		return false, RejectDiscardAll
	}
	for _, name := range op.SetGUCs {
		if _, ok := pinned[name]; ok {
			return false, RejectPinnedSetting
		}
	}
	return true, 0
}
