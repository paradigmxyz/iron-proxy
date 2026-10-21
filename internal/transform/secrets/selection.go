package secrets

import (
	"net/http"
	"strings"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
)

func (s *Secrets) selectAlternatives(req *http.Request) (map[string]int, string) {
	selected := make(map[string]int)
	for i, sec := range s.secrets {
		if sec.selectionGroup == "" || !hostmatch.MatchAnyRule(sec.rules, req) {
			continue
		}
		previous, exists := selected[sec.selectionGroup]
		if !exists {
			selected[sec.selectionGroup] = -1
		}
		if !sec.selectedByHeaders(req.Header) {
			continue
		}
		if exists && previous >= 0 {
			return nil, sec.selectionGroup
		}
		selected[sec.selectionGroup] = i
	}
	if len(selected) == 0 {
		return nil, ""
	}
	for group, index := range selected {
		if index < 0 {
			return nil, group
		}
	}
	owners := make(map[string]string)
	for _, sec := range s.secrets {
		if sec.selectionGroup == "" || !hostmatch.MatchAnyRule(sec.rules, req) {
			continue
		}
		chosen := s.secrets[selected[sec.selectionGroup]]
		for name, values := range req.Header {
			if !sec.matchesHeader(name) {
				continue
			}
			canonical := http.CanonicalHeaderKey(name)
			if owner, exists := owners[canonical]; exists && owner != sec.selectionGroup {
				return nil, sec.selectionGroup
			}
			owners[canonical] = sec.selectionGroup
			for _, value := range values {
				if !chosen.matchesHeader(name) || !matchesProxyValue(value, chosen.proxyValue) {
					return nil, sec.selectionGroup
				}
			}
		}
	}
	for _, sec := range s.secrets {
		if sec.selectionGroup != "" || !hostmatch.MatchAnyRule(sec.rules, req) {
			continue
		}
		if sec.mode == "inject" && sec.injectHeader != "" {
			for _, grouped := range s.secrets {
				if grouped.selectionGroup != "" && grouped.matchesHeader(sec.injectHeader) && hostmatch.MatchAnyRule(grouped.rules, req) {
					return nil, grouped.selectionGroup
				}
			}
		}
		for name, group := range owners {
			if sec.mode == "replace" && (len(sec.matchHeaders) == 0 || sec.matchesHeader(name)) {
				return nil, group
			}
		}
	}
	return selected, ""
}

func (sec *resolvedSecret) selectedByHeaders(header http.Header) bool {
	for name, values := range header {
		if !sec.matchesHeader(name) {
			continue
		}
		for _, value := range values {
			if matchesProxyValue(value, sec.proxyValue) {
				return true
			}
		}
	}
	return false
}

func (sec *resolvedSecret) matchesHeader(name string) bool {
	for _, matcher := range sec.matchHeaders {
		if strings.EqualFold(name, matcher.name) || (matcher.re != nil && matcher.re.MatchString(name)) {
			return true
		}
	}
	return false
}

func matchesProxyValue(value, marker string) bool {
	return value == marker || (len(value) >= 7 && strings.EqualFold(value[:7], "Bearer ") && value[7:] == marker)
}
