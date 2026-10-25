// Package rubric owns the judge prompt and the stable verdict-code vocabulary.
//
// The text is copied verbatim from cake's src/clients/judge_rubric.md. Keep the
// two files byte-identical until slice 5 moves the rubric out of cake; the
// parity test in this repository hashes the local copy and the corpus report
// records the same fingerprint.
package rubric

import (
	_ "embed"
	"fmt"
)

// Default is the embedded judge system prompt.
//
//go:embed rubric.md
var Default string

// Code is one stable verdict code. Only Warnings are advisory; every other
// code names a block class.
type Code string

const (
	GitHistoryRewrite    Code = "git-history-rewrite"
	GitWorktreeDiscard   Code = "git-worktree-discard"
	GitUntrackedDelete   Code = "git-untracked-delete"
	GitForcePush         Code = "git-force-push"
	GitBranchForceDelete Code = "git-branch-force-delete"
	GitStashDestructive  Code = "git-stash-destructive"
	DestructiveRm        Code = "destructive-rm"
	GitCommitBackticks   Code = "git-commit-backticks"
	RgReplaceFootgun     Code = "rg-replace-footgun"
	CredentialDisclosure Code = "credential-disclosure"
	DataEgress           Code = "data-egress"
	UnknownDestructive   Code = "unknown-destructive"
)

// Codes is the v1 vocabulary in cake's stable order.
var Codes = []Code{
	GitHistoryRewrite,
	GitWorktreeDiscard,
	GitUntrackedDelete,
	GitForcePush,
	GitBranchForceDelete,
	GitStashDestructive,
	DestructiveRm,
	GitCommitBackticks,
	RgReplaceFootgun,
	CredentialDisclosure,
	DataEgress,
	UnknownDestructive,
}

var known = func() map[Code]struct{} {
	set := make(map[Code]struct{}, len(Codes))
	for _, code := range Codes {
		set[code] = struct{}{}
	}
	return set
}()

// Parse returns the code when it is part of the v1 vocabulary.
func Parse(value string) (Code, bool) {
	code := Code(value)
	_, ok := known[code]
	return code, ok
}

// IsWarnClass reports whether the code may appear on a warn verdict. Only the
// rg replacement footgun warns; every other code contradicts the rubric.
func (c Code) IsWarnClass() bool {
	return c == RgReplaceFootgun
}

// Prompt returns the judge system prompt with an optional user rubric appended.
// A blank user rubric leaves the default unchanged.
func Prompt(user string) string {
	if len(user) == 0 || isBlank(user) {
		return Default
	}
	return fmt.Sprintf("%s\n\n# User-added rubric guidance\n\n%s", Default, user)
}

func isBlank(s string) bool {
	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}
