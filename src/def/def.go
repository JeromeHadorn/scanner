package def

import yara "github.com/hillu/go-yara/v4"

type FileAccessIssue struct {
	Path string
	Err  error
}
type ScanFailure struct {
	File  string // Where issue was experienced
	Error error
}
type ScanMatch struct {
	File           string
	Rulename       string
	Namespace      string
	Tags           []string
	Metas          []yara.Meta
	MatchedStrings []yara.MatchString
}
