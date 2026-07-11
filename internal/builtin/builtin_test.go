package builtin

import "testing"

// TestBuiltinAskContainsPgateAdd guards against accidentally deleting the
// ask-tier entry that gates `pgate add` itself. Removing it would let an
// agent self-grant permissions without human approval, defeating the
// permission gate. If you intentionally change the list, update both this
// test and the comment block in commands.go.
func TestBuiltinAskContainsPgateAdd(t *testing.T) {
	for _, c := range Ask() {
		if c == "pgate add" {
			return
		}
	}
	t.Fatal("builtin.Ask() must contain 'pgate add' so agents cannot self-grant permissions")
}

// TestBuiltinAllowKeepsPgate makes sure the wrapper-allow entry stays
// even after we add 'pgate add' to ask. The engine's deny → ask → allow
// ordering means a more-specific ask entry outranks a broader allow entry
// for the same prefix, so 'pgate add' falls into ask while 'pgate check'
// / 'pgate update' / 'pgate version' remain in allow.
func TestBuiltinAllowKeepsPgate(t *testing.T) {
	for _, c := range Allow() {
		if c == "pgate" {
			return
		}
	}
	t.Fatal("builtin.Allow() must keep 'pgate' so check/update/version/init don't trigger ask")
}
