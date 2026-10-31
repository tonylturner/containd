// SPDX-License-Identifier: Apache-2.0
package ics

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestProtocolVocabularyHasNoLegacyLearnerGate(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "protocols.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Learnable" {
			t.Fatal("legacy protocol-wide learner gate must not survive the explicit evidence workflow")
		}
	}
}
