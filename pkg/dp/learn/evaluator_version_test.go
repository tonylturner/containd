// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
	"testing"
)

func TestProofRequiresCurrentOrderedEvaluator(t *testing.T) {
	v := Versions{Schema: SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: GeneratorVersion, Evaluator: rules.EvaluatorVersion}
	if !CompatibleVersions(v) {
		t.Fatal("current proof rejected")
	}
	v.Evaluator = rules.EvaluatorVersion + "-different"
	if CompatibleVersions(v) {
		t.Fatal("proof from another evaluator accepted")
	}
}
