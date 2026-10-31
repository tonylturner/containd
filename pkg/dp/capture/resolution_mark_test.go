// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"errors"
	"syscall"
	"testing"
)

func TestResolutionRepeatMarks(t *testing.T) {
	for _, path := range []string{"settle", "resolved", "staged"} {
		for _, conflict := range []bool{false, true} {
			t.Run(path+map[bool]string{false: "/same", true: "/conflict"}[conflict], func(t *testing.T) {
				fx := newInlineFixture(t)
				var submitted []submission
				fx.gen.submit = func(id uint32, v Verdict, mark uint32) error {
					submitted = append(submitted, submission{tok: NewToken(fx.gen.id, id), v: v, mark: mark})
					return nil
				}
				resolutions := func(tok Token) []Resolution {
					other := uint32(0x040000ab)
					if conflict {
						other ^= 0x10000000
					}
					return []Resolution{{Token: tok, Verdict: VerdictRepeat, Mark: 0x040000ab},
						{Token: tok, Verdict: VerdictRepeat, Mark: other}}
				}
				var tok Token
				switch path {
				case "settle":
					tok = fx.hold(1)
					errs := fx.settler.Settle(resolutions(tok)...)
					for _, err := range errs {
						if conflict != errors.Is(err, ErrConflictingVerdicts) {
							t.Fatalf("conflict=%v error=%v", conflict, err)
						}
					}
				case "resolved":
					tok = fx.hold(1)
					fx.deliver(2, func(Packet) Decision { return Decision{Action: Hold, Resolved: resolutions(tok)} })
				case "staged":
					tok = fx.deliver(1, func(p Packet) Decision {
						fx.settler.Settle(resolutions(p.Token)...)
						return Decision{Action: Hold}
					})
				}
				want, mark := VerdictRepeat, uint32(0x040000ab)
				if conflict {
					want, mark = VerdictDrop, 0
				}
				if len(submitted) != 1 || submitted[0].tok != tok || submitted[0].v != want || submitted[0].mark != mark {
					t.Fatalf("submissions: %+v", submitted)
				}
				done := fx.completions()
				if len(done) != 1 || done[0].v != want || conflict != errors.Is(done[0].err, ErrConflictingVerdicts) {
					t.Fatalf("completions: %+v", done)
				}
				if fx.gen.failure() != nil {
					t.Fatalf("token conflict failed source: %v", fx.gen.failure())
				}
			})
		}
	}
}

func TestResolutionRepeatDropWins(t *testing.T) {
	fx := newInlineFixture(t)
	tok := fx.hold(1)
	errs := fx.settler.Settle(Resolution{Token: tok, Verdict: VerdictRepeat, Mark: 123},
		Resolution{Token: tok, Verdict: VerdictDrop},
		Resolution{Token: tok, Verdict: VerdictRepeat, Mark: 456})
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := fx.kernelVerdicts(); len(got) != 1 || got[0].v != VerdictDrop {
		t.Fatalf("kernel: %+v", got)
	}
}

func TestResolutionFlushedTokenDoesNotFailSource(t *testing.T) {
	fx := newInlineFixture(t)
	tok := fx.hold(1)
	fx.submitErr[1] = syscall.ENOENT
	if err := fx.settler.Settle(Resolution{Token: tok, Verdict: VerdictRepeat, Mark: 123})[0]; !errors.Is(err, syscall.ENOENT) {
		t.Fatal(err)
	}
	if fx.gen.failure() != nil {
		t.Fatal("flushed token failed source")
	}
	if err := fx.settler.Settle(Resolution{Token: tok, Verdict: VerdictDrop})[0]; !errors.Is(err, ErrUnknownToken) {
		t.Fatalf("token not retired: %v", err)
	}
	fx.deliver(2, func(Packet) Decision { return Decision{Action: Accept} })
	if len(fx.kernelVerdicts()) != 2 {
		t.Fatal("queue no longer usable")
	}
}
