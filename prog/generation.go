// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
)

// Generate generates a random program of length ~ncalls.
// calls is a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct)
	// p.calls表示已经生成的函数,如果少于30个，则继续
	for len(p.Calls) < ncalls {
		var calls []*Call
		if ct.index == 0 {
			calls = r.generateCall(s, p)
		} else {
			calls = r.myGenerateCall(s, p)
		}
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	if debug {
		if err := p.validate(); err != nil {
			panic(err)
		}
	}
	return p
}
