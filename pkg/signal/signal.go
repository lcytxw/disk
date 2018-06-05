// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package signal provides types for working with feedback signal.
package signal

import (
	"sort"
)

type (
	elemType uint32
	prioType int8
)

type Signal map[elemType]prioType

type Serial struct {
	Elems []elemType
	Prios []prioType
}

func (s Signal) Len() int {
	return len(s)
}

func (s Signal) Empty() bool {
	return len(s) == 0
}

// 发现包含新路径的函数之后，将这个函数的执行路径添加优先级之后以Signal的形式返回
func FromRaw(raw []uint32, prio uint8) Signal {
	if len(raw) == 0 {
		return nil
	}
	s := make(Signal, len(raw))
	for _, e := range raw {
		s[elemType(e)] = prioType(prio)
	}
	return s
}

// 新增的函数，作用和Deserialize()相反，将Signal转换为Serial
func (s Signal) Serialize() Serial {
	// signal为空，直接返回空的serial
	if s.Empty() {
		return Serial{}
	}
	res := Serial{
		Elems: make([]elemType, len(s)),
		Prios: make([]prioType, len(s)),
	}
	i := 0
	// 将elemType和prioType逐个赋值给res
	for e, p := range s {
		res.Elems[i] = e
		res.Prios[i] = p
		i++
	}
	return res
}

// 新增加的函数，将serial转换为signal，以前的signal仅仅为[]uint32的地址
// Serial是一个结构体类型，而Signal是map类型
func (ser Serial) Deserialize() Signal {
	if len(ser.Elems) != len(ser.Prios) {
		panic("corrupted Serial")
	}
	if len(ser.Elems) == 0 {
		return nil
	}
	s := make(Signal, len(ser.Elems))
	for i, e := range ser.Elems {
		s[e] = ser.Prios[i]
	}
	return s
}

// 比较两个不同的map，将两个map中不同的边添加到一个新的map中返回
func (s Signal) Diff(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	var res Signal
	for e, p1 := range s1 {
		if p, ok := s[e]; ok && p >= p1 {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[e] = p1
	}
	return res
}

// 如果一个signal不在maxsignal中，将其添加到res；
// 如果一个signal的优先级比maxsignal中的优先级更高，将其添加到res中；最终返回res
func (s Signal) DiffRaw(raw []uint32, prio uint8) Signal {
	var res Signal
	for _, e := range raw {
		// 如果signal是一样的，且maxSignal中的优先级较高，那么不存入maxSignal中
		if p, ok := s[elemType(e)]; ok && p >= prioType(prio) {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[elemType(e)] = prioType(prio)
	}
	return res
}

// 去除了不稳定的边和优先级低的边
func (s Signal) Intersection(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	res := make(Signal, len(s))
	for e, p := range s {
		if p1, ok := s1[e]; ok && p1 >= p {
			res[e] = p
		}
	}
	return res
}

// 合并两个signal，如果他们的key值不一样，或者s的优先级小于s1的优先级，将s1的添加到s中或替换原来的低优先级边
func (s *Signal) Merge(s1 Signal) {
	if s1.Empty() {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(Signal, len(s1))
		*s = s0
	}
	for e, p1 := range s1 {
		if p, ok := s0[e]; !ok || p < p1 {
			s0[e] = p1
		}
	}
}

type Context struct {
	Signal  Signal
	Context interface{}
}

// corpus是一个结构体，包含Singal和Context，Signal是map[elem]prio,Context是RPCInput
// Minimize函数的主要作用是将corpus中重复路径，或者路径优先级低的路径去掉
func Minimize(corpus []Context) []interface{} {
	sort.Slice(corpus, func(i, j int) bool {
		return corpus[i].Signal.Len() > corpus[j].Signal.Len()
	})
	type ContextPrio struct {
		prio prioType
		idx  int
	}
	covered := make(map[elemType]ContextPrio)
	// i表示取得第i个corpus，inp表示每一个corpus
	for i, inp := range corpus {
		// e表示elemType，p表示prioType
		for e, p := range inp.Signal {
		// e可以看做一条边，如果这条边没有被加入到covered中，或者之前有相同的路径加入到了
		// covered中，但是它的优先级比加入到covered中的路径优先级高，那么更新covered中的优先级
			if prev, ok := covered[e]; !ok || p > prev.prio {
				covered[e] = ContextPrio{
					prio: p,
					idx:  i,
				}
			}
		}
	}
	/*
	感觉这里有点麻烦，首先为了取得了covered中的idx，对covered遍
	历了一次。 然后又遍历indices进行赋值，应该可以修改为如下：
	result := make([]interface{}, 0, len(corpus))
	for _, cp := range covered {
		result = append(result, corpus[cp.idx].Context)
	}
	return result
	 */
	indices := make(map[int]struct{}, len(corpus))
	for _, cp := range covered {
		indices[cp.idx] = struct{}{}
	}
	result := make([]interface{}, 0, len(indices))
	for idx := range indices {
		result = append(result, corpus[idx].Context)
	}
	return result
}
