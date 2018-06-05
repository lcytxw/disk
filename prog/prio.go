// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"sort"
//	"os"
//	"strconv"
)

// Calulation of call-to-call priorities.
// For a given pair of calls X and Y, the priority is our guess as to whether
// additional of call Y into a program containing call X is likely to give
// new coverage or not.
// The current algorithm has two components: static and dynamic.
// The static component is based on analysis of argument types. For example,
// if call X and call Y both accept fd[sock], then they are more likely to give
// new coverage together.
// The dynamic component is based on frequency of occurrence of a particular
// pair of syscalls in a single program in corpus. For example, if socket and
// connect frequently occur in programs together, we give higher priority to
// this pair of syscalls.
// Note: the current implementation is very basic, there is no theory behind any
// constants.

func (target *Target) CalculatePriorities(corpus []*Prog) [][]float32 {
	// 计算静态优先级
	static := target.calcStaticPriorities()
	// 计算动态优先级
	dynamic := target.calcDynamicPrio(corpus)
	for i, prios := range static {
		for j, p := range prios {
			dynamic[i][j] *= p
		}
	}
	return dynamic
}

//
func (target *Target) calcStaticPriorities() [][]float32 {
	uses := make(map[string]map[int]float32)
	for _, c := range target.Syscalls {
		noteUsage := func(weight float32, str string, args ...interface{}) {
			id := fmt.Sprintf(str, args...)
			if uses[id] == nil {
				uses[id] = make(map[int]float32)
			}
			old := uses[id][c.ID]
			if weight > old {
				uses[id][c.ID] = weight
			}
		}
		ForeachType(c, func(t Type) {
			switch a := t.(type) {
			case *ResourceType:
				if a.Desc.Name == "pid" || a.Desc.Name == "uid" || a.Desc.Name == "gid" {
					// Pid/uid/gid usually play auxiliary role,
					// but massively happen in some structs.
					// 如果资源名为"pid"、"uid"、"gid"，调用noteUsage将名称为"res+pid\uid\gid"的
					// 资源描述符存入uses[id][c.ID]，c.id表示函数名，取最大优先级
					noteUsage(0.1, "res%v", a.Desc.Name)
				} else {
					str := "res"
					// 一个资源描述符可能有多种type,如{fd、fd_dir}
					for i, k := range a.Desc.Kind {
						str += "-" + k
						w := 1.0
						// 最后一个优先级最高为1.0，其它为0.2
						if i < len(a.Desc.Kind)-1 {
							w = 0.2
						}
						noteUsage(float32(w), str)
					}
				}
			case *PtrType:
				if _, ok := a.Type.(*StructType); ok {
					noteUsage(1.0, "ptrto-%v", a.Type.Name())
				}
				if _, ok := a.Type.(*UnionType); ok {
					noteUsage(1.0, "ptrto-%v", a.Type.Name())
				}
				if arr, ok := a.Type.(*ArrayType); ok {
					noteUsage(1.0, "ptrto-%v", arr.Type.Name())
				}
			case *BufferType:
				switch a.Kind {
				case BufferBlobRand, BufferBlobRange, BufferText:
				case BufferString:
					if a.SubKind != "" {
						noteUsage(0.2, fmt.Sprintf("str-%v", a.SubKind))
					}
				case BufferFilename:
					noteUsage(1.0, "filename")
				default:
					panic("unknown buffer kind")
				}
			case *VmaType:
				noteUsage(0.5, "vma")
			case *IntType:
				switch a.Kind {
				case IntPlain, IntFileoff, IntRange:
				default:
					panic("unknown int kind")
				}
			}
		})
	}
	prios := make([][]float32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]float32, len(target.Syscalls))
	}
	for _, calls := range uses {
		for c0, w0 := range calls {
			for c1, w1 := range calls {
				if c0 == c1 {
					// Self-priority is assigned below.
					continue
				}
				prios[c0][c1] += w0 * w1
			}
		}
	}

	// Self-priority (call wrt itself) is assigned to the maximum priority
	// this call has wrt other calls. This way the priority is high, but not too high.
	for c0, pp := range prios {
		var max float32
		for _, p := range pp {
			if max < p {
				max = p
			}
		}
		// 取prios每一行中的最大值赋值给自己
		pp[c0] = max
	}
	normalizePrio(prios)
	return prios
}

func (target *Target) calcDynamicPrio(corpus []*Prog) [][]float32 {
	prios := make([][]float32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]float32, len(target.Syscalls))
	}
	for _, p := range corpus {
		for _, c0 := range p.Calls {
			for _, c1 := range p.Calls {
				id0 := c0.Meta.ID
				id1 := c1.Meta.ID
				prios[id0][id1] += 1.0
			}
		}
	}
	normalizePrio(prios)
	return prios
}

// normalizePrio assigns some minimal priorities to calls with zero priority,
// and then normalizes priorities to 0.1..1 range.
func normalizePrio(prios [][]float32) {
	for _, prio := range prios {
		max := float32(0)
		min := float32(1e10)
		nzero := 0
		// 求prios中每行的最小值（非0）、最大值、0的个数
		for _, p := range prio {
			if max < p {
				max = p
			}
			if p != 0 && min > p {
				min = p
			}
			if p == 0 {
				nzero++
			}
		}
		// 如果0的个数不为0，最小值 = 最小值/0的个数
		if nzero != 0 {
			min /= 2 * float32(nzero)
		}

		for i, p := range prio {
			// 如果最大值为0（即整行都为0），将整行的优先级都置1
			if max == 0 {
				prio[i] = 1
				continue
			}
			// 优先级如果为0，那么将其置为min
			if p == 0 {
				p = min
			}
			// 归一化：优先级p = (p-min)/(max-min)*0.9+0.1，这样会使得矩阵不对称
			p = (p-min)/(max-min)*0.9 + 0.1
			if p > 1 {
				p = 1
			}
			prio[i] = p
		}
	}
}

// ChooseTable allows to do a weighted choice of a syscall for a given syscall
// based on call-to-call priorities and a set of enabled syscalls.
type ChoiceTable struct {
	target       *Target
	run          [][]int
	enabledCalls []*Syscall
	enabled      map[*Syscall]bool
	index		 int
}

// 返回函数间的距离(prios[][]*1000并求和)
func (target *Target) BuildChoiceTable(prios [][]float32, enabled map[*Syscall]bool, index int) *ChoiceTable {
	// 如果enabled为空，那么将其赋值为默认的函数
	if enabled == nil {
		enabled = make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			enabled[c] = true
		}
	}
	var enabledCalls []*Syscall
	// 将enabled中的函数添加到enableCalls中
	for c := range enabled {
		enabledCalls = append(enabledCalls, c)
	}
	run := make([][]int, len(target.Syscalls))
	// i, j 可以视作函数组成的行列值。从行的第一个被使能(enabled)的函数开始，如果这个列有函数被使能
	// 那么从这一行开始，遍历每一个j，如果函数j是使能的，将ij函数间的优先级关系(正常情况下prios不为0)
	// 扩大1000倍并求和，这样[ run[i][j],run[i][j+1] )之间的距离可以表示当i被选中后，j被选中的概率
	for i := range run {
		if !enabled[target.Syscalls[i]] {
			continue
		}
		run[i] = make([]int, len(target.Syscalls))
		sum := 0
		for j := range run[i] {
			if enabled[target.Syscalls[j]] {
				w := 1
				if prios != nil {
					w = int(prios[i][j] * 1000)
				}
				sum += w
			}
			run[i][j] = sum
		}
	}
	// run可以理解为函数间的距离，当一个函数确定之后，在这些距离中随机选一个整数，
	// 落点即为被选择的函数
	//fd, err := os.Create("run")
	//if err != nil {
	//}
	//for _, v := range run {
	//	for _,  val := range v{
	//		fd.WriteString(strconv.Itoa(val))
	//	}
	//	fd.WriteString("\n")
	//}
	return &ChoiceTable{target, run, enabledCalls, enabled, index}
}

func (ct *ChoiceTable) Choose(r *rand.Rand, call int) int {
	if call < 0 {
		return ct.enabledCalls[r.Intn(len(ct.enabledCalls))].ID
	}
	run := ct.run[call]
	if run == nil {
		return ct.enabledCalls[r.Intn(len(ct.enabledCalls))].ID
	}
	for {
		x := r.Intn(run[len(run)-1]) + 1
		i := sort.SearchInts(run, x)
		if ct.enabled[ct.target.Syscalls[i]] {
			return i
		}
	}
}

func (ct *ChoiceTable) MyChoose(r *rand.Rand, call int) int {
	if call < 0 {
		return ct.enabledCalls[r.Intn(len(ct.enabledCalls))].ID
	}
	run := ct.run[call]
	if run == nil {
		return ct.enabledCalls[r.Intn(len(ct.enabledCalls))].ID
	}
	for {
		x := r.Intn(run[len(run)-1]+1)
		i := sort.SearchInts(run, x)
		if ct.enabled[ct.target.Syscalls[i]] {
			return i
		}
	}
}
