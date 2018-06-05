// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

func (target *Target) calcResourceCtors(kind []string, precise bool) []*Syscall {
	// Find calls that produce the necessary resources.
	var metas []*Syscall
	for _, meta := range target.Syscalls {
		// Recurse into arguments to see if there is an out/inout arg of necessary type.
		ok := false
		ForeachType(meta, func(typ Type) {
			if ok {
				return
			}
			switch typ1 := typ.(type) {
			case *ResourceType:
				// Dirout，即生成的资源描述符是输出到参数的
				if typ1.Dir() != DirIn && isCompatibleResourceImpl(kind, typ1.Desc.Kind, precise) {
					ok = true
				}
			}
		})
		if ok {
			metas = append(metas, meta)
		}
	}
	return metas
}

// isCompatibleResource returns true if resource of kind src can be passed as an argument of kind dst.
func (target *Target) isCompatibleResource(dst, src string) bool {
	if dst == target.any.res32.TypeName || dst == target.any.res64.TypeName {
		return true
	}
	dstRes := target.resourceMap[dst]
	if dstRes == nil {
		panic(fmt.Sprintf("unknown resource '%v'", dst))
	}
	srcRes := target.resourceMap[src]
	if srcRes == nil {
		panic(fmt.Sprintf("unknown resource '%v'", src))
	}
	return isCompatibleResourceImpl(dstRes.Kind, srcRes.Kind, false)
}

// isCompatibleResourceImpl returns true if resource of kind src can be passed as an argument of kind dst.
// If precise is true, then it does not allow passing a less specialized resource (e.g. fd)
// as a more specialized resource (e.g. socket). Otherwise it does.
func isCompatibleResourceImpl(dst, src []string, precise bool) bool {
	if len(dst) > len(src) {
		// dst is more specialized, e.g dst=socket, src=fd.
		if precise {
			return false
		}
		dst = dst[:len(src)]
	}
	if len(src) > len(dst) {
		// src is more specialized, e.g dst=fd, src=socket.
		src = src[:len(dst)]
	}
	for i, k := range dst {
		if k != src[i] {
			return false
		}
	}
	return true
}

func (c *Syscall) inputResources() []*ResourceType {
	var resources []*ResourceType
	ForeachType(c, func(typ Type) {
		switch typ1 := typ.(type) {
		case *ResourceType:
			if typ1.Dir() != DirOut && !typ1.IsOptional {
				resources = append(resources, typ1)
			}
		}
	})
	return resources
}

// 这个函数大致做了如下事情：
// 首先在所有supported函数中，找出使能的函数，然后在使能的函数中，通过函数inputResources()函数找到
// 所有需要resource作为输入(Dirin,Dirin的作用见google文档)资源描述符存放在inputResources中，然后通过函数calcResourceCtors()
// 在所有函数中(target.Syscall)中找到能够生成这些Dirin资源描述符的函数存放在ctors中，对于inputResources中的每一个函数所需要的资源，如果在
// ctors中存在能够产生此资源的函数，并且这个函数是enabled的，那么inputResources中的函数保留，否则删除。不在inputResources中的函数不处理
func (target *Target) TransitivelyEnabledCalls(enabled map[*Syscall]bool) map[*Syscall]bool {
	supported := make(map[*Syscall]bool)
	for c := range enabled {
		supported[c] = true
	}
	inputResources := make(map[*Syscall][]*ResourceType)
	ctors := make(map[string][]*Syscall)
	for c := range supported {
		// 找到参数类型为Dirin的资源描述符，这是函数需要的资源描述符
		inputs := c.inputResources()
		inputResources[c] = inputs
		for _, res := range inputs {
			if _, ok := ctors[res.Desc.Name]; ok {
				continue
			}
			// 通过函数calcResourceCtors得到能够产生上述Dirin类型资源描述符的函数
			// 由于这些函数是在target.Syscall中的，不一定是enabled syscall
			ctors[res.Desc.Name] = target.calcResourceCtors(res.Desc.Kind, true)
		}
	}
	for {
		n := len(supported)
		haveGettime := supported[target.SyscallMap["clock_gettime"]]
		for c := range supported {
			canCreate := true
			for _, res := range inputResources[c] {
				noctors := true
				// 默认noctors为true，即初始时认为不能产生这类函数。然后判断在所有的生成Dirin
				// 的函数中，是否是enabled的。如果是，那么将noctors置为false，表示能
				// 产生这类资源描述符
				for _, ctor := range ctors[res.Desc.Name] {
					if supported[ctor] {
						noctors = false
						break
					}
				}
				if noctors {
					canCreate = false
					break
				}
			}
			// We need to support structs as resources,
			// but for now we just special-case timespec/timeval.
			// 如果不支持clock_gettime这个函数，那么需要进一步进行判断，因为如果不存在这个函数
			// 时间这类结构体无法产生
			if canCreate && !haveGettime {
				ForeachType(c, func(typ Type) {
					if a, ok := typ.(*StructType); ok && a.Dir() != DirOut && (a.Name() == "timespec" || a.Name() == "timeval") {
						canCreate = false
					}
				})
			}
			// 不支持这个函数，则进行删除
			if !canCreate {
				delete(supported, c)
			}
		}
		// 直到没有函数删除为止，结束循环
		if n == len(supported) {
			break
		}
	}
	return supported
}
