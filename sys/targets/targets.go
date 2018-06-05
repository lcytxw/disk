// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

type Target struct {
	os
	OS                 string
	Arch               string
	PtrSize            uint64
	PageSize           uint64
	NumPages           uint64
	DataOffset         uint64
	CArch              []string
	CFlags             []string
	CrossCFlags        []string
	CCompilerPrefix    string
	KernelArch         string
	KernelHeaderArch   string
	KernelCrossCompile string
	// NeedSyscallDefine is used by csource package to decide when to emit __NR_* defines.
	NeedSyscallDefine func(nr uint64) bool
}

type os struct {
	// Does the OS use syscall numbers (e.g. Linux) or has interface based on functions (e.g. fuchsia).
	SyscallNumbers bool
	// E.g. "__NR_" or "SYS_".
	SyscallPrefix string
	// ipc<->executor communication tuning.
	// If ExecutorUsesShmem, programs and coverage are passed through shmem, otherwise via pipes.
	ExecutorUsesShmem bool
	// If ExecutorUsesForkServer, executor uses extended protocol with handshake.
	ExecutorUsesForkServer bool
}

// 将多个target组合起来，List是一个map[][]*Target，第一个map存放系统，第二个map存放架构，
// 最后一个Target存放一些简单的初始值。这个Target和target.go中的Target是分离的，互不影响
var List = map[string]map[string]*Target{
	"test": map[string]*Target{
		"32": {
			PtrSize:  4,
			PageSize: 8 << 10,
		},
		"64": {
			PtrSize:  8,
			PageSize: 4 << 10,
		},
	},
	"linux": map[string]*Target{
		"amd64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			CArch:            []string{"__x86_64__"},
			CFlags:           []string{"-m64"},
			CrossCFlags:      []string{"-m64"},
			CCompilerPrefix:  "x86_64-linux-gnu-",
			KernelArch:       "x86_64",
			KernelHeaderArch: "x86",
			NeedSyscallDefine: func(nr uint64) bool {
				// Only generate defines for new syscalls
				// (added after commit 8a1ab3155c2ac on 2012-10-04).
				return nr >= 313
			},
		},
		"386": {
			PtrSize:          4,
			PageSize:         4 << 10,
			CArch:            []string{"__i386__"},
			CFlags:           []string{"-m32"},
			CrossCFlags:      []string{"-m32"},
			CCompilerPrefix:  "x86_64-linux-gnu-",
			KernelArch:       "i386",
			KernelHeaderArch: "x86",
		},
		"arm64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			CArch:            []string{"__aarch64__"},
			CCompilerPrefix:  "aarch64-linux-gnu-",
			KernelArch:       "arm64",
			KernelHeaderArch: "arm64",
		},
		"arm": {
			PtrSize:          4,
			PageSize:         4 << 10,
			CArch:            []string{"__arm__"},
			CFlags:           []string{"-D__LINUX_ARM_ARCH__=6", "-m32", "-D__ARM_EABI__"},
			CrossCFlags:      []string{"-D__LINUX_ARM_ARCH__=6", "-march=armv6t2"},
			CCompilerPrefix:  "arm-linux-gnueabihf-",
			KernelArch:       "arm",
			KernelHeaderArch: "arm",
		},
		"ppc64le": {
			PtrSize:          8,
			PageSize:         4 << 10,
			CArch:            []string{"__ppc64__", "__PPC64__", "__powerpc64__"},
			CFlags:           []string{"-D__powerpc64__"},
			CrossCFlags:      []string{"-D__powerpc64__"},
			CCompilerPrefix:  "powerpc64le-linux-gnu-",
			KernelArch:       "powerpc",
			KernelHeaderArch: "powerpc",
		},
	},
	"freebsd": map[string]*Target{
		"amd64": {
			PtrSize:  8,
			PageSize: 4 << 10,
			CArch:    []string{"__x86_64__"},
			CFlags:   []string{"-m64"},
		},
	},
	"netbsd": map[string]*Target{
		"amd64": {
			PtrSize:  8,
			PageSize: 4 << 10,
			CArch:    []string{"__x86_64__"},
			CFlags:   []string{"-m64"},
		},
	},
	"fuchsia": map[string]*Target{
		"amd64": {
			PtrSize:  8,
			PageSize: 4 << 10,
			CArch:    []string{"__x86_64__"},
		},
		"arm64": {
			PtrSize:  8,
			PageSize: 4 << 10,
			CArch:    []string{"__aarch64__"},
		},
	},
	"windows": map[string]*Target{
		"amd64": {
			PtrSize: 8,
			// TODO(dvyukov): what should we do about 4k vs 64k?
			PageSize: 4 << 10,
			CArch:    []string{"_M_X64"},
		},
	},
	"akaros": map[string]*Target{
		"amd64": {
			PtrSize:           8,
			PageSize:          4 << 10,
			CArch:             []string{"__x86_64__"},
			NeedSyscallDefine: dontNeedSyscallDefine,
		},
	},
}

var oses = map[string]os{
	// 不同的系统对应不同的初始值，linux/freebsd等可以使用共享内存和forkserver等功能
	"linux": {
		SyscallNumbers:         true,
		SyscallPrefix:          "__NR_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
	},
	"freebsd": {
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
	},
	"netbsd": {
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
	},
	"fuchsia": {
		SyscallNumbers:         false,
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: false,
	},
	"windows": {
		SyscallNumbers:         false,
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: false,
	},
	"akaros": {
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: false,
	},
}

// 初始化函数
func init() {
	for OS, archs := range List {
		for arch, target := range archs {
			target.os = oses[OS]
			target.OS = OS
			target.Arch = arch
			if target.NeedSyscallDefine == nil {
				target.NeedSyscallDefine = needSyscallDefine
			}
			target.DataOffset = 512 << 20
			target.NumPages = (16 << 20) / target.PageSize
		}
	}
}

func needSyscallDefine(nr uint64) bool {
	return true
}
func dontNeedSyscallDefine(nr uint64) bool {
	return false
}
