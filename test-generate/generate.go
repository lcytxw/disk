package main

import (
	"flag"
	"runtime"
	"github.com/google/syzkaller/prog"
	"fmt"
	"strings"
	"strconv"
	"github.com/google/syzkaller/pkg/host"
	_ "github.com/google/syzkaller/vm"
	_ "github.com/google/syzkaller/sys"
	"os"
	"math/rand"
	"time"
)

var (
	flagArch = flag.String("arch", runtime.GOARCH, "target arch")
)

func main() {
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		fmt.Printf("%v", err)
	}
	f, err1 := os.Create("callname")
	if err1 != nil {
		os.Exit(1)
	}
	//for _, syscall := range target.Syscalls {
	//	_, err1 := f.WriteString(syscall.Name + "\n")
	//	if err1 != nil {
	//		os.Exit(1)
	//	}
	//}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(1)*1e12))
	prios := target.CalculatePriorities(nil)
	//for _, p := range prios {
	//	for _, r := range p {
	//		_, err1 := f.WriteString(strconv.FormatFloat(float64(r), 'f', -1, 32) + " ")
	//		if err1 != nil {
	//			os.Exit(1)
	//		}
	//	}
	//	f.WriteString("\n")
	//}
	calls := buildCallList(target, "", "none")
	ct := target.BuildChoiceTable(prios, calls, 1)
	for i := 1; i < 100; i++ {
		p := target.Generate(rnd, 30, ct)
		_, err = f.Write(p.Serialize())
		f.WriteString("\n")
	}
	if err != nil {
		os.Exit(1)
	}
}

// enabledCalls传递的是使能的函数的id构成的string，如：1,2,3,4,5,8
// buildCallList函数的主要作用是删除一些不被支持的函数
func buildCallList(target *prog.Target, enabledCalls, sandbox string) map[*prog.Syscall]bool {
	calls := make(map[*prog.Syscall]bool)
	if enabledCalls != "" {
		// 通过","分离使能的函数并通过parseuint将其转换为int类型
		for _, id := range strings.Split(enabledCalls, ",") {
			n, err := strconv.ParseUint(id, 10, 64)
			// 错误的n值
			if err != nil || n >= uint64(len(target.Syscalls)) {
				panic(fmt.Sprintf("invalid syscall in -calls flag: %v", id))
			}
			// calls存放有效的syscall，key值为syscall
			calls[target.Syscalls[n]] = true
		}
	} else {
		// 如果没有使能的函数，那么默认是使能所有target.syscalls中的函数
		for _, c := range target.Syscalls {
			calls[c] = true
		}
	}

	// 检测内核支持的函数，对linux系统来说，有三种方式检测，具体见函数DetectSupportedSyscalls。
	// syzkaller采用的方法是查看/proc/kallsyms文件对比函数名的方法来判断的
	if supp, err := host.DetectSupportedSyscalls(target, sandbox); err != nil {
		fmt.Printf("failed to detect host supported syscalls: %v", err)
	} else {
		// 删除内核不支持的函数
		for c := range calls {
			if !supp[c] {
				fmt.Printf("disabling unsupported syscall: %v", c.Name)
				delete(calls, c)
			}
		}
	}
	// 这个函数的主要作用是删除包含无法产生的资源描述符的函数
	trans := target.TransitivelyEnabledCalls(calls)
	for c := range calls {
		if !trans[c] {
			fmt.Printf("disabling transitively unsupported syscall: %v", c.Name)
			delete(calls, c)
		}
	}
	return calls
}
