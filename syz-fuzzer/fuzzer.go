// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	. "github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
)

type Fuzzer struct {
	name        string
	outputType  OutputType
	config      *ipc.Config
	execOpts    *ipc.ExecOpts
	procs       []*Proc
	gate        *ipc.Gate
	workQueue   *WorkQueue
	needPoll    chan struct{}
	choiceTable *prog.ChoiceTable
	stats       [StatCount]uint64
	manager     *RPCClient
	target      *prog.Target

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool
	coverageEnabled          bool
	leakCheckEnabled         bool
	leakCheckReady           uint32

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]struct{}

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master

	logMu sync.Mutex
	initPrios	 []float32
	transMatrix  [][]float32

	// icy: add
	findCallTable	*prog.ChoiceTable
	lenCalls	 int
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func main() {
	// 设置GC
	debug.SetGCPercent(50)
	// 读取参数
	var (
		flagName    = flag.String("name", "", "unique name for manager")
		flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager = flag.String("manager", "", "manager rpc address")
		flagProcs   = flag.Int("procs", 1, "number of parallel test processes")
		flagLeak    = flag.Bool("leak", false, "detect memory leaks")
		flagOutput  = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagPprof   = flag.String("pprof", "", "address to serve pprof profiles")
		flagTest    = flag.Bool("test", false, "enable image testing mode") // used by syz-ci
	)
	// 解析参数
	flag.Parse()
	var outputType OutputType
	switch *flagOutput {
	case "none":
		outputType = OutputNone
	case "stdout":
		outputType = OutputStdout
	case "dmesg":
		outputType = OutputDmesg
	case "file":
		outputType = OutputFile
	default:
		fmt.Fprintf(os.Stderr, "-output flag must be one of none/stdout/dmesg/file\n")
		os.Exit(1)
	}
	Logf(0, "fuzzer started")

	/*
	OS, arch: runtime.GOOS, runtime.GOARCH
	linux/amd64; linux/arm64; windows/amd64 etc;
	 */
	target, err := prog.GetTarget(runtime.GOOS, *flagArch)
	if err != nil {
		Fatalf("%v", err)
	}

	// config和execOpts都是配置
	config, execOpts, err := ipc.DefaultConfig()
	if err != nil {
		panic(err)
	}
	// sandbox默认为none
	sandbox := "none"
	if config.Flags&ipc.FlagSandboxSetuid != 0 {
		sandbox = "setuid"
	} else if config.Flags&ipc.FlagSandboxNamespace != 0 {
		sandbox = "namespace"
	}

	// 设置终止信号
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	// 新增加的一个功能，用于syz-ci
	if *flagTest {
		testImage(*flagManager, target, sandbox)
		return
	}

	// 通过Pprof在web上监控服务状态，包括cpu占用和内存使用情况
	if *flagPprof != "" {
		go func() {
			err := http.ListenAndServe(*flagPprof, nil)
			Fatalf("failed to serve pprof profiles: %v", err)
		}()
	} else {
		runtime.MemProfileRate = 0
	}
	// 开始通过rpc-server连接syz-manager，传递参数a，返回参数r
	Logf(0, "dialing manager at %v", *flagManager)
	a := &ConnectArgs{*flagName}
	r := &ConnectRes{}
	if err := RPCCall(*flagManager, "Manager.Connect", a, r); err != nil {
		panic(err)
	}
	// buildCallList表示最终被支持的函数，类型map[*prog.Syscall]bool
	calls := buildCallList(target, r.EnabledCalls, sandbox)
	// 通过prios和calls创建函数间距离作为choice_table
	ct := target.BuildChoiceTable(r.Prios, calls, 0)

	// icy: add
	findcalls := findCallList(target, r.FindCalls)
	fct := target.BuildChoiceTable(r.TransMatrix, findcalls, 1)
	// This requires "fault-inject: support systematic fault injection" kernel commit.
	// 错误注入：当我们在开发内核功能或者验证定位问题时，经常需要模拟各种内核的异常场景，来验证程序的健壮性
	// 或加速问题的复现，如内存分配失败，磁盘IO错误超时等。Linux内核继承了一个比较实用的功能“Fault-injection”
	// 来帮助我们进行故障注入，从而构建一些通用的内核异常场景。
	// 包含文件/proc/self/fail-nth表示支持faultInjection
	faultInjectionEnabled := false
	if fd, err := syscall.Open("/proc/self/fail-nth", syscall.O_RDWR, 0); err == nil {
		syscall.Close(fd)
		faultInjectionEnabled = true
	}
	// 模拟Tun设备
	if calls[target.SyscallMap["syz_emit_ethernet"]] ||
		calls[target.SyscallMap["syz_extract_tcp_res"]] {
		config.Flags |= ipc.FlagEnableTun
	}
	// 如果支持faultInjection，判断是否开启了错误注入
	if faultInjectionEnabled {
		config.Flags |= ipc.FlagEnableFault
	}
	// 支持覆盖率收集
	coverageEnabled := config.Flags&ipc.FlagSignal != 0
	// 返回的第一个参数是判断是否支持kcov，第二个参数是判断是否支持trace_cmp
	kcov, comparisonTracingEnabled := checkCompsSupported()
	Logf(0, "kcov=%v, comps=%v", kcov, comparisonTracingEnabled)
	// 首次执行Needcheck为true
	if r.NeedCheck {
		// 执行syz-executor，参数为version
		// 返回四个值 linux amd64 d701f2a2142a12c08b17afbc15110c24f09bf0da
		//  f505ca4b5b3b9b595531a66f864a8c2843294c70+
		out, err := osutil.RunCmd(time.Minute, "", config.Executor, "version")
		if err != nil {
			panic(err)
		}
		vers := strings.Split(strings.TrimSpace(string(out)), " ")
		// 检测syz-executor的版本，防止更新后不同版本之间出现兼容性问题
		if len(vers) != 4 {
			panic(fmt.Sprintf("bad executor version: %q", string(out)))
		}

		a := &CheckArgs{
			// fuzz-x表示第几个执行的syz-fuzzer
			Name:           *flagName,
			// user namespace
			UserNamespaces: osutil.IsExist("/proc/self/ns/user"),
			// Makefile指定的gitrevision: f505ca4b5b3b9b595531a66f864a8c2843294c70
			// 在git目录运行git rev-parse HEAD显示
			FuzzerGitRev:   sys.GitRevision,
			// 对amd64来说为: d701f2a2142a12c08b17afbc15110c24f09bf0da,用于标记不同的Target
			FuzzerSyzRev:   target.Revision,
			// 运行syz-executor version得到的结果，用于标记syz-executor的一些信息
			ExecutorGitRev: vers[3],
			ExecutorSyzRev: vers[2],
			ExecutorArch:   vers[1],
		}
		a.Kcov = kcov
		// 内核是否支持检测内存泄漏
		if fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0); err == nil {
			syscall.Close(fd)
			a.Leak = true
		}
		// 内核是否支持faultInjection和trace_cmp
		a.Fault = faultInjectionEnabled
		a.CompsSupported = comparisonTracingEnabled
		for c := range calls {
			a.Calls = append(a.Calls, c.Name)
		}
		// 运行Manager.check函数
		if err := RPCCall(*flagManager, "Manager.Check", a, nil); err != nil {
			panic(err)
		}
	}

	// Manager.Connect reply can ve very large and that memory will be permanently cached in the connection.
	// So we do the call on a transient connection, free all memory and reconnect.
	// The rest of rpc requests have bounded size.
	debug.FreeOSMemory()
	manager, err := NewRPCClient(*flagManager)
	if err != nil {
		panic(err)
	}
	// 开启flagLeak，支持内存泄漏检测，将"scanf=off"写入"/sys/kernel/debug/kmemleak"表示
	// 暂停扫描线程（后面会再次开启）
	kmemleakInit(*flagLeak)

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	fuzzer := &Fuzzer{
		// fuzzer名称
		name:                     *flagName,
		// 输出方式，默认为stdout，但是syz-fuzzer的stdout是被重定向到syz-manager的
		outputType:               outputType,
		// 配置文件
		config:                   config,
		execOpts:                 execOpts,
		// 工作队列，传递进程数和needPool为参数构成一个WorkQueue结构体
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		// needpoll参数
		needPoll:                 needPoll,
		// 函数优先级列表
		choiceTable:              ct,
		// RPC客户端
		manager:                  manager,
		// target
		target:                   target,
		// 是否支持错误注入
		faultInjectionEnabled:    faultInjectionEnabled,
		// 是否支持trace_cmp
		comparisonTracingEnabled: comparisonTracingEnabled,
		// 是否开启覆盖率信息收集
		coverageEnabled:          coverageEnabled,
		// 是否开启信息泄露检测
		leakCheckEnabled:         *flagLeak,
		// 语料库的hash缩略信息
		corpusHashes:             make(map[hash.Sig]struct{}),

		// icytxw: add
		initPrios:				  r.InitPrios,
		transMatrix:			  r.TransMatrix,
		findCallTable:			  fct,
		lenCalls:				  len(findcalls),
	}
	// ????
	fuzzer.gate = ipc.NewGate(2**flagProcs, fuzzer.leakCheckCallback)
	// 重启的fuzzer不需要经过manager.check阶段，所以r.inputs表示从mgr.corpus中
	// 传递过来的corpus，可以认为是其它fuzzer传入的测试例。由于此时刚启动，认为所有的
	// corpus和signal都是new的。
	for _, inp := range r.Inputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	// 将manager.connect传递过来的MaxSignal转换为map类型后给fuzzer.MaxSignal
	fuzzer.addMaxSignal(r.MaxSignal.Deserialize())
	// 如果corpus.db中有数据(fuzzer执行一段时间关闭后，重新启动时corpus不为空)，
	// 那么manager传递过来的r.candidates将不为空，每次读取的数量不会超过线程数
	for _, candidate := range r.Candidates {
		p, err := fuzzer.target.Deserialize(candidate.Prog)
		if err != nil {
			panic(err)
		}
		// 开启了coverage，将candidate存到queue中；否则存到corpus中(默认开启)
		if coverageEnabled {
			// prog的类型，在入队的时候能用到
			flags := ProgCandidate
			// candidate是否最小化了，默认从corpus.db中的candidate是最小化了的
			// 通过hub传入的candidate是没有被最小化的
			if candidate.Minimized {
				flags |= ProgMinimized
			}
			// smash粉碎
			if candidate.Smashed {
				flags |= ProgSmashed
			}
			// 将程序p和flags逐个存入workQueue的wq.candidate中
			fuzzer.workQueue.enqueue(&WorkCandidate{
				p:     p,
				flags: flags,
			})
		} else {
			fuzzer.addInputToCorpus(p, nil, hash.Hash(candidate.Prog))
		}
	}
	// 多处理器，对多个flagProcs，传入的fuzzer都是一样的(和vmcount的个数有关)
	// 但是它们的pid不同
	for pid := 0; pid < *flagProcs; pid++ {
		// 同一个vm-instance的proc除了pid不同，其他都相同
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			Fatalf("failed to create proc: %v", err)
		}
		// 多个proc的集合
		fuzzer.procs = append(fuzzer.procs, proc)
		// 每个proc都作为一个单独的进程运行
		go proc.loop()
	}

	fuzzer.pollLoop()
}


func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second).C
	for {
		poll := false
		select {
		case <-ticker:
		// 我们考虑两种情况
		// 1. manager.go中没有candidate传入
		// 此时r.candidate为nil，workcandidate队列也为空。proc.loop()中的dequeue()函数返回nil，loop()执行
		// 生成测试例，poll除了第一次(第一次由于needPoll被初始化不为空，所以poll为true)为true外，其他的循环都为false。
		// poll的作用个人感觉就是用来加速 if poll || time.Since(lastPoll) > 10*time.Second 这个for循环的，
		// 2. manager.go中有candidate传入
		// 当candidate不为空的时候，每次循环prog.loop()都迅速执行一个candidate，执行的时候读取队列的candidates并会
		// 填满needpoll这个chan，当poolLoop()读取needpoll时，会将poll置为true，加速if poll || time.Since(lastPoll) > 10*
		// time.Second的执行，这个if语句会调用manager.poll重新读取manager的candidate供prog.loop()执行
		case <-fuzzer.needPoll:
			poll = true
		}
		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second {
			// Keep-alive for manager.
			Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second {
			// 之前的版本没有这个判断的，如果len(wq.candidate) < wq.procs，那么needcandidates为true
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}

			a := &PollArgs{
				Name:           fuzzer.name,
				NeedCandidates: needCandidates,
				Stats:          make(map[string]uint64),
			}
			// 得到当前执行到的新signal，赋值给a.MaxSignal，注意这里只取了newSignal而不是fuzzer.maxSignal
			// 因为本地的fuzzer.maxSignal和manager很多时重复的，无需再次传递给manager进行比较
			a.MaxSignal = fuzzer.grabNewSignal().Serialize()
			// 结果为多个线程的和
			for _, proc := range fuzzer.procs {
				a.Stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				a.Stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}

			for stat := Stat(0); stat < StatCount; stat++ {
				// 取fuzzer.stats[stat]的值给v并将fuzzer.stats[stat]置0
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				a.Stats[statNames[stat]] = v
				// 执行的总次数时所有状态执行次数的总和
				execTotal += v
			}

			r := &PollRes{}
			if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
				panic(err)
			}
			// maxSignal为新的signal
			maxSignal := r.MaxSignal.Deserialize()
			Logf(1, "poll: candidates=%v inputs=%v signal=%v",
				len(r.Candidates), len(r.NewInputs), maxSignal.Len())
			// 更新maxsignal
			fuzzer.addMaxSignal(maxSignal)
			for _, inp := range r.NewInputs {
				fuzzer.addInputFromAnotherFuzzer(inp)
			}
			for _, candidate := range r.Candidates {
				p, err := fuzzer.target.Deserialize(candidate.Prog)
				if err != nil {
					panic(err)
				}
				if fuzzer.coverageEnabled {
					flags := ProgCandidate
					if candidate.Minimized {
						flags |= ProgMinimized
					}
					if candidate.Smashed {
						flags |= ProgSmashed
					}
					fuzzer.workQueue.enqueue(&WorkCandidate{
						p:     p,
						flags: flags,
					})
				} else {
					fuzzer.addInputToCorpus(p, nil, hash.Hash(candidate.Prog))
				}
			}
			if len(r.Candidates) == 0 && fuzzer.leakCheckEnabled &&
				atomic.LoadUint32(&fuzzer.leakCheckReady) == 0 {
				kmemleakScan(false) // ignore boot leaks
				atomic.StoreUint32(&fuzzer.leakCheckReady, 1)
			}
			if len(r.NewInputs) == 0 && len(r.Candidates) == 0 {
				lastPoll = time.Now()
			}
		}
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
		Logf(0, "failed to detect host supported syscalls: %v", err)
	} else {
		// 删除内核不支持的函数
		for c := range calls {
			if !supp[c] {
				Logf(1, "disabling unsupported syscall: %v", c.Name)
				delete(calls, c)
			}
		}
	}
	// 这个函数的主要作用是删除包含无法产生的资源描述符的函数
	trans := target.TransitivelyEnabledCalls(calls)
	for c := range calls {
		if !trans[c] {
			Logf(1, "disabling transitively unsupported syscall: %v", c.Name)
			delete(calls, c)
		}
	}
	return calls
}

// icy: add
func findCallList(target *prog.Target, findCalls map[int]float32) map[*prog.Syscall]bool {
	calls := make(map[*prog.Syscall]bool)
	if findCalls == nil {
		return nil
	}
	for i := range findCalls {
		calls[target.Syscalls[i]] = true
	}
	return calls
}

func (fuzzer *Fuzzer) sendInputToManager(inp RPCInput) {
	// rpc传递给manager的参数
	a := &NewInputArgs{
		Name:     fuzzer.name,
		RPCInput: inp,
	}
	// rpc远程过程调用Manager.NewInput函数
	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		panic(err)
	}
}

// 将其他fuzzer来的input添加到corpus中并且更新fuzzer的maxSignal和corpusSignal
func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp RPCInput) {
	if !fuzzer.coverageEnabled {
		panic("should not be called when coverage is disabled")
	}
	// 将byte[]类型的函数集(一个测试例)转换为prog类型
	p, err := fuzzer.target.Deserialize(inp.Prog)
	if err != nil {
		panic(err)
	}
	// 求此函数集(一个测试例)的hash值
	sig := hash.Hash(inp.Prog)
	// 将结构体类型的signal转换为map类型的signal
	sign := inp.Signal.Deserialize()
	fuzzer.addInputToCorpus(p, sign, sig)
}

// addInputToCorpus将包含新边的测试例加入fuzzer.corpus中，并更新fuzzer.maxSignal和fuzzer.corpusSignal
func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	// fuzzer的corpusHashes中没有此sig，将其添加到fuzzer.corpus中
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
	}
	fuzzer.corpusMu.Unlock()

	// 将sign添加到corpussignal和maxSignal中
	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
}

func (fuzzer *Fuzzer) corpusSnapshot() []*prog.Prog {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return fuzzer.corpus
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}


func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

// 返回带有newSignal的函数下标，execute函数执行完后会利用这个函数进行检测
func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info []ipc.CallInfo) (calls []int) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	// info表示所有函数的执行路径信息，inf表示第i个函数的执行信息
	for i, inf := range info {
		// 和maxsignal不同的signal
		diff := fuzzer.maxSignal.DiffRaw(inf.Signal, signalPrio(p.Target, p.Calls[i], &inf))
		if diff.Empty() {
			continue
		}
		calls = append(calls, i)
		fuzzer.signalMu.RUnlock()
		fuzzer.signalMu.Lock()
		fuzzer.maxSignal.Merge(diff)
		fuzzer.newSignal.Merge(diff)
		fuzzer.signalMu.Unlock()
		fuzzer.signalMu.RLock()
	}
	return
}

// 设置每个signal的priority(一个signal可以看作一条边)
func signalPrio(target *prog.Target, c *prog.Call, ci *ipc.CallInfo) (prio uint8) {
	// ci.Errno == 0 表示这个函数执行没有错误，函数执行没有错误则优先级较高(prio = prio | 2)
	if ci.Errno == 0 {
		prio |= 1 << 1
	}
	// CallContainsAny(c)表示函数c的参数包含任意指向array的指针时返回true，这里如果包含
	// anytype则优先级会比不包含any的低1
	if !target.CallContainsAny(c) {
		prio |= 1 << 0
	}
	return
}

func (fuzzer *Fuzzer) leakCheckCallback() {
	if atomic.LoadUint32(&fuzzer.leakCheckReady) != 0 {
		// Scan for leaks once in a while (it is damn slow).
		kmemleakScan(true)
	}
}
