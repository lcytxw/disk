// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	. "github.com/google/syzkaller/pkg/log"
	. "github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

const (
	programLength = 30
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer            *Fuzzer
	pid               int
	env               *ipc.Env
	rnd               *rand.Rand
	execOpts          *ipc.ExecOpts
	execOptsCover     *ipc.ExecOpts
	execOptsComps     *ipc.ExecOpts
	execOptsNoCollide *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))

	execOptsNoCollide := *fuzzer.execOpts
	// 假如collide开为FlagCollide:100000 -> ^FlagCollide:11011111
	// 用flags与^ipc.FlagCollide表示Collide一定是关闭的，即NoCollide
	execOptsNoCollide.Flags &= ^ipc.FlagCollide
	execOptsCover := execOptsNoCollide
	// 表明收集cover信息，这个和coverageEnabled有所区别
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := execOptsNoCollide
	// 表明开启了trace_cmp功能
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:            fuzzer,
		pid:               pid,
		env:               env,
		rnd:               rnd,
		// syz-executor的执行参数
		execOpts:          fuzzer.execOpts,
		execOptsCover:     &execOptsCover,
		execOptsComps:     &execOptsComps,
		execOptsNoCollide: &execOptsNoCollide,
	}
	return proc, nil
}

// 无限循环，每个线程(proc)都执行能执行一个loop()
func (proc *Proc) loop() {
	for i := 0; ; i++ {
		// 取一个队列中的值(可能通过三种方式传入：candidate，smash，tirge)
		// WorkCandidate可以从manager的candidate传入
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			// 多个线程执行将会同时执行WorkCandidate，执行出的新路径将添加到WorkTriage中
			case *WorkCandidate:
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				proc.smashInput(item)
			default:
				panic("unknown work type")
			}
			// 队列中有数据，先执行队列中的数据，否则执行下面的生成和变异函数
			continue
		}

		ct := proc.fuzzer.choiceTable
		corpus := proc.fuzzer.corpusSnapshot()
		fct := proc.fuzzer.findCallTable
		if proc.fuzzer.lenCalls > 500 && i%5 == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, programLength, fct)
			Logf(1, "#%v: mygenerated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
		} else if len(corpus) == 0 || i%100 == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, programLength, ct)
			Logf(1, "#%v: generated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
			// Mutate an existing prog.
			p := corpus[proc.rnd.Intn(len(corpus))].Clone()
			p.Mutate(proc.rnd, programLength, ct, corpus)
			Logf(1, "#%v: mutated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
		}
	}
}

func (proc *Proc) triageInput(item *WorkTriage) {
	Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)
	// 没有开启coverageEnabled，triageInput不应该被执行，即不会往WorkTriage里面存数据
	// 无论哪个测试例(candidate、generate、mutate)在execute阶段执行出新路径，都会将此测试例克隆
	// 一份保存在WorkTriage队列中
	if !proc.fuzzer.coverageEnabled {
		panic("should not be called when coverage is disabled")
	}

	// itmp.info.signal表示signal，call表示的单个函数(item.call为callindex)，info表示这个函数的执行信息
	call := item.p.Calls[item.call]

	// 得到rawSignal和rawSignal的优先级，存入inputSignal，info.Signal表示执行函数(单个函数)得到的signal
	inputSignal := signal.FromRaw(item.info.Signal, signalPrio(item.p.Target, call, &item.info))
	// 对比inputSignal中的signal和corpus中的signal不同的地方，将不同的signal返回
	// 因为inputSignal是一个测试例中某个函数完整的执行路径，其中的一些边可能是和现有的边重复的
	// 因此去除重复边将其添加到newSignal中
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	// 没有新signal，直接返回
	if newSignal.Empty() {
		return
	}
	// 对包含新边的函数进行检伤分类
	Logf(3, "triaging input for %v (new signal=%v)", call.Meta.CallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	for i := 0; i < signalRuns; i++ {
		// 开启execOptsCover选项重新执行
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if len(info) == 0 || len(info[item.call].Signal) == 0 {
			// The call was not executed. Happens sometimes.
			notexecuted++
			if notexecuted > signalRuns/2 {
				return // if happens too often, give up
			}
			continue
		}
		// 取得这个函数的执行路径信息
		inf := info[item.call]
		// 这个函数的signal(边)
		thisSignal := signal.FromRaw(inf.Signal, signalPrio(item.p.Target, call, &inf))
		// Intersection函数将thisSignal不包含在newSignal中的边去掉了，且去掉了优先级低的边
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		// inf.Cover表示未被处理的路径信息
		inputCover.Merge(inf.Cover)
	}
	// minimize
	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
					if len(info) == 0 || len(info[call1].Signal) == 0 {
						continue // The call was not executed.
					}
					inf := info[call1]
					if item.info.Errno == 0 && inf.Errno != 0 {
						// Don't minimize calls from successful to unsuccessful.
						// Successful calls are much more valuable.
						return false
					}
					prio := signalPrio(p1.Target, p1.Calls[call1], &inf)
					thisSignal := signal.FromRaw(inf.Signal, prio)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			})
	}
	// *prog.Prog -> []byte
	data := item.p.Serialize()
	// 取得data的hash值
	sig := hash.Hash(data)

	// 如果确定一个函数是一个包含新路径的输入，将整个测试例添加到corpus中
	Logf(2, "added new input for %v to corpus:\n%s", call.Meta.CallName, data)
	// 能坚持到这一步的都是有新边的测试例，发送给manager
	proc.fuzzer.sendInputToManager(RPCInput{
		Call:   call.Meta.CallName,
		Prog:   data,
		Signal: inputSignal.Serialize(),
		Cover:  inputCover.Serialize(),
	})

	// 将inputSignal合并到fuzzer.Maxsignal和corpusSignal
	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)

	// call -> callindex
	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func (proc *Proc) smashInput(item *WorkSmash) {
	// 如果使能了faultInjection的话，执行proc.failCall
	if proc.fuzzer.faultInjectionEnabled {
		proc.failCall(item.p, item.call)
	}
	// 如果使能了trace_cmp，执行fuzzer.comparisonTracingEnabled函数
	if proc.fuzzer.comparisonTracingEnabled {
		proc.executeHintSeed(item.p, item.call)
	}
	// corpusSnapshot读取fuzzer.corpus
	corpus := proc.fuzzer.corpusSnapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, programLength, proc.fuzzer.choiceTable, corpus)
		Logf(1, "#%v: smash mutated", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 0; nth < 100; nth++ {
		Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		opts := *proc.execOpts
		opts.Flags |= ipc.FlagInjectFault
		opts.FaultCall = call
		opts.FaultNth = nth
		info := proc.executeRaw(&opts, p, StatSmash)
		if info != nil && len(info) > call && !info[call].FaultInjected {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	// 这个主要是开启了trace_cmp进行字段替换
	p.MutateWithHints(call, info[call].Comps, func(p *prog.Prog) {
		Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) []ipc.CallInfo {
	info := proc.executeRaw(execOpts, p, stat)
	for _, callIndex := range proc.fuzzer.checkNewSignal(p, info) {
		info := info[callIndex]
		// info.Signal points to the output shmem region, detach it before queueing.
		// info.Signal是指向共享内存的，为了防止被破坏，将其取出之后保存在info.Signal中
		info.Signal = append([]uint32{}, info.Signal...)
		// None of the caller use Cover, so just nil it instead of detaching.
		// Note: triage input uses executeRaw to get coverage.
		info.Cover = nil
		// 将每次执行出newSignal的函数以WorkTriage的形式入队，每个有new signal的函数都会入队列
		proc.fuzzer.workQueue.enqueue(&WorkTriage{
			p:     p.Clone(),
			call:  callIndex,
			info:  info,
			flags: flags,
		})
	}
	return info
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) []ipc.CallInfo {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		panic("dedup cover is not enabled")
	}

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	try := 0
retry:
	atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
	output, info, failed, hanged, err := proc.env.Exec(opts, p)
	if failed {
		// BUG in output should be recognized by manager.
		Logf(0, "BUG: executor-detected bug:\n%s", output)
		// Don't return any cover so that the input is not added to corpus.
		return nil
	}
	if err != nil {
		if _, ok := err.(ipc.ExecutorFailure); ok || try > 10 {
			panic(err)
		}
		try++
		Logf(4, "fuzzer detected executor failure='%v', retrying #%d\n", err, (try + 1))
		debug.FreeOSMemory()
		time.Sleep(time.Second)
		goto retry
	}
	Logf(2, "result failed=%v hanged=%v: %v\n", failed, hanged, string(output))
	return info
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()
	strOpts := ""
	if opts.Flags&ipc.FlagInjectFault != 0 {
		strOpts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)", opts.FaultCall, opts.FaultNth)
	}

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		proc.fuzzer.logMu.Lock()
		Logf(0, "executing program %v%v:\n%s\n", proc.pid, strOpts, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v%v:\n%s\n",
				proc.pid, strOpts, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			if strOpts != "" {
				fmt.Fprintf(f, "#%v\n", strOpts)
			}
			f.Write(data)
			f.Close()
		}
	default:
		panic("unknown output type")
	}
}
