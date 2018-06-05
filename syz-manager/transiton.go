package main

import (
	"github.com/google/syzkaller/prog"
)

// 计算马尔科夫-蒙特卡洛转移矩阵
func (mgr *Manager) calcTransMatrix (corpus []*prog.Prog) ([][]float32, []float32){
	// 根据传入的corpus更新findcalls和callways
	findcalls, callways := mgr.calcDynamicTrans(corpus)
	// 静态优先级表示如果在启动的时候将corpus.db中的数据作为静态转移矩阵
	static := mgr.calcStaticTrans(findcalls, callways)
	// 计算马尔科夫-蒙特卡洛的初始矩阵
	initPrios := mgr.calcInitPrios(findcalls)
	return static, initPrios
}

// 计算静态转移概率，目前只是简单的通过短序列出现的次数来决定其概率
func (mgr *Manager) calcStaticTrans(findcalls map[int]float32, callways map[int]map[int]float32) [][]float32 {
	if findcalls == nil || callways == nil {
		return nil
	}
	static := make([][]float32, len(mgr.target.Syscalls))
	for i := range static {
		static[i] = make([]float32, len(mgr.target.Syscalls))
	}
	lineSum := make(map[int]float32)
	for name0, calls := range callways {
		for _, v := range calls {
			lineSum[name0] += v
		}
	}
	for name0, calls := range callways {
		for name1 := range calls {
			static[name0][name1] = callways[name0][name1] / lineSum[name0]
		}
	}
	return static
}

// 通过传入的corpus信息更新(短序列对)CallWays和已发现的函数(FindCalls)
func (mgr *Manager) calcDynamicTrans(corpus []*prog.Prog) (map[int]float32, map[int]map[int]float32) {
	findCalls := make(map[int]float32)
	callWays := make(map[int]map[int]float32)
	for i, v := range mgr.findcalls {
		findCalls[i] = v
	}
	for name0, call := range mgr.callways {
		callWays[name0] = make(map[int]float32)
		for name1, v := range call {
			callWays[name0][name1] = v
		}
	}
	for _, p := range corpus {
		name0 := -1;
		for _, c := range p.Calls {
			name1 := c.Meta.ID
			findCalls[name1] += 1
			if name0 == -1 {
				name0 = name1
				continue
			}
			if callWays[name0] == nil {
				callWays[name0] = make(map[int]float32)
			}
			callWays[name0][name1] += 1
			name0 = name1
		}
	}
	mgr.findcalls = findCalls
	mgr.callways = callWays

	return findCalls, callWays
}

// 更新马尔科夫-蒙特卡洛的初始状态
func (mgr *Manager) calcInitPrios(findcalls map[int]float32) ([]float32){
	if findcalls == nil {
		return nil
	}
	initPrios := make([]float32, len(mgr.target.Syscalls))
	var totalSum float32
	for _, v := range findcalls {
		totalSum += v
	}
	for c, v := range findcalls {
		initPrios[c] = v / totalSum
	}
	return initPrios
}
