package main
//
//import (
//	"io/ioutil"
//	"fmt"
//	"path/filepath"
//	."os"
//	"strconv"
//	"github.com/google/syzkaller/prog"
//	_ "github.com/google/syzkaller/sys"
//	"runtime"
//)
//
//var (
//	dir = "./workdir-new/temp"
//	shortSerial = "./serial.txt"
//	callName = "./calls.txt"
//	prio = "./prio.txt"
//)
//
//func showImage() {
//	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
//	calls := make(map[int]int)
//	callways := make(map[int]map[int]float32)
//	dir_list, err := ioutil.ReadDir(dir)
//	if dir_list == nil {
//		fmt.Errorf("dir is nil: ", dir)
//		return
//	}
//	if err != nil {
//		fmt.Errorf("faild to read dir: ", dir)
//		return
//	}
//	for _, info := range dir_list {
//		if info == nil {
//			continue
//		}
//		data, err := ioutil.ReadFile(filepath.Join(dir, info.Name()))
//		if err != nil {
//			fmt.Errorf("faild to read file: ", info.Name())
//		}
//		p, err := target.Deserialize(data)
//		name0 := -1
//		for _, c := range p.Calls {
//			// icytxw: add
//			// 当前每个出现过的calls的频率
//			name1 := c.Meta.ID
//			calls[name1] += 1
//			// 将得到的函数短序列存入callways中(有向图)
//			if name0 == -1 {
//				name0 = c.Meta.ID
//				continue
//			}
//			if callways[name0][name1] == 0 {
//				if callways[name0] == nil {
//					callways[name0] = make(map[int]float32)
//				}
//				callways[name0][name1] += 1
//				name0 = name1
//			} else {
//				callways[name0][name1] += 1
//			}
//		}
//	}
//	fd, err := OpenFile(shortSerial, O_CREATE|O_APPEND|O_RDWR, 0666)
//	if err != nil {
//		fmt.Errorf("faild to open file: ", shortSerial)
//	}
//	for name0, ways := range callways {
//		for name1, v := range ways {
//			_, err = fd.Write([]byte(strconv.Itoa(name0) + " -> " + strconv.Itoa(name1) + " " + strconv.FormatFloat(float64(v), 'f', -1, 32) + "\n"))
//			if err != nil {
//				fmt.Errorf("faild to write file: ", shortSerial)
//			}
//		}
//	}
//	fd1, err := OpenFile(callName, O_CREATE|O_APPEND|O_RDWR, 0666)
//	if err != nil {
//		fmt.Errorf("faild to open file: ", shortSerial)
//	}
//	for name, freq := range calls {
//		_, err = fd1.Write([]byte(strconv.Itoa(name) + " " + strconv.Itoa(freq) + "\n"))
//		if err != nil {
//			fmt.Errorf("faild to write file: ", callName)
//		}
//	}
//	static := calcStaticTrans(target, callways)
//	fd3, err := OpenFile(prio, O_CREATE|O_APPEND|O_RDWR, 0666)
//	if err != nil {
//		fmt.Errorf("faild to open file: ", shortSerial)
//	}
//	for _, prio := range static {
//		for _, v := range prio {
//			_, err = fd3.WriteString(strconv.FormatFloat(float64(v), 'f', -1, 32) + " ")
//		}
//		_, err = fd3.WriteString("\n")
//	}
//}
//
//func calcStaticTrans(target *prog.Target , callways map[int]map[int]float32) ([][]float32) {
//	totalCall := make(map[int]float32)
//	for name0, calls := range callways {
//		for name1 := range calls {
//			totalCall[name0] += callways[name0][name1]
//		}
//	}
//	static := make([][]float32, len(target.Syscalls))
//	for i, _ := range static {
//		static[i] = make([]float32, len(target.Syscalls))
//	}
//	for name0, calls := range callways {
//		for name1 := range calls {
//			static[name0][name1] = callways[name0][name1] / totalCall[name0]
//		}
//	}
//	return static
//}
//func main () {
//	showImage()
//}
