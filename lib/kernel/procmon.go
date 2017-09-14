package kernel

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
)

type Proc struct {
	Filename string
	Args     string
}

type ProcMon struct {
	Procs map[string]*Proc
}

func NewProcMon() *ProcMon {
	return &ProcMon{}
}

func (pm *ProcMon) GetCmdline(pid string) (string, string) {
	fmt.Printf("pm.Procs[pid]: %v\n", pm.Procs[pid])
	entry, ok := pm.Procs[pid]
	if !ok {
		return "UNKNOWN", "UNKNOWN"
	}
	return entry.Filename, entry.Args
}

func writeFile(path string, value []byte) error {
	var (
		fs         os.FileInfo
		fd         *os.File
		numWritten int
		err        error
	)

	if fs, err = os.Stat(path); err != nil {
		return err
	}

	if fs.IsDir() {
		return errors.New("stat " + path + ": is a directory")
	}

	if fd, err = os.OpenFile(path, os.O_WRONLY, 0644); err != nil {
		return err
	}
	defer fd.Close()

	if numWritten, err = fd.Write(value); err != nil {
		return err
	}

	if numWritten != 1 {
		return errors.New("write " + path + ": corrupt write")
	}

	return nil
}

func enableTrace(ev string) error {
	var (
		value []byte
		err   error
	)

	value = make([]byte, 1)
	value[0] = ONE

	if err = writeFile(TRACE_PATH+ev+"/enable", value); err != nil {
		return err
	}

	return nil
}

func disableTrace(ev string) error {
	var (
		value []byte
		err   error
	)

	value = make([]byte, 1)
	value[0] = ZERO

	if err = writeFile(TRACE_PATH+ev+"/enable", value); err != nil {
		return err
	}

	return nil
}

func enableProbe() error {
	var (
		value []byte
		err   error
	)

	value = make([]byte, 1)
	value[0] = ONE

	if err = writeFile(KPROBE_PATH+PROBE_NAME+"/enable", value); err != nil {
		return err
	}

	return nil
}

func disableProbe() error {
	var (
		value []byte
		err   error
	)

	value = make([]byte, 1)
	value[0] = ZERO

	if err = writeFile(KPROBE_PATH+PROBE_NAME+"/enable", value); err != nil {
		return err
	}

	return nil
}

func HasFtrace() bool {
	var (
		data []byte
	)

	data, _ = ioutil.ReadFile("/proc/sys/kernel/ftrace_enabled")

	if len(data) > 0 && data[0] == ONE {
		return true
	}

	return false
}

func (pm *ProcMon) Enable() error {
	var (
		i            int
		fs           os.FileInfo
		fd           *os.File
		probe_config string
		err          error
	)

	// echo 1 > /sys/kernel/debug/tracing/events/kprobes/sched_process_fork/enable
	if err = enableTrace(TRACE_FORK); err != nil {
		return err
	}

	// echo 1 > /sys/kernel/debug/tracing/events/kprobes/sched_process_exec/enable
	if err = enableTrace(TRACE_EXEC); err != nil {
		return err
	}

	// echo 1 > /sys/kernel/debug/tracing/events/kprobes/sched_process_quit/enable
	if err = enableTrace(TRACE_EXIT); err != nil {
		return err
	}

	// echo "..." > /sys/kernel/debug/tracing/kprobe_events
	probe_config = "p:kprobes/" + PROBE_NAME + " sys_execve"
	for i = 0; i < 16; i++ {
		probe_config = fmt.Sprintf("%s arg%d=+0(+%d(%%si)):string", probe_config, i, i*8)
	}

	if fs, err = os.Stat(KPROBE_EVENTS_PATH); err != nil {
		return err
	}

	if fs.IsDir() {
		return errors.New("stat " + KPROBE_EVENTS_PATH + ": is a directory")
	}

	if fd, err = os.OpenFile(KPROBE_EVENTS_PATH, os.O_WRONLY, 0644); err != nil {
		return err
	}
	defer fd.Close()

	_, err = fd.Write([]byte(probe_config))
	if err != nil {
		return err
	}

	// echo 1 > /sys/kernel/debug/tracing/events/kprobes/snitch_sys_execve/enable
	if err = enableProbe(); err != nil {
		return err
	}

	return nil
}

func (pm *ProcMon) Disable() error {
	var (
		fs  os.FileInfo
		fd  *os.File
		err error
	)

	// echo 0 > /sys/kernel/debug/tracing/events/sched/sched_process_fork/enable
	if err = disableTrace(TRACE_FORK); err != nil {
		return err
	}

	// echo 0 > /sys/kernel/debug/tracing/events/sched/sched_process_exec/enable
	if err = disableTrace(TRACE_EXEC); err != nil {
		return err
	}

	// echo 0 > /sys/kernel/debug/tracing/events/sched/sched_process_quit/enable
	if err = disableTrace(TRACE_EXIT); err != nil {
		return err
	}

	// echo 0 > /sys/kernel/debug/tracing/events/kprobes/snitch_sys_execve/enable
	if err = disableProbe(); err != nil {
		return err
	}

	// echo "-:snitch_sys_execve" > /sys/kernel/debug/tracing/kprobe_events
	if fs, err = os.Stat(KPROBE_EVENTS_PATH); err != nil {
		return err
	}

	if fs.IsDir() {
		return errors.New("stat " + KPROBE_EVENTS_PATH + ": is a directory")
	}

	if fd, err = os.OpenFile(KPROBE_EVENTS_PATH, os.O_WRONLY, 0644); err != nil {
		return err
	}
	defer fd.Close()

	// echo "" > /sys/kernel/debug/tracing/trace
	_, err = fd.Write([]byte("-:" + PROBE_NAME))
	if err != nil {
		return err
	}

	if fs, err = os.Stat(TRACE_INFO_PATH); err != nil {
		return err
	}

	if fs.IsDir() {
		return errors.New("stat " + TRACE_INFO_PATH + ": is a directory")
	}

	if fd, err = os.OpenFile(TRACE_INFO_PATH, os.O_WRONLY, 0644); err != nil {
		return err
	}
	defer fd.Close()

	_, err = fd.Write([]byte(""))
	if err != nil {
		return err
	}
	return nil
}

func (pm *ProcMon) Slurp() error {
	var (
		fs             os.FileInfo
		fd             *os.File
		slurpErr       error
		err            error
		buf            *bufio.Reader
		probeName_b    []byte
		line           []byte
		reProbePID     *regexp.Regexp
		reArgs         *regexp.Regexp
		reSched        *regexp.Regexp
		reEventExec    *regexp.Regexp
		reEventExit    *regexp.Regexp
		allMatches     [][][]byte
		allArgs        [][]string
		allExecMatches [][]string
		allExitMatches [][]string
		event          string
		filename       string
		pid            string
	)

	if fs, err = os.Stat(TRACE_PIPE); err != nil {
		return err
	}

	if fs.IsDir() {
		return errors.New("stat " + TRACE_PIPE + ": is a directory")
	}

	if fd, err = os.OpenFile(TRACE_PIPE, os.O_RDONLY, 0644); err != nil {
		return err
	}

	probeName_b = []byte(PROBE_NAME)
	reProbePID = regexp.MustCompile(RE_PROBE_PID)
	reArgs = regexp.MustCompile(RE_PROBE_ARGS)
	reSched = regexp.MustCompile(RE_PROBE_SCHED)
	reEventExec = regexp.MustCompile(RE_EVENT_EXEC)
	reEventExit = regexp.MustCompile(RE_EVENT_EXIT)

	pm.Procs = make(map[string]*Proc, MAX_PROCS)

	buf = bufio.NewReader(fd)

	for {
		line, slurpErr = buf.ReadBytes('\n')
		if slurpErr != nil && slurpErr != io.EOF {
			break
		}

		line = bytes.TrimRight(line, "\n")

		if bytes.Contains(line, probeName_b) { // New process
			allMatches = reProbePID.FindAllSubmatch(line, 1)
			if allMatches == nil {
				continue
			}

			pid = string(allMatches[0][1])

			if bytes.Contains(line, []byte("(fault)")) {
				line = line[:bytes.Index(line, []byte("(fault)"))]
			}

			allArgs = reArgs.FindAllStringSubmatch(string(line), -1)
			if allArgs == nil {
				continue
			}

			args := allArgs[0][1]
			for i := 1; i < len(allArgs); i++ {
				args += " " + allArgs[i][1]
			}

			pm.Procs[pid] = &Proc{
				Args: args,
			}
		} else {
			allMatches = reSched.FindAllSubmatch(line, 1)
			if allMatches == nil {
				continue
			}

			event = string(allMatches[0][1])

			switch event {
			case EV_EXEC:
				{
					allExecMatches = reEventExec.FindAllStringSubmatch(string(line), -1)

					filename = allExecMatches[0][1]
					pid = allExecMatches[0][2]

					if _, ok := pm.Procs[pid]; !ok {
						fmt.Printf("UpdateProc: no such pid: %d\n", pid)
						continue
					}

					pm.Procs[pid].Filename = filename

				}
			case EV_EXIT:
				{
					allExitMatches = reEventExit.FindAllStringSubmatch(string(line), -1)

					pid = allExitMatches[0][1]

					if _, ok := pm.Procs[pid]; ok {
						delete(pm.Procs, pid)
						continue
					}
				}
			}

		}
	}

	return nil
}
