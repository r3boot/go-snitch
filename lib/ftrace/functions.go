package ftrace

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"

	"github.com/r3boot/go-snitch/lib/utils"
)

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

func (pm *Ftrace) GetCmdline(pid string) (string, string, error) {
	entry, ok := pm.procmap[pid]
	if !ok {
		return "", "", fmt.Errorf("Ftrace.GetCmdline: PID %s not found in procmap", pid)
	}
	return entry.Filename, entry.Args, nil
}

func (pm *Ftrace) enableTrace(ev string) error {
	var (
		value []byte
		err   error
	)

	value = make([]byte, 1)
	value[0] = ONE

	if err = utils.WriteToFile(TRACE_PATH+ev+"/enable", value); err != nil {
		return fmt.Errorf("enableTrace: %v", err)
	}

	return nil
}

func (pm *Ftrace) disableTrace(ev string) error {
	var (
		value []byte
		err   error
	)

	value = make([]byte, 1)
	value[0] = ZERO

	if err = utils.WriteToFile(TRACE_PATH+ev+"/enable", value); err != nil {
		return fmt.Errorf("disableTrace: %v", err)
	}

	return nil
}

func (pm *Ftrace) enableProbe() error {
	var (
		value []byte
		err   error
	)

	value = make([]byte, 1)
	value[0] = ONE

	if err = utils.WriteToFile(KPROBE_PATH+PROBE_NAME+"/enable", value); err != nil {
		return fmt.Errorf("enableProbe: %v", err)
	}

	return nil
}

func (pm *Ftrace) disableProbe() error {
	var (
		value []byte
		err   error
	)

	value = make([]byte, 1)
	value[0] = ZERO

	if err = utils.WriteToFile(KPROBE_PATH+PROBE_NAME+"/enable", value); err != nil {
		return fmt.Errorf("disableProbe: %v", err)
	}

	return nil
}

func (pm *Ftrace) Enable() error {
	var (
		i            int
		fs           os.FileInfo
		fd           *os.File
		probe_config string
		err          error
	)

	// echo 1 > /sys/kernel/debug/tracing/events/kprobes/sched_process_fork/enable
	if err = pm.enableTrace(TRACE_FORK); err != nil {
		return fmt.Errorf("Ftrace.Enable: %v", err)
	}

	// echo 1 > /sys/kernel/debug/tracing/events/kprobes/sched_process_exec/enable
	if err = pm.enableTrace(TRACE_EXEC); err != nil {
		return fmt.Errorf("Ftrace.Enable: %v", err)
	}

	// echo 1 > /sys/kernel/debug/tracing/events/kprobes/sched_process_quit/enable
	if err = pm.enableTrace(TRACE_EXIT); err != nil {
		return fmt.Errorf("Ftrace.Enable: %v", err)
	}

	// echo "..." > /sys/kernel/debug/tracing/kprobe_events
	probe_config = "p:kprobes/" + PROBE_NAME + " sys_execve"
	for i = 0; i < 16; i++ {
		probe_config = fmt.Sprintf("%s arg%d=+0(+%d(%%si)):string", probe_config, i, i*8)
	}

	if fs, err = os.Stat(KPROBE_EVENTS_PATH); err != nil {
		return fmt.Errorf("Ftrace.Enable: %v", KPROBE_EVENTS_PATH, err)
	}

	if fs.IsDir() {
		return fmt.Errorf("Ftrace.Enable: stat " + KPROBE_EVENTS_PATH + ": is a directory")
	}

	if fd, err = os.OpenFile(KPROBE_EVENTS_PATH, os.O_WRONLY, 0644); err != nil {
		return fmt.Errorf("Ftrace.Enable: %v", err)
	}
	defer fd.Close()

	_, err = fd.Write([]byte(probe_config))
	if err != nil {
		return fmt.Errorf("Ftrace.Enable: %v", err)
	}

	// echo 1 > /sys/kernel/debug/tracing/events/kprobes/snitch_sys_execve/enable
	if err = pm.enableProbe(); err != nil {
		return fmt.Errorf("Ftrace.Enable: %v", err)
	}

	return nil
}

func (pm *Ftrace) Disable() error {
	var (
		fs  os.FileInfo
		fd  *os.File
		err error
	)

	// echo 0 > /sys/kernel/debug/tracing/events/sched/sched_process_fork/enable
	if err = pm.disableTrace(TRACE_FORK); err != nil {
		return fmt.Errorf("Ftrace.Disable: %v", err)
	}

	// echo 0 > /sys/kernel/debug/tracing/events/sched/sched_process_exec/enable
	if err = pm.disableTrace(TRACE_EXEC); err != nil {
		return fmt.Errorf("Ftrace.Disable: %v", err)
	}

	// echo 0 > /sys/kernel/debug/tracing/events/sched/sched_process_quit/enable
	if err = pm.disableTrace(TRACE_EXIT); err != nil {
		return fmt.Errorf("Ftrace.Disable: %v", err)
	}

	// echo 0 > /sys/kernel/debug/tracing/events/kprobes/snitch_sys_execve/enable
	if err = pm.disableProbe(); err != nil {
		return fmt.Errorf("Ftrace.Disable: %v", err)
	}

	// echo "-:snitch_sys_execve" > /sys/kernel/debug/tracing/kprobe_events
	if fs, err = os.Stat(KPROBE_EVENTS_PATH); err != nil {
		return fmt.Errorf("Ftrace.Disable: %v", err)
	}

	if fs.IsDir() {
		return fmt.Errorf("Ftrace.Disable: stat " + KPROBE_EVENTS_PATH + ": is a directory")
	}

	if fd, err = os.OpenFile(KPROBE_EVENTS_PATH, os.O_WRONLY, 0644); err != nil {
		return err
	}
	defer fd.Close()

	// echo "" > /sys/kernel/debug/tracing/trace
	_, err = fd.Write([]byte("-:" + PROBE_NAME))
	if err != nil {
		return fmt.Errorf("Ftrace.Disable: %v", err)
	}

	if fs, err = os.Stat(TRACE_INFO_PATH); err != nil {
		return fmt.Errorf("Ftrace.Disable: %v", err)
	}

	if fs.IsDir() {
		return fmt.Errorf("Ftrace.Disable: stat " + TRACE_INFO_PATH + ": is a directory")
	}

	if fd, err = os.OpenFile(TRACE_INFO_PATH, os.O_WRONLY, 0644); err != nil {
		return fmt.Errorf("Ftrace.Disable: %v", err)
	}
	defer fd.Close()

	_, err = fd.Write([]byte(""))
	if err != nil {
		return fmt.Errorf("Ftrace.Disable: %v", err)
	}
	return nil
}

func (pm *Ftrace) Slurp() {
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
		log.Warningf("Ftrace.Slurp: %v", err)
		return
	}

	if fs.IsDir() {
		log.Warningf("Ftrace.Slurp: stat " + TRACE_PIPE + ": is a directory")
		return
	}

	if fd, err = os.OpenFile(TRACE_PIPE, os.O_RDONLY, 0644); err != nil {
		log.Warningf("Ftrace.Slurp: %v", err)
		return
	}

	probeName_b = []byte(PROBE_NAME)
	reProbePID = regexp.MustCompile(RE_PROBE_PID)
	reArgs = regexp.MustCompile(RE_PROBE_ARGS)
	reSched = regexp.MustCompile(RE_PROBE_SCHED)
	reEventExec = regexp.MustCompile(RE_EVENT_EXEC)
	reEventExit = regexp.MustCompile(RE_EVENT_EXIT)

	buf = bufio.NewReader(fd)

	for {
		line, slurpErr = buf.ReadBytes('\n')
		if slurpErr != nil && slurpErr != io.EOF {
			log.Warningf("Ftrace.Slurp: Error from reading trace pipe: %v", err)
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

			pm.procmap[pid] = &Proc{
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

					if _, ok := pm.procmap[pid]; !ok {
						log.Warningf("Ftrace.Slurp: Failed to update PID %s; not found in pidmap", pid)
						continue
					}

					pm.procmap[pid].Filename = filename

				}
			case EV_EXIT:
				{
					allExitMatches = reEventExit.FindAllStringSubmatch(string(line), -1)

					pid = allExitMatches[0][1]

					if _, ok := pm.procmap[pid]; ok {
						delete(pm.procmap, pid)
						continue
					}
				}
			}

		}
	}

	return
}
