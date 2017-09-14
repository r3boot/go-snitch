package kernel

const (
	ZERO               byte   = 0x30
	ONE                byte   = 0x31
	MAX_PROCS          int    = 65535
	TRACE_PATH         string = "/sys/kernel/debug/tracing/events/sched/"
	TRACE_FORK         string = "sched_process_fork"
	TRACE_EXEC         string = "sched_process_exec"
	TRACE_EXIT         string = "sched_process_exit"
	KPROBE_EVENTS_PATH string = "/sys/kernel/debug/tracing/kprobe_events"
	KPROBE_PATH        string = "/sys/kernel/debug/tracing/events/kprobes/"
	TRACE_INFO_PATH    string = "/sys/kernel/debug/tracing/trace"
	TRACE_PIPE         string = "/sys/kernel/debug/tracing/trace_pipe"
	PROBE_NAME         string = "snitch_sys_execve"
	RE_PROBE_PID       string = "^.*?-(?P<pid>\\d+)\\s*\\["
	RE_PROBE_ARGS      string = "arg\\d+=\"(.*?)\""
	RE_PROBE_SCHED     string = "sched_process_(?P<event>.*?):"
	RE_EVENT_EXEC      string = "filename=(?P<filename>.*?)\\s+pid=(\\d+)"
	RE_EVENT_EXIT      string = " pid=(\\d+)"
	EV_EXEC            string = "exec"
	EV_EXIT            string = "exit"
	MAX_RESOLVERS      int    = 16
)