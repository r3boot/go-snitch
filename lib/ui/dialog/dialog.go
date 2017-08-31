package dialog

import (
	"github.com/r3boot/go-snitch/lib/ui"

	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/snitch"
	"time"
)

func NewDialogWindow() *DialogWindow {
	dw := &DialogWindow{}

	dw.whitelistResponseMap = map[Action]map[Scope]int{
		ACTION_ONCE: {
			SCOPE_USER:   snitch.ACCEPT_APP_ONCE_USER,
			SCOPE_SYSTEM: snitch.ACCEPT_APP_ONCE_SYSTEM,
		},
		ACTION_SESSION: {
			SCOPE_USER:   snitch.ACCEPT_APP_SESSION_USER,
			SCOPE_SYSTEM: snitch.ACCEPT_APP_SESSION_SYSTEM,
		},
		ACTION_FOREVER: {
			SCOPE_USER:   snitch.ACCEPT_APP_ALWAYS_USER,
			SCOPE_SYSTEM: snitch.ACCEPT_APP_ALWAYS_SYSTEM,
		},
	}

	dw.blacklistResponseMap = map[Action]map[Scope]int{
		ACTION_ONCE: {
			SCOPE_USER:   snitch.DROP_APP_ONCE_USER,
			SCOPE_SYSTEM: snitch.DROP_APP_ONCE_SYSTEM,
		},
		ACTION_SESSION: {
			SCOPE_USER:   snitch.DROP_APP_SESSION_USER,
			SCOPE_SYSTEM: snitch.DROP_APP_SESSION_SYSTEM,
		},
		ACTION_FOREVER: {
			SCOPE_USER:   snitch.DROP_APP_ALWAYS_SYSTEM,
			SCOPE_SYSTEM: snitch.DROP_CONN_ALWAYS_USER,
		},
	}

	dw.allowResponseMap = map[Action]map[Scope]int{
		ACTION_ONCE: {
			SCOPE_USER:   snitch.ACCEPT_CONN_ONCE_USER,
			SCOPE_SYSTEM: snitch.ACCEPT_CONN_ONCE_SYSTEM,
		},
		ACTION_SESSION: {
			SCOPE_USER:   snitch.ACCEPT_CONN_SESSION_USER,
			SCOPE_SYSTEM: snitch.ACCEPT_CONN_SESSION_SYSTEM,
		},
		ACTION_FOREVER: {
			SCOPE_USER:   snitch.ACCEPT_CONN_ALWAYS_USER,
			SCOPE_SYSTEM: snitch.ACCEPT_CONN_ALWAYS_SYSTEM,
		},
	}

	dw.denyResponseMap = map[Action]map[Scope]int{
		ACTION_ONCE: {
			SCOPE_USER:   snitch.DROP_CONN_ONCE_USER,
			SCOPE_SYSTEM: snitch.DROP_CONN_ONCE_SYSTEM,
		},
		ACTION_SESSION: {
			SCOPE_USER:   snitch.DROP_CONN_SESSION_USER,
			SCOPE_SYSTEM: snitch.DROP_CONN_SESSION_SYSTEM,
		},
		ACTION_FOREVER: {
			SCOPE_USER:   snitch.DROP_CONN_ALWAYS_USER,
			SCOPE_SYSTEM: snitch.DROP_CONN_ALWAYS_SYSTEM,
		},
	}

	dw.durationMap = map[Duration]time.Duration{}
	dw.durationMap[DURATION_5M], _ = time.ParseDuration(DURATION_5M)
	dw.durationMap[DURATION_1H], _ = time.ParseDuration(DURATION_1H)
	dw.durationMap[DURATION_8H], _ = time.ParseDuration(DURATION_1H)
	dw.durationMap[DURATION_24H], _ = time.ParseDuration(DURATION_24H)
	dw.durationMap[DURATION_FOREVER], _ = time.ParseDuration("0s")

	builder := gtk.NewBuilder()
	builder.AddFromString(GLADE_DATA)

	dw.labelHeader = ui.ObjectToLabel(builder, "LabelHeader")
	dw.labelCmdline = ui.ObjectToLabel(builder, "LabelCmdline")
	dw.labelIp = ui.ObjectToLabel(builder, "LabelIp")
	dw.labelPort = ui.ObjectToLabel(builder, "LabelPort")
	dw.labelPid = ui.ObjectToLabel(builder, "LabelPid")
	dw.labelUser = ui.ObjectToLabel(builder, "LabelUser")

	dw.comboAction = ui.ObjectToComboBoxText(builder, "ComboAction")
	dw.comboAction.AppendText(ACTION_ONCE)
	dw.comboAction.AppendText(ACTION_SESSION)
	dw.comboAction.AppendText(ACTION_FOREVER)

	dw.comboScope = ui.ObjectToComboBoxText(builder, "ComboScope")
	dw.comboScope.AppendText(SCOPE_USER)
	dw.comboScope.AppendText(SCOPE_SYSTEM)

	dw.comboDuration = ui.ObjectToComboBoxText(builder, "ComboDuration")
	dw.comboDuration.AppendText(DURATION_5M)
	dw.comboDuration.AppendText(DURATION_1H)
	dw.comboDuration.AppendText(DURATION_8H)
	dw.comboDuration.AppendText(DURATION_24H)
	dw.comboDuration.AppendText(DURATION_FOREVER)

	dw.Verdict = make(chan int)

	dw.initCallbacks(builder)

	return dw
}
