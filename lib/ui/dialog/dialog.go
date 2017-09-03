package dialog

import (
	"time"

	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/snitch"
	"github.com/r3boot/go-snitch/lib/ui"
)

func NewDialogWindow() *DialogWindow {
	dw := &DialogWindow{}

	dw.whitelistResponseMap = map[ui.Action]map[ui.Scope]int{
		ui.ACTION_ONCE: {
			ui.SCOPE_USER:   snitch.ACCEPT_APP_ONCE_USER,
			ui.SCOPE_SYSTEM: snitch.ACCEPT_APP_ONCE_SYSTEM,
		},
		ui.ACTION_SESSION: {
			ui.SCOPE_USER:   snitch.ACCEPT_APP_SESSION_USER,
			ui.SCOPE_SYSTEM: snitch.ACCEPT_APP_SESSION_SYSTEM,
		},
		ui.ACTION_FOREVER: {
			ui.SCOPE_USER:   snitch.ACCEPT_APP_ALWAYS_USER,
			ui.SCOPE_SYSTEM: snitch.ACCEPT_APP_ALWAYS_SYSTEM,
		},
	}

	dw.blacklistResponseMap = map[ui.Action]map[ui.Scope]int{
		ui.ACTION_ONCE: {
			ui.SCOPE_USER:   snitch.DROP_APP_ONCE_USER,
			ui.SCOPE_SYSTEM: snitch.DROP_APP_ONCE_SYSTEM,
		},
		ui.ACTION_SESSION: {
			ui.SCOPE_USER:   snitch.DROP_APP_SESSION_USER,
			ui.SCOPE_SYSTEM: snitch.DROP_APP_SESSION_SYSTEM,
		},
		ui.ACTION_FOREVER: {
			ui.SCOPE_USER:   snitch.DROP_APP_ALWAYS_SYSTEM,
			ui.SCOPE_SYSTEM: snitch.DROP_CONN_ALWAYS_USER,
		},
	}

	dw.allowResponseMap = map[ui.Action]map[ui.Scope]int{
		ui.ACTION_ONCE: {
			ui.SCOPE_USER:   snitch.ACCEPT_CONN_ONCE_USER,
			ui.SCOPE_SYSTEM: snitch.ACCEPT_CONN_ONCE_SYSTEM,
		},
		ui.ACTION_SESSION: {
			ui.SCOPE_USER:   snitch.ACCEPT_CONN_SESSION_USER,
			ui.SCOPE_SYSTEM: snitch.ACCEPT_CONN_SESSION_SYSTEM,
		},
		ui.ACTION_FOREVER: {
			ui.SCOPE_USER:   snitch.ACCEPT_CONN_ALWAYS_USER,
			ui.SCOPE_SYSTEM: snitch.ACCEPT_CONN_ALWAYS_SYSTEM,
		},
	}

	dw.denyResponseMap = map[ui.Action]map[ui.Scope]int{
		ui.ACTION_ONCE: {
			ui.SCOPE_USER:   snitch.DROP_CONN_ONCE_USER,
			ui.SCOPE_SYSTEM: snitch.DROP_CONN_ONCE_SYSTEM,
		},
		ui.ACTION_SESSION: {
			ui.SCOPE_USER:   snitch.DROP_CONN_SESSION_USER,
			ui.SCOPE_SYSTEM: snitch.DROP_CONN_SESSION_SYSTEM,
		},
		ui.ACTION_FOREVER: {
			ui.SCOPE_USER:   snitch.DROP_CONN_ALWAYS_USER,
			ui.SCOPE_SYSTEM: snitch.DROP_CONN_ALWAYS_SYSTEM,
		},
	}

	dw.durationMap = map[ui.Duration]time.Duration{}
	dw.durationMap[ui.DURATION_5M], _ = time.ParseDuration(string(ui.DURATION_5M))
	dw.durationMap[ui.DURATION_1H], _ = time.ParseDuration(string(ui.DURATION_1H))
	dw.durationMap[ui.DURATION_8H], _ = time.ParseDuration(string(ui.DURATION_1H))
	dw.durationMap[ui.DURATION_24H], _ = time.ParseDuration(string(ui.DURATION_24H))
	dw.durationMap[ui.DURATION_FOREVER], _ = time.ParseDuration("0s")

	builder := gtk.NewBuilder()
	builder.AddFromString(GLADE_DATA)

	dw.window = ui.ObjectToWindow(builder, "DialogWindow")

	dw.labelHeader = ui.ObjectToLabel(builder, "LabelHeader")
	dw.labelCmdline = ui.ObjectToLabel(builder, "LabelCommand")
	dw.labelDestination = ui.ObjectToLabel(builder, "LabelDestination")
	dw.labelPort = ui.ObjectToLabel(builder, "LabelPort")
	dw.labelPid = ui.ObjectToLabel(builder, "LabelPid")
	dw.labelUser = ui.ObjectToLabel(builder, "LabelUser")

	dw.comboAction = ui.ObjectToComboBoxText(builder, "ComboAction")
	dw.comboAction.AppendText(string(ui.ACTION_ONCE))
	dw.comboAction.AppendText(string(ui.ACTION_SESSION))
	dw.comboAction.AppendText(string(ui.ACTION_FOREVER))

	dw.comboScope = ui.ObjectToComboBoxText(builder, "ComboScope")
	dw.comboScope.AppendText(string(ui.SCOPE_USER))
	dw.comboScope.AppendText(string(ui.SCOPE_SYSTEM))

	dw.comboDuration = ui.ObjectToComboBoxText(builder, "ComboDuration")
	dw.comboDuration.AppendText(string(ui.DURATION_5M))
	dw.comboDuration.AppendText(string(ui.DURATION_1H))
	dw.comboDuration.AppendText(string(ui.DURATION_8H))
	dw.comboDuration.AppendText(string(ui.DURATION_24H))
	dw.comboDuration.AppendText(string(ui.DURATION_FOREVER))

	dw.Verdict = make(chan int)

	dw.initCallbacks(builder)

	return dw
}
