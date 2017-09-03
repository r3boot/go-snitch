package detail

import (
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/ui"
	"github.com/r3boot/go-snitch/lib/ui/ipc"
)

func NewManageDetailDialog(dbus *ipc.IPCService) *ManageDetailDialog {
	md := &ManageDetailDialog{
		dbus: dbus,
	}

	builder := gtk.NewBuilder()
	builder.AddFromString(GLADE_DATA)

	md.window = ui.ObjectToWindow(builder, "DetailWindow")

	md.commandLabel = ui.ObjectToLabel(builder, "LabelCommand")
	md.destinationEntry = ui.ObjectToEntry(builder, "EntryDestination")
	md.portEntry = ui.ObjectToEntry(builder, "EntryPort")
	md.systemRadio = ui.ObjectToRadioButton(builder, "RadioSystem")
	md.userRadio = ui.ObjectToRadioButton(builder, "RadioUser")
	md.userEntry = ui.ObjectToEntry(builder, "EntryUser")

	md.actionCombo = ui.ObjectToComboBoxText(builder, "ComboAction")
	md.actionCombo.AppendText(ui.VerdictNameMap[netfilter.NF_ACCEPT])
	md.actionCombo.AppendText(ui.VerdictNameMap[netfilter.NF_DROP])

	md.durationCombo = ui.ObjectToComboBoxText(builder, "ComboDuration")
	md.durationCombo.AppendText(string(ui.DURATION_5M))
	md.durationCombo.AppendText(string(ui.DURATION_1H))
	md.durationCombo.AppendText(string(ui.DURATION_8H))
	md.durationCombo.AppendText(string(ui.DURATION_24H))
	md.durationCombo.AppendText(string(ui.DURATION_FOREVER))

	md.initCallbacks(builder)

	return md
}
