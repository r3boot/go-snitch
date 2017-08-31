package icon

import (
	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/ui"
	"github.com/r3boot/go-snitch/lib/ui/dialog"
)

func NewStatusIcon() *StatusIcon {
	si := &StatusIcon{}

	builder := gtk.NewBuilder()
	builder.AddFromString(GLADE_DATA)

	si.Dialog = dialog.NewDialogWindow()
	si.itemEnable = ui.ObjectToMenuItem(builder, "MenuEnable")
	si.itemDisable = ui.ObjectToMenuItem(builder, "MenuDisable")
}
