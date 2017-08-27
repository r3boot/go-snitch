package ui

import (
	"fmt"
	"os"

	"github.com/r3boot/go-snitch/lib/rules"

	_ "github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/gtk"
)

func NewManageDetailWindow(dbus *DBusUi) *ManageDetailWindow {
	md := &ManageDetailWindow{
		dbus: dbus,
	}
	md.Create()
	return md
}

func (md *ManageDetailWindow) Create() {
	md.window = gtk.NewWindow(gtk.WINDOW_TOPLEVEL)
	md.window.SetModal(true)
	md.window.SetPosition(gtk.WIN_POS_CENTER)
	md.window.SetTitle("Manage rule")
	md.window.SetSizeRequest(MANAGE_DETAIL_WIDTH, MANAGE_DETAIL_HEIGHT)
	md.window.Connect("delete-event", md.Hide)

	vbox := gtk.NewVBox(false, 1)

	table := gtk.NewTable(6, 2, false)

	labelCommandIntro := newAlignedLabel(gtk.NewLabel("Command"))
	table.Attach(labelCommandIntro, 0, 1, 0, 1, gtk.FILL, gtk.FILL, 0, 5)

	md.commandLabel = gtk.NewLabel("UNSET")
	md.commandLabel.SetJustify(gtk.JUSTIFY_LEFT)
	alignedCommandLabel := gtk.NewAlignment(0, 0, 0, 0)
	alignedCommandLabel.Add(md.commandLabel)
	table.Attach(alignedCommandLabel, 1, 2, 0, 1, gtk.FILL, gtk.FILL, 0, 5)

	labelIpIntro := newAlignedLabel(gtk.NewLabel("Destination"))
	table.Attach(labelIpIntro, 0, 1, 1, 2, gtk.FILL, gtk.FILL, 0, 0)

	md.dstipLabel = gtk.NewEntry()
	md.dstipLabel.SetWidthChars(27)
	table.Attach(md.dstipLabel, 1, 2, 1, 2, gtk.FILL, gtk.FILL, 0, 0)

	labelPortIntro := newAlignedLabel(gtk.NewLabel("Port"))
	table.Attach(labelPortIntro, 0, 1, 2, 3, gtk.FILL, gtk.FILL, 0, 0)

	md.portLabel = gtk.NewEntry()
	table.Attach(md.portLabel, 1, 2, 2, 3, gtk.FILL, gtk.FILL, 0, 0)

	labelUserIntro := newAlignedLabel(gtk.NewLabel("User"))
	table.Attach(labelUserIntro, 0, 1, 3, 5, gtk.FILL, gtk.FILL, 0, 0)

	md.radioSystem = gtk.NewRadioButtonWithLabel(nil, "System")
	table.Attach(md.radioSystem, 1, 2, 3, 4, gtk.FILL, gtk.FILL, 0, 0)

	usernameHBox := gtk.NewHBox(false, 1)
	md.radioUser = gtk.NewRadioButton(md.radioSystem.GetGroup())
	md.radioUser.Connect("toggled", md.radioUserChanged)
	usernameHBox.Add(md.radioUser)
	userLabelEntryAlign := gtk.NewAlignment(0, 0, 0, 0)
	md.userLabelEntry = gtk.NewEntry()
	userLabelEntryAlign.Add(md.userLabelEntry)
	userLabelEntryAlign.SetPadding(0, 0, 0, 0)
	usernameHBox.Add(userLabelEntryAlign)
	table.Attach(usernameHBox, 1, 2, 4, 5, gtk.FILL, gtk.FILL, 0, 0)

	labelActionIntro := newAlignedLabel(gtk.NewLabel("Action"))
	table.Attach(labelActionIntro, 0, 1, 5, 6, gtk.FILL, gtk.FILL, 0, 0)

	md.actionLabel = gtk.NewComboBoxText()
	md.actionLabel.AppendText("accept")
	md.actionLabel.AppendText("drop")

	table.Attach(md.actionLabel, 1, 2, 5, 6, gtk.FILL, gtk.FILL, 0, 0)

	vbox.Add(table)

	buttonHBox := gtk.NewHBox(false, 1)

	buttonUpdate := gtk.NewButtonWithLabel("Update")
	buttonUpdate.Clicked(md.UpdateRule)
	buttonHBox.Add(buttonUpdate)

	buttonDelete := gtk.NewButtonWithLabel("Delete")
	buttonDelete.Clicked(md.DeleteRule)
	buttonHBox.Add(buttonDelete)

	vbox.Add(buttonHBox)

	md.window.Add(vbox)
}

func (md *ManageDetailWindow) SetManageWindow(window *ManageWindow) {
	md.manageWindow = window
}

func (md *ManageDetailWindow) Show() {
	md.window.ShowAll()
}

func (md *ManageDetailWindow) Hide() bool {
	md.window.Hide()
	return true
}

func (md *ManageDetailWindow) UpdateRule() {
	md.Hide()

	md.rule.Dstip = md.dstipLabel.GetText()
	md.rule.Port = md.portLabel.GetText()
	md.rule.Action = md.actionLabel.GetActiveText()
	if md.radioSystem.GetActive() {
		md.rule.User = rules.USER_ANY
	} else {
		md.rule.User = md.userLabelEntry.GetText()
	}

	if err := md.dbus.UpdateRule(md.rule); err != nil {
		fmt.Fprintf(os.Stderr, "md.UpdateRule: %v\n", err)
		return
	}

	md.manageWindow.LoadRules()
}

func (md *ManageDetailWindow) DeleteRule() {
	md.Hide()

	if err := md.dbus.DeleteRule(md.rule.Id); err != nil {
		fmt.Fprintf(os.Stderr, "md.DeleteRule: %v\n", err)
		return
	}

	md.manageWindow.LoadRules()
}

func (md *ManageDetailWindow) radioUserChanged() {
	if md.radioSystem.GetActive() {
		md.userLabelEntry.SetSensitive(false)
	} else {
		md.userLabelEntry.SetSensitive(true)
	}
}

func (md *ManageDetailWindow) SetValues(r rules.RuleDetail) {
	md.rule = r

	if r.Dstip == "" {
		md.window.SetTitle("Edit application rule")
		md.dstipLabel.SetSensitive(false)
		md.portLabel.SetSensitive(false)
	} else {
		md.window.SetTitle("Edit connection rule")
		md.dstipLabel.SetSensitive(true)
		md.portLabel.SetSensitive(true)
	}
	md.commandLabel.SetText(r.Command)

	if r.User == rules.USER_ANY {
		md.radioSystem.SetActive(true)
		md.userLabelEntry.SetText("Enter manually")
		md.userLabelEntry.SetSensitive(false)
	} else {
		md.radioUser.SetActive(true)
		md.userLabelEntry.SetText(r.User)
		md.userLabelEntry.SetSensitive(true)
	}

	if r.Action == "accept" {
		md.actionLabel.SetActive(0)
	} else {
		md.actionLabel.SetActive(1)
	}

	md.dstipLabel.SetText(r.Dstip)
	md.portLabel.SetText(r.Port)
}
