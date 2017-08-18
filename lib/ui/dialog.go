package ui

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/snitch"
)

func getIANAName(proto, port string) string {
	result := "unknown"

	fd, err := os.Open("/etc/services")
	if err != nil {
		return result
	}
	defer fd.Close()

	reLine := regexp.MustCompile(fmt.Sprintf("^([a-z0-9-_]+)\\ +%s/%s$", port, proto))

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		value := reLine.FindStringSubmatch(scanner.Text())
		if len(value) > 0 {
			return value[1]
		}
	}

	return result
}

func newAlignedLabel(label *gtk.Label) *gtk.Alignment {
	labelAlign := gtk.NewAlignment(0, 0, 0, 0)
	label.SetJustify(gtk.JUSTIFY_LEFT)
	label.SetPadding(10, 0)
	labelAlign.Add(label)
	return labelAlign
}

func newButton(label string, f func(), hotkey uint, ag *gtk.AccelGroup) *gtk.Button {
	button := gtk.NewButtonWithLabel(label)
	button.Clicked(f)
	if ag != nil {
		button.AddAccelerator("activate", ag, hotkey, gdk.CONTROL_MASK, gtk.ACCEL_VISIBLE)
	}
	return button
}

func NewDialogWindow() *DialogWindow {
	dw := &DialogWindow{}
	dw.Verdict = make(chan int)
	dw.Create()

	return dw
}

func (dw *DialogWindow) Create() {
	dw.window = gtk.NewWindow(gtk.WINDOW_TOPLEVEL)
	dw.window.SetModal(true)
	dw.window.SetPosition(gtk.WIN_POS_CENTER)
	dw.window.SetTitle("New connection request")
	dw.window.SetIconName("gtk-dialog-info")
	dw.window.Connect("destroy", dw.GtkDestroy, "quit")
	dw.window.SetSizeRequest(WINDOW_WIDTH, WINDOW_HEIGHT)

	accelGroup := gtk.NewAccelGroup()
	dw.window.AddAccelGroup(accelGroup)

	vbox := gtk.NewVBox(false, 1)

	dw.labelHeader = gtk.NewLabel("UNSET")
	dw.labelHeader.SetPadding(50, 10)
	vbox.Add(dw.labelHeader)

	topSeparator := gtk.NewHSeparator()
	vbox.Add(topSeparator)

	additionalHBox := gtk.NewHBox(false, 1)

	labelVBox := gtk.NewVBox(false, 1)
	labelVBox.Add(newAlignedLabel(gtk.NewLabel("App:")))
	labelVBox.Add(newAlignedLabel(gtk.NewLabel("Ip:")))
	labelVBox.Add(newAlignedLabel(gtk.NewLabel("Port:")))
	labelVBox.Add(newAlignedLabel(gtk.NewLabel("Pid:")))
	labelVBox.Add(newAlignedLabel(gtk.NewLabel("User:")))
	additionalHBox.PackStart(labelVBox, false, false, 0)

	detailVBox := gtk.NewVBox(false, 1)
	dw.labelCmdline = gtk.NewLabel("UNSET")
	dw.labelIp = gtk.NewLabel("UNSET")
	dw.labelPort = gtk.NewLabel("UNSET")
	dw.labelPid = gtk.NewLabel("UNSET")
	dw.labelUser = gtk.NewLabel("UNSET")

	detailVBox.Add(newAlignedLabel(dw.labelCmdline))
	detailVBox.Add(newAlignedLabel(dw.labelIp))
	detailVBox.Add(newAlignedLabel(dw.labelPort))
	detailVBox.Add(newAlignedLabel(dw.labelPid))
	detailVBox.Add(newAlignedLabel(dw.labelUser))

	additionalHBox.PackStart(detailVBox, false, false, 0)

	vbox.Add(additionalHBox)

	bottomSeparator := gtk.NewHSeparator()
	vbox.Add(bottomSeparator)

	comboHBox := gtk.NewHBox(true, 1)
	comboHBox.SetBorderWidth(10)

	labelActionAlign := gtk.NewAlignment(0, 0, 0, 10)
	labelAction := gtk.NewLabel("Take this action")
	labelAction.SetJustify(gtk.JUSTIFY_LEFT)
	labelActionAlign.Add(labelAction)
	comboHBox.PackStart(labelActionAlign, false, true, 0)

	dw.actioncombo = gtk.NewComboBoxText()
	dw.actioncombo.AppendText("Once")
	dw.actioncombo.AppendText("Until Quit")
	dw.actioncombo.AppendText("Forever")
	dw.actioncombo.SetActive(1)
	dw.actioncombo.Connect("changed", dw.ActionChanged)
	comboHBox.PackStart(dw.actioncombo, true, true, 0)

	vbox.Add(comboHBox)

	buttonHBox := gtk.NewHBox(false, 1)

	buttonHBox.SetBorderWidth(10)
	buttonHBox.Add(newButton("Whitelist app", dw.Whitelist, 'w', accelGroup))
	buttonHBox.Add(newButton("Block app", dw.Block, 'b', accelGroup))
	buttonHBox.Add(newButton("Deny", dw.Deny, 'd', accelGroup))
	buttonHBox.Add(newButton("Allow", dw.Allow, 'a', accelGroup))

	vbox.Add(buttonHBox)

	dw.window.Add(vbox)
}

func (dw *DialogWindow) GtkDestroy(ctx *glib.CallbackContext) {
	fmt.Println("Closing dialogbox")
	dw.window.Hide()
}

func (dw *DialogWindow) Hide() {
	dw.window.Hide()
}

func (dw *DialogWindow) Destroy() {
	dw.window.Destroy()
}

func (dw *DialogWindow) Show() {
	gdk.ThreadsEnter()
	dw.window.ShowAll()
	gdk.ThreadsLeave()
}

func (dw *DialogWindow) ActionChanged() {
	fmt.Println("Selected", dw.actioncombo.GetActiveText())
}

func (dw *DialogWindow) Whitelist() {
	fmt.Println("Whitelist clicked")
	dw.Hide()
}

func (dw *DialogWindow) Block() {
	fmt.Println("Block clicked")
	dw.Hide()
}

func (dw *DialogWindow) Deny() {
	fmt.Println("Dropping connection")
	dw.Verdict <- snitch.DROP_CONN_ALWAYS
	dw.Hide()
}

func (dw *DialogWindow) Allow() {
	fmt.Println("Accepting connection")
	dw.Verdict <- snitch.ACCEPT_CONN_ALWAYS
	dw.Hide()
}

func (dw *DialogWindow) SetValues(r snitch.ConnRequest) {
	appname := fmt.Sprintf("<b>%s wants to connect to the network</b>", path.Base(strings.Split(r.Command, " ")[0]))
	portName := getIANAName(strings.ToLower(r.Proto), r.DstPort)

	port := fmt.Sprintf("%s/%s", r.Proto, r.DstPort)
	if portName != "" {
		port = fmt.Sprintf("%s (%s)", port, portName)
	}

	destip := r.DstIp

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	names, err := net.DefaultResolver.LookupAddr(ctx, r.DstIp)
	defer cancel()

	if err == nil && len(names) > 0 {
		destip = names[0][:len(names[0])-1]
	}

	cmdline := r.Cmdline
	if len(cmdline) > 44 {
		cmdline = cmdline[:41] + "..."
	}

	dw.labelHeader.SetMarkup(appname)
	dw.labelCmdline.SetText(cmdline)
	dw.labelIp.SetText(destip)
	dw.labelPort.SetText(port)
	dw.labelPid.SetText(r.Pid)
	dw.labelUser.SetText(r.User)

}
