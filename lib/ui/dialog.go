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

func getIANAName(proto int, port string) string {
	result := "unknown"

	fd, err := os.Open("/etc/services")
	if err != nil {
		return result
	}
	defer fd.Close()

	protoName := ""
	switch proto {
	case snitch.PROTO_TCP:
		{
			protoName = "tcp"
		}
	case snitch.PROTO_UDP:
		{
			protoName = "udp"
		}
	}

	reLine := regexp.MustCompile(fmt.Sprintf("^([a-z0-9-_]+)\\ +%s/%d$", port, protoName))

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

	comboVBox := gtk.NewVBox(true, 1)
	comboVBox.SetBorderWidth(10)

	comboActionHBox := gtk.NewHBox(true, 1)

	labelActionAlign := gtk.NewAlignment(0, 0, 0, 10)
	labelAction := gtk.NewLabel("Take this action")
	labelAction.SetJustify(gtk.JUSTIFY_LEFT)
	labelActionAlign.Add(labelAction)
	comboActionHBox.PackStart(labelActionAlign, false, true, 0)

	dw.actioncombo = gtk.NewComboBoxText()
	dw.actioncombo.AppendText(actionOptions[ACTION_ONCE])
	dw.actioncombo.AppendText(actionOptions[ACTION_SESSION])
	dw.actioncombo.AppendText(actionOptions[ACTION_ALWAYS])
	dw.actioncombo.SetActive(ACTION_SESSION)
	comboActionHBox.PackStart(dw.actioncombo, true, true, 0)

	comboVBox.Add(comboActionHBox)

	comboApplyToHBox := gtk.NewHBox(true, 1)

	labelApplyToAlign := gtk.NewAlignment(0, 0, 0, 10)
	labelApplyTo := gtk.NewLabel("Apply this rule")
	labelApplyTo.SetJustify(gtk.JUSTIFY_LEFT)
	labelApplyToAlign.Add(labelApplyTo)
	comboApplyToHBox.PackStart(labelApplyToAlign, false, true, 0)

	dw.applycombo = gtk.NewComboBoxText()
	dw.applycombo.AppendText(applyOptions[APPLY_USER])
	dw.applycombo.AppendText(applyOptions[APPLY_SYSTEM])
	dw.applycombo.SetActive(APPLY_USER)
	comboApplyToHBox.PackStart(dw.applycombo, true, true, 0)

	comboVBox.Add(comboApplyToHBox)
	vbox.Add(comboVBox)

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
	switch dw.applycombo.GetActive() {
	case APPLY_USER:
		{
			switch dw.actioncombo.GetActive() {
			case ACTION_ONCE:
				{
					dw.Verdict <- snitch.ACCEPT_APP_ONCE_USER
				}
			case ACTION_SESSION:
				{
					dw.Verdict <- snitch.ACCEPT_APP_SESSION_USER
				}
			case ACTION_ALWAYS:
				{
					dw.Verdict <- snitch.ACCEPT_APP_ALWAYS_USER
				}
			}
		}
	case APPLY_SYSTEM:
		{
			switch dw.actioncombo.GetActive() {
			case ACTION_ONCE:
				{
					dw.Verdict <- snitch.ACCEPT_APP_ONCE_SYSTEM
				}
			case ACTION_SESSION:
				{
					dw.Verdict <- snitch.ACCEPT_APP_SESSION_SYSTEM
				}
			case ACTION_ALWAYS:
				{
					dw.Verdict <- snitch.ACCEPT_APP_ALWAYS_SYSTEM
				}
			}
		}
	}
	dw.Hide()
}

func (dw *DialogWindow) Block() {
	switch dw.applycombo.GetActive() {
	case APPLY_USER:
		{
			switch dw.actioncombo.GetActive() {
			case ACTION_ONCE:
				{
					dw.Verdict <- snitch.DROP_APP_ONCE_USER
				}
			case ACTION_SESSION:
				{
					dw.Verdict <- snitch.DROP_APP_SESSION_USER
				}
			case ACTION_ALWAYS:
				{
					dw.Verdict <- snitch.DROP_APP_ALWAYS_USER
				}
			}
		}
	case APPLY_SYSTEM:
		{
			switch dw.actioncombo.GetActive() {
			case ACTION_ONCE:
				{
					dw.Verdict <- snitch.DROP_APP_ONCE_SYSTEM
				}
			case ACTION_SESSION:
				{
					dw.Verdict <- snitch.DROP_APP_SESSION_SYSTEM
				}
			case ACTION_ALWAYS:
				{
					dw.Verdict <- snitch.DROP_APP_ALWAYS_SYSTEM
				}
			}
		}
	}
	dw.Hide()
}

func (dw *DialogWindow) Deny() {
	switch dw.applycombo.GetActive() {
	case APPLY_USER:
		{
			switch dw.actioncombo.GetActive() {
			case ACTION_ONCE:
				{
					dw.Verdict <- snitch.DROP_CONN_ONCE_USER
				}
			case ACTION_SESSION:
				{
					dw.Verdict <- snitch.DROP_CONN_SESSION_USER
				}
			case ACTION_ALWAYS:
				{
					dw.Verdict <- snitch.DROP_CONN_ALWAYS_USER
				}
			}
		}
	case APPLY_SYSTEM:
		{
			switch dw.actioncombo.GetActive() {
			case ACTION_ONCE:
				{
					dw.Verdict <- snitch.DROP_CONN_ONCE_SYSTEM
				}
			case ACTION_SESSION:
				{
					dw.Verdict <- snitch.DROP_CONN_SESSION_SYSTEM
				}
			case ACTION_ALWAYS:
				{
					dw.Verdict <- snitch.DROP_CONN_ALWAYS_SYSTEM
				}
			}
		}
	}
	dw.Hide()
}

func (dw *DialogWindow) Allow() {
	switch dw.applycombo.GetActive() {
	case APPLY_USER:
		switch dw.actioncombo.GetActive() {
		case ACTION_ONCE:
			{
				dw.Verdict <- snitch.ACCEPT_CONN_ONCE_USER
			}
		case ACTION_SESSION:
			{
				dw.Verdict <- snitch.ACCEPT_CONN_SESSION_USER
			}
		case ACTION_ALWAYS:
			{
				dw.Verdict <- snitch.ACCEPT_CONN_ALWAYS_USER
			}
		default:
			{
				fmt.Fprintf(os.Stderr, "Invalid action: %d\n", dw.actioncombo.GetActive())
			}
		}
	case APPLY_SYSTEM:
		switch dw.actioncombo.GetActive() {
		case ACTION_ONCE:
			{
				dw.Verdict <- snitch.ACCEPT_CONN_ONCE_SYSTEM
			}
		case ACTION_SESSION:
			{
				dw.Verdict <- snitch.ACCEPT_CONN_SESSION_SYSTEM
			}
		case ACTION_ALWAYS:
			{
				dw.Verdict <- snitch.ACCEPT_CONN_ALWAYS_SYSTEM
			}
		default:
			{
				fmt.Fprintf(os.Stderr, "Invalid action: %d\n", dw.actioncombo.GetActive())
			}
		}
	}
	dw.Hide()
}

func (dw *DialogWindow) SetValues(r snitch.ConnRequest) {
	appname := fmt.Sprintf("<b>%s wants to connect to the network</b>", path.Base(strings.Split(r.Command, " ")[0]))
	portName := getIANAName(r.Proto, r.Port)

	port := fmt.Sprintf("%s/%s", r.Proto, r.Port)
	if portName != "" {
		port = fmt.Sprintf("%s (%s)", port, portName)
	}

	destip := r.Dstip

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	names, err := net.DefaultResolver.LookupAddr(ctx, r.Dstip)
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

	dw.actioncombo.SetActive(ACTION_SESSION)
	dw.applycombo.SetActive(APPLY_USER)
}
