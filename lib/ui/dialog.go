package ui

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

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
		value := reLine.FindString(scanner.Text())
		if value != "" {
			return value
		}
	}

	return result
}

func NewDialogWindow() *DialogWindow {
	dw := &DialogWindow{}
	dw.Verdict = make(chan int)
	dw.Create()

	return dw
}

func (dw *DialogWindow) Create() {
	dw.window = gtk.NewWindow(gtk.WINDOW_POPUP)
	dw.window.SetPosition(gtk.WIN_POS_CENTER)
	dw.window.SetTitle("Hello")
	dw.window.SetIconName("gtk-dialog-info")
	dw.window.Connect("destroy", dw.GtkDestroy, "quit")

	vbox := gtk.NewVBox(false, 1)

	dw.labelHeader = gtk.NewLabel("UNSET")
	vbox.Add(dw.labelHeader)

	separator := gtk.NewHSeparator()
	vbox.Add(separator)

	dw.labelBody = gtk.NewLabel("UNSET")
	dw.labelBody.SetLineWrap(true)
	vbox.Add(dw.labelBody)

	comboHBox := gtk.NewHBox(false, 1)

	labelAction := gtk.NewLabel("Take this action")
	comboHBox.Add(labelAction)

	dw.actioncombo = gtk.NewComboBoxText()
	dw.actioncombo.AppendText("Once")
	dw.actioncombo.AppendText("Until Quit")
	dw.actioncombo.AppendText("Forever")
	dw.actioncombo.SetActive(0)
	dw.actioncombo.Connect("changed", dw.ActionChanged)
	comboHBox.Add(dw.actioncombo)

	vbox.Add(comboHBox)

	buttonHBox := gtk.NewHBox(false, 1)

	buttonWhitelist := gtk.NewButtonWithLabel("Whitelist app")
	buttonWhitelist.Clicked(dw.Whitelist)
	buttonHBox.Add(buttonWhitelist)

	buttonBlock := gtk.NewButtonWithLabel("Block app")
	buttonBlock.Clicked(dw.Block)
	buttonHBox.Add(buttonBlock)

	buttonDeny := gtk.NewButtonWithLabel("Deny")
	buttonDeny.Clicked(dw.Deny)
	buttonHBox.Add(buttonDeny)

	buttonAllow := gtk.NewButtonWithLabel("Allow")
	buttonAllow.Clicked(dw.Allow)
	buttonHBox.Add(buttonAllow)
	buttonHBox.ShowAll()

	vbox.Add(buttonHBox)

	dw.window.Add(vbox)
	dw.window.SetSizeRequest(WINDOW_WIDTH, WINDOW_HEIGHT)
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
	appname := path.Base(strings.Split(r.Cmdline, " ")[0])
	dw.labelHeader.SetText(appname)

	portName := getIANAName("tcp", r.DstPort)

	body := fmt.Sprintf("%s (pid=%s, user=%s) wants to connect to %s on %s port %s (%s)", r.Cmdline, r.Pid, r.User, r.DstIp, "tcp", r.DstPort, portName)
	dw.labelBody.SetText(body)
}
