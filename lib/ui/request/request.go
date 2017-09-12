package request

import (
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/widgets"
)

func NewRequestWindow() *RequestWindow {
	rw := &RequestWindow{
		responseChan: make(chan Response),
	}

	rw.window = widgets.NewQMainWindow(nil, 0)
	rw.window.SetWindowTitle("New connection request")
	rw.window.SetWindowModality(core.Qt__ApplicationModal)

	vboxWidget := widgets.NewQWidget(nil, 0)
	vbox := widgets.NewQVBoxLayout2(vboxWidget)

	rw.labelHeader = widgets.NewQLabel2("<font size='3'><b>blah wants to connect to the network</b></font>", nil, 0)
	vbox.AddWidget(rw.labelHeader, 0, core.Qt__AlignCenter)

	separator := widgets.NewQFrame(nil, 0)
	separator.SetFrameShape(widgets.QFrame__HLine)
	separator.SetFrameShadow(widgets.QFrame__Sunken)
	separator.SetLineWidth(2)
	vbox.AddWidget(separator, 0, core.Qt__AlignCenter)

	connInfoWidget := widgets.NewQWidget(nil, 0)
	connInfoLayout := widgets.NewQGridLayout(connInfoWidget)
	vbox.AddWidget(connInfoWidget, 0, core.Qt__AlignLeft)

	prefixCommandLabel := widgets.NewQLabel2("Command:", nil, 0)
	connInfoLayout.AddWidget(prefixCommandLabel, 0, 0, core.Qt__AlignLeft)

	rw.labelCommand = widgets.NewQLabel2("UNSET", nil, 0)
	connInfoLayout.AddWidget(rw.labelCommand, 0, 1, core.Qt__AlignLeft)

	prefixDestinationLabel := widgets.NewQLabel2("Destination:", nil, 0)
	connInfoLayout.AddWidget(prefixDestinationLabel, 1, 0, core.Qt__AlignLeft)

	rw.labelDestination = widgets.NewQLabel2("UNSET", nil, 0)
	connInfoLayout.AddWidget(rw.labelDestination, 1, 1, core.Qt__AlignLeft)

	prefixPortLabel := widgets.NewQLabel2("Port:", nil, 0)
	connInfoLayout.AddWidget(prefixPortLabel, 2, 0, core.Qt__AlignLeft)

	rw.labelPort = widgets.NewQLabel2("UNSET", nil, 0)
	connInfoLayout.AddWidget(rw.labelPort, 2, 1, core.Qt__AlignLeft)

	prefixPidLabel := widgets.NewQLabel2("Pid:", nil, 0)
	connInfoLayout.AddWidget(prefixPidLabel, 3, 0, core.Qt__AlignLeft)

	rw.labelPid = widgets.NewQLabel2("UNSET", nil, 0)
	connInfoLayout.AddWidget(rw.labelPid, 3, 1, core.Qt__AlignLeft)

	prefixUserLabel := widgets.NewQLabel2("User:", nil, 0)
	connInfoLayout.AddWidget(prefixUserLabel, 4, 0, core.Qt__AlignLeft)

	rw.labelUser = widgets.NewQLabel2("UNSET", nil, 0)
	connInfoLayout.AddWidget(rw.labelUser, 4, 1, core.Qt__AlignLeft)

	prefixActionLabel := widgets.NewQLabel2("Take this action", nil, 0)
	connInfoLayout.AddWidget(prefixActionLabel, 5, 0, core.Qt__AlignLeft)

	rw.comboScope = widgets.NewQComboBox(nil)
	actionComboItems := []string{"once", "for this session", "forever"}
	rw.comboScope.AddItems(actionComboItems)
	connInfoLayout.AddWidget(rw.comboScope, 5, 1, core.Qt__AlignLeft)

	prefixScopeLabel := widgets.NewQLabel2("Apply rule", nil, 0)
	connInfoLayout.AddWidget(prefixScopeLabel, 6, 0, core.Qt__AlignLeft)

	rw.comboUser = widgets.NewQComboBox(nil)
	scopeComboItems := []string{"for this user", "system wide"}
	rw.comboUser.AddItems(scopeComboItems)
	connInfoLayout.AddWidget(rw.comboUser, 6, 1, core.Qt__AlignLeft)

	prefixDurationLabel := widgets.NewQLabel2("Duration of rule", nil, 0)
	connInfoLayout.AddWidget(prefixDurationLabel, 7, 0, core.Qt__AlignLeft)

	rw.comboDuration = widgets.NewQComboBox(nil)
	durationComboItems := []string{"5 minutes", "1 hour", "8 hours", "1 day", "forever"}
	rw.comboDuration.AddItems(durationComboItems)
	connInfoLayout.AddWidget(rw.comboDuration, 7, 1, core.Qt__AlignLeft)

	buttonHboxWidget := widgets.NewQWidget(nil, 0)
	buttonHbox := widgets.NewQHBoxLayout2(buttonHboxWidget)
	vbox.AddWidget(buttonHboxWidget, 0, core.Qt__AlignLeft)

	rw.buttonWhitelist = widgets.NewQPushButton2("Whitelist app", nil)
	buttonHbox.AddWidget(rw.buttonWhitelist, 0, core.Qt__AlignCenter)

	rw.buttonBlock = widgets.NewQPushButton2("Block app", nil)
	buttonHbox.AddWidget(rw.buttonBlock, 0, core.Qt__AlignCenter)

	rw.buttonAllow = widgets.NewQPushButton2("Allow", nil)
	buttonHbox.AddWidget(rw.buttonAllow, 0, core.Qt__AlignCenter)

	rw.buttonDeny = widgets.NewQPushButton2("Deny", nil)
	buttonHbox.AddWidget(rw.buttonDeny, 0, core.Qt__AlignCenter)

	rw.window.SetCentralWidget(vboxWidget)

	rw.initCallbacks()

	return rw
}
