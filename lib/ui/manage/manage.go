package manage

import (
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"

	"github.com/r3boot/go-snitch/lib/ipc/manageipc"
	"github.com/r3boot/go-snitch/lib/logger"
)

func NewManageWindow(l *logger.Logger, ipc *manageipc.ManageIPCService) *ManageWindow {
	log = l

	mw := &ManageWindow{
		ipc: ipc,
	}

	mw.window = widgets.NewQMainWindow(nil, 0)
	mw.window.SetWindowTitle("Manage ruleset")
	mw.window.SetMinimumHeight(600)
	mw.window.SetMinimumWidth(850)
	mw.window.SetWindowModality(core.Qt__ApplicationModal)

	fileMenu := mw.window.MenuBar().AddMenu2("&File")
	mw.fileMenuEnable = fileMenu.AddAction("&Enable")
	mw.fileMenuDisable = fileMenu.AddAction("&Disable")
	fileMenu.AddSeparator()
	mw.fileMenuClose = fileMenu.AddAction("&Close")

	ruleMenu := mw.window.MenuBar().AddMenu2("&Rule")
	mw.ruleMenuAdd = ruleMenu.AddAction("&Add")
	mw.ruleMenuEdit = ruleMenu.AddAction("&Edit")
	mw.ruleMenuDelete = ruleMenu.AddAction("&Delete")

	helpMenu := mw.window.MenuBar().AddMenu2("&Help")
	mw.helpMenuHelp = helpMenu.AddAction("&Get help")
	mw.helpMenuAbout = helpMenu.AddAction("&About")

	tabWidget := widgets.NewQTabWidget(nil)

	inboundScrollArea := widgets.NewQScrollArea(nil)
	inboundScrollArea.SetWidgetResizable(true)

	mw.treeviewRule = widgets.NewQTreeView(nil)
	mw.treeviewRule.SetEditTriggers(widgets.QAbstractItemView__NoEditTriggers)
	mw.treeviewRule.SetAlternatingRowColors(true)
	treeModel := gui.NewQStandardItemModel(nil)
	mw.treeviewRoot = treeModel.InvisibleRootItem()

	headerLabels := []string{
		"Command",
		"Destination",
		"Port",
		"Proto",
		"User",
		"Duration",
		"Verdict",
	}

	treeModel.SetHorizontalHeaderLabels(headerLabels)
	mw.treeviewRule.SetModel(treeModel)

	mw.treeviewRule.SetColumnWidth(COLUMN_COMMAND, 270)
	mw.treeviewRule.SetColumnWidth(COLUMN_DESTINATION, 280)
	mw.treeviewRule.SetColumnWidth(COLUMN_PORT, 50)
	mw.treeviewRule.SetColumnWidth(COLUMN_PROTO, 50)
	mw.treeviewRule.SetColumnWidth(COLUMN_USER, 70)
	mw.treeviewRule.SetColumnWidth(COLUMN_DURATION, 70)
	mw.treeviewRule.SetColumnWidth(COLUMN_ACTION, 50)

	inboundScrollArea.SetWidget(mw.treeviewRule)

	tabWidget.AddTab(inboundScrollArea, "Outbound")

	mw.window.SetCentralWidget(tabWidget)

	mw.initCallbacks()

	return mw
}
