package detail

import (
	"fmt"
	"os"

	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/snitch"
	"github.com/r3boot/go-snitch/lib/ui"
)

func (dw *DetailWindow) initCallbacks() {
        dw.buttonSave.ConnectClicked(dw.OnButtonSaveClicked)
        dw.buttonDelete.ConnectClicked(dw.OnButtonDeleteClicked)
        dw.labelSystem.ConnectMousePressEvent(dw.OnLabelSystemFocusInEvent)
        dw.radioUser.ConnectClicked(dw.OnRadioUserClicked)
        dw.entryUser.ConnectMousePressEvent(dw.OnEntryUserMousePressEvent)
}

func (dd *ManageDetailDialog) OnClose() bool {
	dd.Hide()
	return true
}

func (dd *ManageDetailDialog) OnUpdateButtonClicked() {

	dd.Hide()

	dd.rule.Dstip = dd.destinationEntry.GetText()
	dd.rule.Port = dd.portEntry.GetText()
	dd.rule.Action = dd.actionCombo.GetActiveText()

	if dd.systemRadio.GetActive() {
		dd.rule.User = rules.USER_ANY
	} else {
		dd.rule.User = dd.userEntry.GetText()
	}

	fmt.Printf("dd.rule: %v\n", dd.rule)

	switch dd.rule.RuleType {
	case ui.RULE_DB:
		{
			if err := dd.dbus.UpdateRule(dd.rule); err != nil {
				fmt.Fprintf(os.Stderr, "dd.UpdateRule: %v\n", err)
				return
			}
		}
	case ui.RULE_SESSION:
		{
			switch dd.rule.Action {
			case "accept":
				{
					if dd.rule.User == rules.USER_ANY {
						dd.rule.Verdict = snitch.ACCEPT_CONN_ONCE_SYSTEM
					} else {
						dd.rule.Verdict = snitch.ACCEPT_CONN_ONCE_USER
					}
				}
			case "reject":
				{
					if dd.rule.User == rules.USER_ANY {
						dd.rule.Verdict = snitch.DROP_CONN_ONCE_SYSTEM
					} else {
						dd.rule.Verdict = snitch.DROP_CONN_ONCE_USER
					}
				}
			}
			dd.cache.UpdateRule(dd.rule)
		}
	}
}

func (dd *ManageDetailDialog) OnDeleteButtonClicked() {
	dd.Hide()

	switch dd.rule.RuleType {
	case ui.RULE_DB:
		{
			if err := dd.dbus.DeleteRule(dd.rule.Id); err != nil {
				fmt.Fprintf(os.Stderr, "dd.DeleteRule: %v\n", err)
				return
			}
		}
	case ui.RULE_SESSION:
		{
			dd.cache.DeleteRule(dd.rule.Id)
		}
	}
}

func (dd *ManageDetailDialog) OnEntryButtonPressEvent() {
	dd.userRadio.Activate()
}
