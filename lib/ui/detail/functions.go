package detail

import (
	"fmt"
	"os"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/snitch"
	"github.com/r3boot/go-snitch/lib/ui"
)

func (dd *ManageDetailDialog) Show() {
	dd.window.ShowAll()
}

func (dd *ManageDetailDialog) Hide() {
	dd.window.Hide()
}

func (md *ManageDetailDialog) UpdateRule() {
	md.Hide()

	md.rule.Dstip = md.destinationEntry.GetText()
	md.rule.Port = md.portEntry.GetText()
	md.rule.Action = md.actionCombo.GetActiveText()
	if md.systemRadio.GetActive() {
		md.rule.User = rules.USER_ANY
	} else {
		md.rule.User = md.userEntry.GetText()
	}

	fmt.Printf("md.rule: %v\n", md.rule)

	switch md.rule.RuleType {
	case ui.RULE_DB:
		{
			if err := md.dbus.UpdateRule(md.rule); err != nil {
				fmt.Fprintf(os.Stderr, "md.UpdateRule: %v\n", err)
				return
			}
		}
	case ui.RULE_SESSION:
		{
			switch md.rule.Action {
			case "accept":
				{
					if md.rule.User == rules.USER_ANY {
						md.rule.Verdict = snitch.ACCEPT_CONN_ONCE_SYSTEM
					} else {
						md.rule.Verdict = snitch.ACCEPT_CONN_ONCE_USER
					}
				}
			case "reject":
				{
					if md.rule.User == rules.USER_ANY {
						md.rule.Verdict = snitch.DROP_CONN_ONCE_SYSTEM
					} else {
						md.rule.Verdict = snitch.DROP_CONN_ONCE_USER
					}
				}
			}
			md.cache.UpdateRule(md.rule)
		}
	}
}

func (md *ManageDetailDialog) DeleteRule() {
	md.Hide()

	switch md.rule.RuleType {
	case ui.RULE_DB:
		{
			if err := md.dbus.DeleteRule(md.rule.Id); err != nil {
				fmt.Fprintf(os.Stderr, "md.DeleteRule: %v\n", err)
				return
			}
		}
	case ui.RULE_SESSION:
		{
			md.cache.DeleteRule(md.rule.Id)
		}
	}
}

func (dd *ManageDetailDialog) SetSessionCache(cache *rules.SessionCache) {
	dd.cache = cache
}

func (dd *ManageDetailDialog) SetValues(r rules.RuleDetail) {
	dd.rule = r

	if r.Dstip == "" {
		dd.window.SetTitle("Edit application rule")
		dd.destinationEntry.SetSensitive(false)
		dd.portEntry.SetSensitive(false)
	} else {
		dd.window.SetTitle("Edit connection rule")
		dd.destinationEntry.SetSensitive(true)
		dd.portEntry.SetSensitive(true)
	}
	dd.commandLabel.SetText(r.Command)

	if r.User == rules.USER_ANY {
		dd.systemRadio.Activate()
		dd.userEntry.SetText("Enter manually")
		dd.userEntry.SetSensitive(false)
	} else {
		dd.userRadio.Activate()
		dd.userEntry.SetText(r.User)
		dd.userEntry.SetSensitive(true)
	}

	if r.Action == "accept" {
		dd.actionCombo.SetActive(0)
	} else {
		dd.actionCombo.SetActive(1)
	}

	dd.durationCombo.SetActive(ui.DurationToIntMap[ui.DURATION_FOREVER])

	dd.destinationEntry.SetText(r.Dstip)
	dd.portEntry.SetText(r.Port)
}
