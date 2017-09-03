package manage

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui"
)

func (mw *ManageWindow) Show() {
	mw.LoadRules()
	mw.window.ShowAll()
}

func (mw *ManageWindow) Hide() bool {
	mw.window.Hide()
	return true
}

func (mw *ManageWindow) GetRuleDetail() (*gtk.TreePath, *rules.RuleDetail) {
	var path *gtk.TreePath
	var column *gtk.TreeViewColumn
	var id, connId string
	var id_i, connId_i int

	mw.ruleTreeview.GetCursor(&path, &column)
	tokens := strings.Split(path.String(), ":")
	if len(tokens) > 1 {
		id = tokens[0]
		id_i, _ = strconv.Atoi(id)
		connId = tokens[1]
		connId_i, _ = strconv.Atoi(connId)
	} else {
		id = tokens[0]
		id_i, _ = strconv.Atoi(id)
	}

	if len(mw.ruleset[id_i].ConnRules) > 0 && connId == "" {
		return path, nil
	}

	detail := &rules.RuleDetail{
		RowPath: gtk.NewTreePathFromString(id),
	}

	if connId == "" {
		detail.Id = mw.ruleset[id_i].Id
		detail.Command = mw.ruleset[id_i].Command
		detail.User = mw.ruleset[id_i].User
		detail.Duration = mw.ruleset[id_i].Duration
		detail.Action = mw.ruleset[id_i].Action
		detail.Verdict = mw.ruleset[id_i].Verdict
		detail.RuleType = mw.ruleset[id_i].RuleType
	} else {
		detail.Id = mw.ruleset[id_i].ConnRules[connId_i].Id
		detail.Command = mw.ruleset[id_i].Command
		detail.Dstip = mw.ruleset[id_i].ConnRules[connId_i].Dstip
		detail.Port = mw.ruleset[id_i].ConnRules[connId_i].Port
		detail.Proto = mw.ruleset[id_i].ConnRules[connId_i].Proto
		detail.User = mw.ruleset[id_i].ConnRules[connId_i].User
		detail.Duration = mw.ruleset[id_i].ConnRules[connId_i].Duration
		detail.Action = mw.ruleset[id_i].ConnRules[connId_i].Action
		detail.Verdict = mw.ruleset[id_i].ConnRules[connId_i].Verdict
		detail.RuleType = mw.ruleset[id_i].RuleType
	}

	return path, detail
}

func (mw *ManageWindow) fetchRules() map[int]*ui.Rule {
	dbRules, err := mw.dbus.GetRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dbus: Failed to retrieve rules: %v\n", err)
	}

	ruleset := make(map[int]*ui.Rule)

	for _, item := range dbRules {
		ruleId := ui.GetRuleId(item.Cmd, ruleset)
		if ruleId == -1 {
			newRuleId := len(ruleset)
			ruleset[newRuleId] = &ui.Rule{
				Command:   item.Cmd,
				RuleType:  ui.RULE_DB,
				ConnRules: make(map[int]*ui.ConnRule),
			}
			ruleId = newRuleId
		}

		if item.Dstip != "" {
			cmdRuleId := ui.GetRuleId(item.Cmd, ruleset)
			if cmdRuleId == -1 {
				ruleset[ruleId] = &ui.Rule{
					RuleType:  ui.RULE_DB,
					ConnRules: make(map[int]*ui.ConnRule),
				}
				cmdRuleId = len(ruleset[cmdRuleId].ConnRules)
			}

			connRuleId := len(ruleset[cmdRuleId].ConnRules)
			if _, ok := ruleset[cmdRuleId].ConnRules[connRuleId]; !ok {
				ruleset[cmdRuleId].ConnRules[connRuleId] = &ui.ConnRule{}
			}

			ruleset[cmdRuleId].ConnRules[connRuleId].Id = item.Id
			ruleset[cmdRuleId].ConnRules[connRuleId].Dstip = item.Dstip
			ruleset[cmdRuleId].ConnRules[connRuleId].Port = item.Port
			ruleset[cmdRuleId].ConnRules[connRuleId].Proto = item.Proto
			ruleset[cmdRuleId].ConnRules[connRuleId].User = item.User
			ruleset[cmdRuleId].ConnRules[connRuleId].Action = ui.VerdictNameMap[item.Verdict]
			ruleset[cmdRuleId].ConnRules[connRuleId].Timestamp = item.Timestamp
			ruleset[cmdRuleId].ConnRules[connRuleId].Duration = item.Duration
		} else {
			ruleset[ruleId].Id = item.Id
			ruleset[ruleId].RuleType = ui.RULE_DB
			ruleset[ruleId].User = item.User
			ruleset[ruleId].Action = ui.VerdictNameMap[item.Verdict]
			ruleset[ruleId].Timestamp = item.Timestamp
			ruleset[ruleId].Duration = item.Duration
		}
	}

	sessionRules, err := mw.cache.GetAllRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mw.fetchRules: Failed to load session rules: %v\n", err)
	}

	for _, item := range sessionRules {
		ruleId := ui.GetRuleId(item.Cmd, ruleset)
		if ruleId == -1 {
			newRuleId := len(ruleset)
			ruleset[newRuleId] = &ui.Rule{
				Command:   item.Cmd,
				RuleType:  ui.RULE_SESSION,
				ConnRules: make(map[int]*ui.ConnRule),
			}
			ruleId = newRuleId
		}

		if item.Dstip != "" {
			cmdRuleId := ui.GetRuleId(item.Cmd, ruleset)
			if cmdRuleId == -1 {
				ruleset[ruleId] = &ui.Rule{
					RuleType:  ui.RULE_SESSION,
					ConnRules: make(map[int]*ui.ConnRule),
				}
				cmdRuleId = len(ruleset[cmdRuleId].ConnRules)
			}

			connRuleId := len(ruleset[cmdRuleId].ConnRules)
			if _, ok := ruleset[cmdRuleId].ConnRules[connRuleId]; !ok {
				ruleset[cmdRuleId].ConnRules[connRuleId] = &ui.ConnRule{}
			}

			ruleset[cmdRuleId].ConnRules[connRuleId].Id = item.Id
			ruleset[cmdRuleId].ConnRules[connRuleId].Dstip = item.Dstip
			ruleset[cmdRuleId].ConnRules[connRuleId].Port = item.Port
			ruleset[cmdRuleId].ConnRules[connRuleId].Proto = item.Proto
			ruleset[cmdRuleId].ConnRules[connRuleId].User = item.User
			ruleset[cmdRuleId].ConnRules[connRuleId].Action = ui.ActionNameMap[item.Verdict]
			ruleset[cmdRuleId].ConnRules[connRuleId].Verdict = item.Verdict
			ruleset[cmdRuleId].ConnRules[connRuleId].Timestamp = item.Timestamp
			ruleset[cmdRuleId].ConnRules[connRuleId].Duration = item.Duration
		} else {
			ruleset[ruleId].Id = item.Id
			ruleset[ruleId].RuleType = ui.RULE_SESSION
			ruleset[ruleId].User = item.User
			ruleset[ruleId].Action = ui.ActionNameMap[item.Verdict]
			ruleset[ruleId].Verdict = item.Verdict
			ruleset[ruleId].Timestamp = item.Timestamp
			ruleset[ruleId].Duration = item.Duration
		}
	}
	return ruleset
}

func (mw *ManageWindow) LoadRules() {
	mw.ruleset = mw.fetchRules()

	mw.ClearTreeStore()

	for i := 0; i < len(mw.ruleset); i++ {
		rule := mw.ruleset[i]
		var iter gtk.TreeIter
		mw.ruleStore.Append(&iter, nil)
		mw.ruleStore.SetValue(&iter, COLUMN_COMMAND, rule.Command)
		if len(rule.ConnRules) > 0 {
			for j := 0; j < len(rule.ConnRules); j++ {
				connRule := rule.ConnRules[j]
				var connIter gtk.TreeIter
				mw.ruleStore.Append(&connIter, &iter)
				mw.ruleStore.SetValue(&connIter, COLUMN_DESTINATION, connRule.Dstip)
				mw.ruleStore.SetValue(&connIter, COLUMN_PORT, connRule.Port)
				mw.ruleStore.SetValue(&connIter, COLUMN_PROTO, ui.ProtoNameMap[connRule.Proto])
				mw.ruleStore.SetValue(&connIter, COLUMN_USER, connRule.User)
				mw.ruleStore.SetValue(&connIter, COLUMN_DURATION, "0")
				mw.ruleStore.SetValue(&connIter, COLUMN_ACTION, connRule.Action)
			}
		} else {
			mw.ruleStore.SetValue(&iter, COLUMN_USER, rule.User)
			mw.ruleStore.SetValue(&iter, COLUMN_DURATION, "0")
			mw.ruleStore.SetValue(&iter, COLUMN_ACTION, rule.Action)
		}
	}
}
