package manage

import (
	"fmt"
	"os"

	"github.com/therecipe/qt/gui"

	"github.com/r3boot/go-snitch/lib/datastructures"
)

func (mw *ManageWindow) Show() {
	mw.LoadRules()
	mw.window.Show()
}

func (mw *ManageWindow) Hide() {
	mw.window.Close()
}

func (mw *ManageWindow) GetRuleMeta(cmd string) RuleMeta {
	meta, ok := mw.ruleset[cmd]
	if !ok {
		return RuleMeta{}
	}
	return meta
}

func (mw *ManageWindow) fetchRules(ruleType datastructures.RuleType) {
	var ruleset datastructures.Ruleset
	var err error

	switch ruleType {
	case datastructures.TYPE_DB:
		ruleset, err = mw.ipc.GetDBRules()
	case datastructures.TYPE_SESSION:
		ruleset, err = mw.ipc.GetClientRules()
	default:
		fmt.Fprintf(os.Stderr, "ManageWindow.fetchRules: no such ruletype: %d", ruleType)
		return
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "ManageWindow.fetchRules: failed to retrieve rules: %v", err)
		return
	}

	for _, rule := range ruleset {
		meta := mw.GetRuleMeta(rule.Command)
		if rule.Destination == "" {
			meta.IsAppRule = true
			rule := RuleItem{
				Id:        rule.Id,
				User:      rule.User,
				Duration:  rule.Duration,
				Verdict:   rule.Verdict,
				Timestamp: rule.Timestamp,
				RuleType:  ruleType,
			}
			meta.Rules = append(meta.Rules, rule)
		} else {
			rule := RuleItem{
				Id:          rule.Id,
				Destination: rule.Destination,
				Port:        rule.Port,
				Proto:       rule.Proto,
				User:        rule.User,
				Duration:    rule.Duration,
				Verdict:     rule.Verdict,
				Timestamp:   rule.Timestamp,
				RuleType:    ruleType,
			}
			meta.Rules = append(meta.Rules, rule)
		}
		mw.ruleset[rule.Command] = meta
	}

}

func (mw *ManageWindow) fetchAllRules() {
	mw.ruleset = make(map[string]RuleMeta)
	mw.fetchRules(datastructures.TYPE_DB)
	mw.fetchRules(datastructures.TYPE_SESSION)
}

func (mw *ManageWindow) LoadRules() {
	mw.fetchAllRules()

	for cmd, meta := range mw.ruleset {
		if meta.IsAppRule {
			row := []*gui.QStandardItem{
				gui.NewQStandardItem2(cmd),
				gui.NewQStandardItem(),
				gui.NewQStandardItem(),
				gui.NewQStandardItem(),
				gui.NewQStandardItem2(meta.Rules[0].User),
				gui.NewQStandardItem2(meta.Rules[0].Duration.String()),
				gui.NewQStandardItem2(meta.Rules[0].Verdict.String()),
			}
			mw.treeviewRoot.AppendRow(row)
		} else {
			cmdRow := []*gui.QStandardItem{
				gui.NewQStandardItem2(cmd),
			}
			mw.treeviewRoot.AppendRow(cmdRow)

			for _, rule := range meta.Rules {
				row := []*gui.QStandardItem{
					gui.NewQStandardItem(),
					gui.NewQStandardItem2(rule.Destination),
					gui.NewQStandardItem2(rule.Port),
					gui.NewQStandardItem2(rule.Proto.String()),
					gui.NewQStandardItem2(rule.User),
					gui.NewQStandardItem2(rule.Duration.String()),
					gui.NewQStandardItem2(rule.Verdict.String()),
				}
				cmdRow[0].AppendRow(row)
			}
		}
	}
}
