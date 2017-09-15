package manage

import (
	"fmt"
	"os"

	"github.com/therecipe/qt/gui"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui"
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

func (mw *ManageWindow) fetchRules(ruleType ui.RuleType) {
	var ruleset []rules.RuleItem
	var err error

	switch ruleType {
	case ui.TYPE_DB:
		ruleset, err = mw.ipc.GetDBRules()
	case ui.TYPE_SESSION:
		ruleset, err = mw.ipc.GetClientRules()
	default:
		fmt.Fprintf(os.Stderr, "mw.fetchRules: no such ruletype: %d", ruleType)
		return
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "mw.fetchRules: failed to retrieve rules: %v", err)
		return
	}

	for _, rule := range ruleset {
		meta := mw.GetRuleMeta(rule.Cmd)
		verdict := ui.VERDICT_REJECT
		switch ruleType {
		case ui.TYPE_DB:
			verdict = ui.NFVerdictToVerdict(rule.Verdict)
		case ui.TYPE_SESSION:
			verdict = ui.SnitchVerdictToVerdict(rule.Verdict)
		}
		if rule.Dstip == "" {
			meta.IsAppRule = true
			rule := RuleItem{
				Id:        rule.Id,
				User:      rule.User,
				Duration:  rule.Duration,
				Verdict:   verdict,
				Timestamp: rule.Timestamp,
				RuleType:  ruleType,
			}
			meta.Rules = append(meta.Rules, rule)
		} else {
			rule := RuleItem{
				Id:          rule.Id,
				Destination: rule.Dstip,
				Port:        rule.Port,
				Proto:       ui.ProtoIntMap[rule.Proto],
				User:        rule.User,
				Duration:    rule.Duration,
				Verdict:     verdict,
				Timestamp:   rule.Timestamp,
				RuleType:    ruleType,
			}
			meta.Rules = append(meta.Rules, rule)
		}
		mw.ruleset[rule.Cmd] = meta
	}

}

func (mw *ManageWindow) fetchAllRules() {
	mw.ruleset = make(map[string]RuleMeta)
	mw.fetchRules(ui.TYPE_DB)
	mw.fetchRules(ui.TYPE_SESSION)
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
