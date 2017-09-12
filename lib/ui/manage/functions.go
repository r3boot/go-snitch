package manage

import (
	"github.com/therecipe/qt/gui"

	"fmt"
	"github.com/r3boot/go-snitch/lib/ui"
	"os"
)

func (mw *ManageWindow) Show() {
	mw.LoadRules()
	mw.window.Show()
}

func (mw *ManageWindow) Hide() {
	mw.window.Hide()
}

func (mw *ManageWindow) GetRuleMeta(cmd string) RuleMeta {
	meta, ok := mw.ruleset[cmd]
	if !ok {
		return RuleMeta{}
	}
	return meta
}

func (mw *ManageWindow) fetchRules() {
	ruleset, err := mw.ipc.GetDBRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mw.fetchRules: failed to retrieve rules: %v", err)
		return
	}

	fmt.Printf("ruleset: %v", ruleset)

	mw.ruleset = make(map[string]RuleMeta)

	for _, dbrule := range ruleset {
		meta := mw.GetRuleMeta(dbrule.Cmd)

		if dbrule.Dstip == "" {
			meta.IsAppRule = true
			rule := RuleItem{
				Id:        dbrule.Id,
				Scope:     ui.Scope(dbrule.User),
				Duration:  dbrule.Duration,
				Verdict:   ui.NFVerdictToVerdict(dbrule.Verdict),
				Timestamp: dbrule.Timestamp,
				RuleType:  ui.TYPE_DB,
			}
			meta.Rules = append(meta.Rules, rule)
		} else {
			rule := RuleItem{
				Id:          dbrule.Id,
				Destination: dbrule.Dstip,
				Port:        dbrule.Port,
				Proto:       ui.Proto(dbrule.Proto),
				Scope:       ui.Scope(dbrule.User),
				Duration:    dbrule.Duration,
				Verdict:     ui.NFVerdictToVerdict(dbrule.Verdict),
				Timestamp:   dbrule.Timestamp,
				RuleType:    ui.TYPE_DB,
			}
			meta.Rules = append(meta.Rules, rule)
		}
		mw.ruleset[dbrule.Cmd] = meta
	}

}

func (mw *ManageWindow) LoadRules() {
	mw.fetchRules()

	for cmd, meta := range mw.ruleset {
		if meta.IsAppRule {
			row := []*gui.QStandardItem{
				gui.NewQStandardItem2(cmd),
				gui.NewQStandardItem(),
				gui.NewQStandardItem(),
				gui.NewQStandardItem(),
				gui.NewQStandardItem2(meta.Rules[0].Scope.String()),
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
					gui.NewQStandardItem2(rule.Scope.String()),
					gui.NewQStandardItem2(rule.Duration.String()),
					gui.NewQStandardItem2(rule.Verdict.String()),
				}
				cmdRow[0].AppendRow(row)
			}
		}
	}
}
