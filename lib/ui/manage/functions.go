package manage

import (
	"fmt"

	"github.com/therecipe/qt/gui"

	"github.com/r3boot/go-snitch/lib/datastructures"
)

func (mw *ManageWindow) Show() {
	if err := mw.LoadRules(); err != nil {
		log.Warningf("ManageWindow.Show: %v", err)
	}
	mw.window.Show()
}

func (mw *ManageWindow) Hide() {
	mw.window.Close()
}

func (mw *ManageWindow) GetRuleMeta(cmd string) datastructures.UiRulesItem {
	cmdRules, ok := mw.ruleset[cmd]
	if !ok {
		return datastructures.UiRulesItem{}
	}
	return cmdRules
}

func (mw *ManageWindow) fetchRules(ruleSource datastructures.RuleSource) error {
	var ruleset datastructures.Ruleset
	var err error

	switch ruleSource {
	case datastructures.SOURCE_DB:
		ruleset, err = mw.ipc.GetDBRules()
	case datastructures.SOURCE_SESSION:
		ruleset, err = mw.ipc.GetClientRules()
	default:
		return fmt.Errorf("ManageWindow.fetchRules: no such ruletype: %d", ruleSource)
	}

	log.Debugf("Ruleset: %s", ruleset)

	if err != nil {
		return fmt.Errorf("ManageWindow.fetchRules: failed to retrieve rules: %v", err)
	}

	for _, rule := range ruleset {
		cmdRules := mw.GetRuleMeta(rule.Command)

		if rule.Destination == "" {
			cmdRules.RuleType = datastructures.TYPE_APP
		} else {
			cmdRules.RuleType = datastructures.TYPE_CONN
		}

		detailRule := datastructures.RuleDetail{RuleItem: rule}
		detailRule.RuleSource = ruleSource
		cmdRules.Rules = append(cmdRules.Rules, detailRule)

		mw.ruleset[rule.Command] = cmdRules
	}

	return nil
}

func (mw *ManageWindow) fetchAllRules() error {
	mw.ruleset = make(datastructures.UiRuleset)

	err := mw.fetchRules(datastructures.SOURCE_DB)
	if err != nil {
		return err
	}

	err = mw.fetchRules(datastructures.SOURCE_SESSION)
	if err != nil {
		return err
	}

	return nil
}

func (mw *ManageWindow) LoadRules() error {
	if err := mw.fetchAllRules(); err != nil {
		return fmt.Errorf("ManageWindow.LoadRules: %v", err)
	}

	for cmd, rule := range mw.ruleset {
		switch rule.RuleType {
		case datastructures.TYPE_APP:
			{
				row := []*gui.QStandardItem{
					gui.NewQStandardItem2(cmd),
					gui.NewQStandardItem(),
					gui.NewQStandardItem(),
					gui.NewQStandardItem(),
					gui.NewQStandardItem2(rule.Rules[0].User),
					gui.NewQStandardItem2(rule.Rules[0].Duration.String()),
					gui.NewQStandardItem2(rule.Rules[0].Verdict.String()),
				}
				mw.treeviewRoot.AppendRow(row)
			}
		case datastructures.TYPE_CONN:
			{
				cmdRow := []*gui.QStandardItem{
					gui.NewQStandardItem2(cmd),
				}
				mw.treeviewRoot.AppendRow(cmdRow)

				for _, cmdRule := range rule.Rules {
					row := []*gui.QStandardItem{
						gui.NewQStandardItem(),
						gui.NewQStandardItem2(cmdRule.Destination),
						gui.NewQStandardItem2(cmdRule.Port),
						gui.NewQStandardItem2(cmdRule.Proto.String()),
						gui.NewQStandardItem2(cmdRule.User),
						gui.NewQStandardItem2(cmdRule.Duration.String()),
						gui.NewQStandardItem2(cmdRule.Verdict.String()),
					}
					cmdRow[0].AppendRow(row)
				}
			}
		}
	}

	return nil
}
