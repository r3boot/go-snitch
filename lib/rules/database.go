package rules

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/datastructures"
	"github.com/r3boot/go-snitch/lib/logger"
)

func NewRuleDB(l *logger.Logger, dbpath string) (*RuleDB, error) {
	if l != nil {
		log = l
	}

	db := &RuleDB{
		path: dbpath,
	}

	if err := db.Connect(); err != nil {
		return nil, fmt.Errorf("NewRuleDB: failed to connect to database: %v", err)
	}

	return db, nil
}

func (db *RuleDB) Connect() error {
	var (
		err error
	)

	db.mutex.Lock()
	defer db.mutex.Unlock()
	db.conn, err = sql.Open("sqlite3", db.path)
	if err != nil {
		return fmt.Errorf("rules: Failed to open database: %v", err)
	}

	// Create ruleset table
	statement, err := db.conn.Prepare(RULESET_TABLE_SQL)
	if err != nil {
		fmt.Fprintf(os.Stderr, RULESET_TABLE_SQL)
		return fmt.Errorf("rules: Failed to prepare statement: %v", err)
	}

	_, err = statement.Exec()
	if err != nil {
		return fmt.Errorf("rules: Failed to execute statement: %v", err)
	}

	return nil
}

func (db *RuleDB) GetVerdict(r datastructures.ConnRequest) (netfilter.Verdict, error) {
	verdict := netfilter.NF_UNDEF

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	response, err := db.conn.Query(GET_RULE_BY_CMD_SQL, r.Command)
	if err != nil {
		return verdict, fmt.Errorf("rules: Failed to query app table: %v", err)
	}
	defer response.Close()

	isAppRule := true
	foundRules := datastructures.Ruleset{}
	matchingRule := datastructures.RuleItem{}

	// Get all rules in database
	for response.Next() {
		item := datastructures.RuleItem{}
		err = response.Scan(&item.Id, &item.Command, &item.Verdict, &item.Destination,
			&item.Port, &item.Proto, &item.User, &item.Timestamp, &item.Duration)
		if err != nil {
			return netfilter.NF_UNDEF, fmt.Errorf("rules: Failed to get verdict from app table: %v", err)
		}
		if item.Destination != "" {
			isAppRule = false
		}
		foundRules = append(foundRules, item)
	}

	// Return if no rules are found
	if len(foundRules) == 0 {
		return netfilter.NF_UNDEF, nil
	}

	// Check if we have a rule which matches on ip+port+proto
	if !isAppRule {
		for _, rule := range foundRules {
			if r.Destination == rule.Destination && r.Port == rule.Port && r.Proto == rule.Proto {
				matchingRule = rule
				break
			}
		}
		if matchingRule.Command == "" {
			return netfilter.NF_UNDEF, nil
		}
	} else {
		matchingRule = foundRules[0]
	}

	// Check if the rule is expired
	if matchingRule.Duration != 0 {
		if time.Since(matchingRule.Timestamp) > matchingRule.Duration {
			db.DeleteRule(matchingRule.Id)
			return netfilter.NF_UNDEF, nil
		}
	}

	// Check if the rule matches the requested user
	if matchingRule.User == USER_ANY || matchingRule.User == r.User {
		return netfilter.Verdict(matchingRule.Verdict), nil
	}

	return netfilter.NF_UNDEF, nil
}

func (db *RuleDB) AddAppRule(r datastructures.ConnRequest, action datastructures.ResponseType) error {
	db.mutex.Lock()

	verdict := netfilter.NF_UNDEF
	switch action {
	case datastructures.DROP_APP_ALWAYS_USER, datastructures.DROP_APP_ALWAYS_SYSTEM:
		{
			verdict = netfilter.NF_DROP
		}
	case datastructures.ACCEPT_APP_ALWAYS_USER, datastructures.ACCEPT_APP_ALWAYS_SYSTEM:
		{
			verdict = netfilter.NF_ACCEPT
		}
	}

	statement, err := db.conn.Prepare(ADD_APP_DURATION_RULE_SQL)
	if err != nil {
		db.mutex.Unlock()
		return fmt.Errorf("rules: Failed to prepare statement: %v", err)
	}
	_, err = statement.Exec(r.Command, verdict, r.User, time.Now(), r.Duration)
	if err != nil {
		db.mutex.Unlock()
		return fmt.Errorf("rules: Failed to execute statement: %v", err)
	}
	db.mutex.Unlock()

	return nil
}

func (db *RuleDB) AddConnRule(r datastructures.ConnRequest, action datastructures.ResponseType) error {
	db.mutex.Lock()

	verdict := netfilter.NF_UNDEF
	switch action {
	case datastructures.DROP_CONN_ALWAYS_USER, datastructures.DROP_CONN_ALWAYS_SYSTEM:
		{
			verdict = netfilter.NF_DROP
		}
	case datastructures.ACCEPT_CONN_ALWAYS_USER, datastructures.ACCEPT_CONN_ALWAYS_SYSTEM:
		{
			verdict = netfilter.NF_ACCEPT
		}
	}

	statement, err := db.conn.Prepare(ADD_CONN_DURATION_RULE_SQL)
	if err != nil {
		db.mutex.Unlock()
		return fmt.Errorf("rules: Failed to prepare statement: %v", err)
	}
	_, err = statement.Exec(r.Command, verdict, r.Destination, r.Port, r.Proto, r.User, time.Now(), r.Duration)
	if err != nil {
		db.mutex.Unlock()
		return fmt.Errorf("rules: Failed to execute statement: %v", err)
	}
	db.mutex.Unlock()

	return nil
}

func (db *RuleDB) AddRule(r datastructures.ConnRequest, action datastructures.ResponseType) error {
	r.Duration = time.Duration(0)

	switch action {
	case datastructures.DROP_APP_ALWAYS_USER, datastructures.DROP_APP_ALWAYS_SYSTEM, datastructures.ACCEPT_APP_ALWAYS_USER, datastructures.ACCEPT_APP_ALWAYS_SYSTEM:
		{
			if err := db.DeleteConnRulesFor(r.Command); err != nil {
				return fmt.Errorf("Failed to delete conn rules: %v\n", err)
			}
			return db.AddAppRule(r, action)
		}
	case datastructures.DROP_CONN_ALWAYS_USER, datastructures.DROP_CONN_ALWAYS_SYSTEM, datastructures.ACCEPT_CONN_ALWAYS_USER, datastructures.ACCEPT_CONN_ALWAYS_SYSTEM:
		{
			// Is conn rule
			return db.AddConnRule(r, action)
		}
	}

	return nil
}

func (db *RuleDB) DeleteConnRulesFor(cmd string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	statement, err := db.conn.Prepare(DELETE_CONN_RULE_BY_CMD_SQL)
	if err != nil {
		return fmt.Errorf("rules: Failed to prepare statement: %v\n", err)
	}

	_, err = statement.Exec(cmd)
	if err != nil {
		return fmt.Errorf("rules: Failed to execute statement: %v\n", err)
	}

	return nil
}

func (db *RuleDB) DeleteRule(id int) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	statement, err := db.conn.Prepare(DELETE_RULE_BY_ID_SQL)
	if err != nil {
		return fmt.Errorf("rules: Failed to prepare statement: %v\n", err)
	}

	_, err = statement.Exec(id)
	if err != nil {
		return fmt.Errorf("rules: Failed to execute statement: %v\n", err)
	}

	return nil
}

func (db *RuleDB) UpdateRule(newRule datastructures.RuleDetail) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	statement, err := db.conn.Prepare(UPDATE_RULE_SQL)
	if err != nil {
		return fmt.Errorf("rules: Failed to prepare statement: %v\n", err)
	}

	verdict := netfilter.NF_UNDEF
	switch newRule.Verdict {
	case datastructures.VERDICT_ACCEPT:
		{
			verdict = netfilter.NF_ACCEPT
		}
	case datastructures.VERDICT_REJECT:
		{
			verdict = netfilter.NF_DROP
		}
	}

	_, err = statement.Exec(newRule.Destination, newRule.Port, newRule.Proto, newRule.User, verdict, newRule.Duration, newRule.Id)
	if err != nil {
		return fmt.Errorf("rules: Failed to execute statement: %v\n", err)
	}

	return nil
}

func (db *RuleDB) GetAllRules() (datastructures.Ruleset, error) {
	ruleset := datastructures.Ruleset{}

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	response, err := db.conn.Query(GET_ALL_RULES_SQL)
	if err != nil {
		return nil, err
	}
	defer response.Close()

	for response.Next() {
		rule := datastructures.RuleItem{}
		var dstip sql.NullString
		var port sql.NullString
		var proto sql.NullInt64

		err = response.Scan(&rule.Id, &rule.Command, &rule.Verdict, &dstip,
			&port, &proto, &rule.User, &rule.Timestamp, &rule.Duration)
		if err != nil {
			log.Infof("db.GetAllRules: Failed to parse entry: %v\n", err)
			continue
		}
		rule.Destination = dstip.String
		rule.Port = port.String
		rule.Proto = datastructures.Proto(proto.Int64)

		ruleset = append(ruleset, rule)
	}

	return ruleset, nil
}
