package rules

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/snitch"
)

func NewRuleDB(dbpath string) *RuleDB {
	db := &RuleDB{
		path: dbpath,
	}

	if err := db.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}

	return db
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

	// Create connection table
	statement, err := db.conn.Prepare(CONN_TABLE_SQL)
	if err != nil {
		return fmt.Errorf("rules: Failed to prepare statement: %v", err)
	}

	_, err = statement.Exec()
	if err != nil {
		return fmt.Errorf("rules: Failed to execute statement: %v", err)
	}

	// Create application table
	statement, err = db.conn.Prepare(APP_TABLE_SQL)
	if err != nil {
		return fmt.Errorf("rules: Failed to prepare statement: %v", err)
	}

	_, err = statement.Exec()
	if err != nil {
		return fmt.Errorf("rules: Failed to execute statement: %v", err)
	}

	return nil
}

func (db *RuleDB) GetAppRule(r snitch.ConnRequest) (netfilter.Verdict, error) {
	verdict := netfilter.NF_UNDEF

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	response, err := db.conn.Query(GET_APP_SQL, r.Command)
	if err != nil {
		return verdict, fmt.Errorf("rules: Failed to query app table: %v", err)
	}
	defer response.Close()

	for response.Next() {
		err = response.Scan(&verdict)
		if err != nil {
			return netfilter.NF_UNDEF, fmt.Errorf("rules: Failed to get verdict from app table: %v", err)
		}
		break
	}

	return verdict, nil
}

func (db *RuleDB) AddAppRule(r snitch.ConnRequest, verdict netfilter.Verdict) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	statement, err := db.conn.Prepare(ADD_APP_SQL)
	if err != nil {
		return fmt.Errorf("rules: Failed to prepare statement: %v", err)
	}

	_, err = statement.Exec(r.Command, verdict)
	if err != nil {
		return fmt.Errorf("rules: Failed to execute statement: %v", err)
	}

	return nil
}

func (db *RuleDB) GetConnRule(r snitch.ConnRequest) (netfilter.Verdict, error) {
	verdict := netfilter.NF_UNDEF

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	response, err := db.conn.Query(GET_CONN_SQL, r.Command, r.DstIp, r.DstPort, r.Proto, r.User)
	if err != nil {
		return verdict, fmt.Errorf("rules: Failed to query app table: %v", err)
	}
	defer response.Close()

	for response.Next() {
		err = response.Scan(&verdict)
		if err != nil {
			return netfilter.NF_UNDEF, fmt.Errorf("rules: Failed to get verdict from app table: %v", err)
		}
		break
	}

	return verdict, nil
}

func (db *RuleDB) AddConnRule(r snitch.ConnRequest, verdict netfilter.Verdict) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	statement, err := db.conn.Prepare(ADD_CONN_SQL)
	if err != nil {
		return fmt.Errorf("rules: Failed to prepare statement: %v", err)
	}

	_, err = statement.Exec(r.Command, verdict, r.DstIp, r.DstPort, r.Proto, r.User)
	if err != nil {
		return fmt.Errorf("rules: Failed to execute statement: %v", err)
	}

	return nil
}

func (db *RuleDB) GetAllConnEntries() ([]ConnCacheEntry, error) {
	entries := make([]ConnCacheEntry, MAX_CACHE_SIZE)

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	response, err := db.conn.Query(GET_ALL_CONN_SQL)
	if err != nil {
		return nil, err
	}
	defer response.Close()

	for response.Next() {
		entry := ConnCacheEntry{}
		err = response.Scan(&entry.Cmd, &entry.Verdict, &entry.DstIp, &entry.DstPort, &entry.Proto, &entry.User)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse entry: %v\n", err)
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func (db *RuleDB) GetAllAppEntries() ([]AppCacheEntry, error) {
	entries := make([]AppCacheEntry, MAX_CACHE_SIZE)

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	response, err := db.conn.Query(GET_ALL_APP_SQL)
	if err != nil {
		return nil, err
	}
	defer response.Close()

	for response.Next() {
		entry := AppCacheEntry{}
		err = response.Scan(&entry.Cmd, &entry.Verdict)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse entry: %v\n", err)
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func (db *RuleDB) GetVerdict(r snitch.ConnRequest) (netfilter.Verdict, error) {
	verdict := netfilter.NF_UNDEF

	verdict, err := db.GetAppRule(r)
	if err != nil {
		return netfilter.NF_UNDEF, err
	}

	if verdict != netfilter.NF_UNDEF {
		return verdict, nil
	}

	verdict, err = db.GetConnRule(r)
	if err != nil {
		return netfilter.NF_UNDEF, err
	}

	return verdict, nil
}
