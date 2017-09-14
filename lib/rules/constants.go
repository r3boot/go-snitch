package rules

import (
	"database/sql"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/r3boot/go-snitch/lib/ui"
)

const RULESET_TABLE_SQL string = `CREATE TABLE IF NOT EXISTS ruleset (
	id INTEGER PRIMARY KEY,
	cmd TEXT NOT NULL,
	verdict INTEGER NOT NULL,
	dstip TEXT,
	port TEXT,
	proto INTEGER,
	user TEXT NOT NULL,
	timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
	duration INTEGER,
	UNIQUE (cmd, verdict, user, dstip, port, proto, user, duration))`

const ADD_APP_RULE_SQL string = `INSERT INTO ruleset
	(cmd, verdict, user, timestamp) VALUES (?, ?, ?, ?)`

const ADD_APP_DURATION_RULE_SQL string = `INSERT INTO ruleset
	(cmd, verdict, user, timestamp, duration) VALUES (?, ?, ?, ?, ?)`

const ADD_CONN_RULE_SQL string = `INSERT INTO ruleset
	(cmd, verdict, dstip, port, proto, user, timestamp)
	VALUES (?, ?, ?, ?, ?, ?, ?)`

const ADD_CONN_DURATION_RULE_SQL string = `INSERT INTO ruleset
	(cmd, verdict, dstip, port, proto, user, timestamp, duration)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

const GET_RULE_BY_CMD_SQL string = `SELECT id, cmd, verdict, dstip, dstport,
	proto, user, timestamp, duration FROM ruleset WHERE cmd = ?`

const DELETE_RULE_BY_ID_SQL string = `DELETE FROM ruleset WHERE id = ?`

const DELETE_CONN_RULE_BY_CMD_SQL string = `DELETE FROM ruleset WHERE
	cmd = ? AND dstip != ''`

const UPDATE_RULE_SQL string = `UPDATE ruleset SET
	dstip = ?, port = ?, proto = ?, user = ?, verdict = ?, duration = ?
	WHERE id = ?`

const GET_ALL_RULES_SQL string = `SELECT * FROM ruleset`

const (
	DB_PATH        string = "/var/lib/go-snitch.db"
	MAX_CACHE_SIZE int    = 16384
	USER_ANY       string = "*"
	UNKNOWN_ID     int    = -1
	FILTER_USER    int    = 0
	FILTER_SYSTEM  int    = 1
)

type RuleItem struct {
	Id        int
	Cmd       string
	Verdict   int
	Dstip     string
	Port      string
	Proto     int
	User      string
	Timestamp time.Time
	Duration  time.Duration
}

type RuleDetail struct {
	Id        int
	Command   string
	Dstip     string
	Port      string
	Proto     int
	User      string
	Action    string
	RuleType  ui.RuleType
	Verdict   int
	Timestamp time.Time
	Duration  time.Duration
}

type RuleDB struct {
	conn  *sql.DB
	path  string
	mutex sync.RWMutex
}

type RuleCache struct {
	backend *RuleDB
	ruleset []RuleItem
	mutex   sync.RWMutex
}

type SessionCache struct {
	ruleset []RuleItem
	mutex   sync.RWMutex
}
