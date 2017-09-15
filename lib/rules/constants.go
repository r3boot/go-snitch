package rules

import (
	"database/sql"
	"sync"

	_ "github.com/mattn/go-sqlite3"

	"github.com/r3boot/go-snitch/lib/datastructures"
	"github.com/r3boot/go-snitch/lib/logger"
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
	MAX_CACHE_SIZE int    = 16384
	USER_ANY       string = "*"
)

type RuleDB struct {
	conn  *sql.DB
	path  string
	mutex sync.RWMutex
}

type RuleCache struct {
	backend *RuleDB
	ruleset datastructures.Ruleset
	mutex   sync.RWMutex
}

type SessionCache struct {
	ruleset datastructures.Ruleset
	mutex   sync.RWMutex
}

var log *logger.Logger
