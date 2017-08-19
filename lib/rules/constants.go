package rules

import (
	"database/sql"
	"sync"

	_ "github.com/mattn/go-sqlite3"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
)

const (
	DB_PATH           string = "/var/lib/go-snitch.db"
	CONN_TABLE_SQL    string = "CREATE TABLE IF NOT EXISTS conn_rules (cmd TEXT, verdict INTEGER, dstip TEXT, port TEXT, proto TEXT, user TEXT, UNIQUE (cmd, verdict, dstip, port, proto, user))"
	GET_CONN_SQL      string = "SELECT verdict, user FROM conn_rules WHERE cmd = ? AND dstip = ? AND port = ? AND proto = ?"
	ADD_CONN_SQL      string = "INSERT OR REPLACE INTO conn_rules VALUES (?, ?, ?, ?, ?, ?)"
	DEL_CONN_USER_SQL string = "DELETE FROM conn_rules WHERE cmd = ? AND user != '*'"
	GET_ALL_CONN_SQL  string = "SELECT cmd, verdict, dstip, port, proto, user FROM conn_rules"
	APP_TABLE_SQL     string = "CREATE TABLE IF NOT EXISTS app_rules (cmd TEXT, verdict INTEGER, user TEXT, UNIQUE (cmd, verdict, user))"
	GET_APP_SQL       string = "SELECT verdict, user FROM app_rules WHERE cmd = ?"
	DEL_APP_USER_SQL  string = "DELETE FROM app_rules WHERE cmd = ? AND user != '*'"
	GET_ALL_APP_SQL   string = "SELECT cmd, verdict, user FROM app_rules"
	ADD_APP_SQL       string = "INSERT OR REPLACE INTO app_rules VALUES (?, ?, ?)"
	MAX_CACHE_SIZE    int    = 16384
	USER_ANY          string = "*"
	FILTER_USER       int    = 0
	FILTER_SYSTEM     int    = 1
)

type RuleDB struct {
	conn  *sql.DB
	path  string
	mutex sync.RWMutex
}

type AppCacheEntry struct {
	Cmd     string
	Verdict netfilter.Verdict
	User    string
}

type ConnCacheEntry struct {
	Cmd     string
	Verdict netfilter.Verdict
	DstIp   string
	DstPort string
	Proto   string
	User    string
}

type SessionAppCacheEntry struct {
	Cmd     string
	Verdict int
	User    string
}

type SessionConnCacheEntry struct {
	Cmd     string
	Verdict int
	DstIp   string
	DstPort string
	Proto   string
	User    string
}

type RuleCache struct {
	backend   *RuleDB
	appCache  []AppCacheEntry
	connCache []ConnCacheEntry
	mutex     sync.RWMutex
}

type SessionCache struct {
	appCache  []SessionAppCacheEntry
	connCache []SessionConnCacheEntry
	mutex     sync.RWMutex
}
