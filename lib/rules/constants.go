package rules

import (
	"database/sql"
	"sync"

	_ "github.com/mattn/go-sqlite3"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
)

const (
	DB_PATH        string = "/var/lib/go-snitch.db"
	CONN_TABLE_SQL string = "CREATE TABLE IF NOT EXISTS conn_rules (cmd TEXT, verdict INTEGER, dstip TEXT, port TEXT, proto TEXT, user TEXT, UNIQUE (cmd, verdict, dstip, port, proto, user))"
	GET_CONN_SQL   string = "SELECT verdict FROM conn_rules WHERE cmd = ? AND dstip = ? AND port = ? AND proto = ? AND user = ?"
	ADD_CONN_SQL   string = "INSERT OR REPLACE INTO conn_rules VALUES (?, ?, ?, ?, ?, ?)"
	APP_TABLE_SQL  string = "CREATE TABLE IF NOT EXISTS app_rules (cmd TEXT, verdict INTEGER, UNIQUE (cmd, verdict))"
	GET_APP_SQL    string = "SELECT verdict FROM app_rules WHERE cmd = ?"
	ADD_APP_SQL    string = "INSERT OR REPLACE INTO app_rules VALUES (?, ?)"
	MAX_CACHE_SIZE int    = 16384
)

type RuleDB struct {
	conn  *sql.DB
	path  string
	mutex sync.RWMutex
}

type AppCacheEntry struct {
	Cmd     string
	Verdict netfilter.Verdict
}

type ConnCacheEntry struct {
	Cmd     string
	Verdict netfilter.Verdict
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
