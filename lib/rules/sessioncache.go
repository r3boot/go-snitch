package rules

import (
	"github.com/r3boot/go-snitch/lib/snitch"
)

func NewSessionCache() *SessionCache {

	cache := &SessionCache{
		appCache:  make([]SessionAppCacheEntry, MAX_CACHE_SIZE),
		connCache: make([]SessionConnCacheEntry, MAX_CACHE_SIZE),
	}

	return cache
}

func (cache *SessionCache) hasUserRule(r snitch.ConnRequest) bool {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	for _, entry := range cache.appCache {
		if entry.Cmd == r.Command && entry.User != USER_ANY {
			return true
		}
	}

	return false
}

func (cache *SessionCache) DeleteAppUserRules(r snitch.ConnRequest) {
	cache.mutex.Lock()
	defer cache.mutex.RUnlock()

	newAppCache := make([]SessionAppCacheEntry, MAX_CACHE_SIZE)
	for _, entry := range cache.appCache {
		if entry.Cmd != r.Command {
			continue
		}
		if entry.User != USER_ANY {
			continue
		}
		newAppCache = append(newAppCache, entry)
	}

	cache.appCache = newAppCache
}

func (cache *SessionCache) GetAppRule(r snitch.ConnRequest) (int, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	for _, entry := range cache.appCache {
		if entry.Cmd == r.Command {
			switch entry.User {
			case USER_ANY:
				{
					return entry.Verdict, nil
				}
			default:
				{
					if r.User == entry.User {
						return entry.Verdict, nil
					}
				}
			}
		}
	}

	return snitch.UNKNOWN, nil
}

func (cache *SessionCache) AddAppRule(r snitch.ConnRequest, verdict int) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	user := r.User

	switch verdict {
	case snitch.DROP_APP_ONCE_SYSTEM, snitch.ACCEPT_APP_ONCE_SYSTEM:
		{
			cache.DeleteAppUserRules(r)
			user = USER_ANY
		}
	}

	cache.appCache = append(cache.appCache, SessionAppCacheEntry{
		Cmd:     r.Command,
		Verdict: verdict,
		User:    user,
	})

	return nil
}

func (cache *SessionCache) GetConnRule(r snitch.ConnRequest) (int, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	for _, entry := range cache.connCache {
		if entry.Cmd == r.Command && entry.DstIp == r.DstIp && entry.DstPort == r.DstPort && entry.Proto == r.Proto {
			switch entry.User {
			case USER_ANY:
				{
					return entry.Verdict, nil
				}
			default:
				if r.User == entry.User {
					return entry.Verdict, nil
				}
			}
		}
	}

	return snitch.UNKNOWN, nil
}

func (cache *SessionCache) DeleteConnUserRules(r snitch.ConnRequest) {
	cache.mutex.Lock()
	defer cache.mutex.RUnlock()

	newConnCache := make([]SessionConnCacheEntry, MAX_CACHE_SIZE)
	for _, entry := range cache.connCache {
		if entry.Cmd != r.Command {
			continue
		}
		if entry.User != USER_ANY {
			continue
		}
		newConnCache = append(newConnCache, entry)
	}

	cache.connCache = newConnCache
}

func (cache *SessionCache) AddConnRule(r snitch.ConnRequest, verdict int) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	user := r.User

	switch verdict {
	case snitch.DROP_CONN_ONCE_SYSTEM, snitch.ACCEPT_CONN_ONCE_SYSTEM:
		{
			cache.DeleteConnUserRules(r)
			user = USER_ANY
		}
	}

	cache.connCache = append(cache.connCache, SessionConnCacheEntry{
		Cmd:     r.Command,
		Verdict: verdict,
		DstIp:   r.DstIp,
		DstPort: r.DstPort,
		Proto:   r.Proto,
		User:    user,
	})

	return nil
}

func (cache *SessionCache) GetVerdict(r snitch.ConnRequest) (int, error) {
	verdict := snitch.UNKNOWN

	verdict, err := cache.GetAppRule(r)
	if err != nil {
		return snitch.UNKNOWN, err
	}

	if verdict != snitch.UNKNOWN {
		return verdict, nil
	}

	verdict, err = cache.GetConnRule(r)
	if err != nil {
		return snitch.UNKNOWN, err
	}

	return verdict, nil
}
