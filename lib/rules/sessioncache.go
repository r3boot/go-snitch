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

func (cache *SessionCache) GetAppRule(r snitch.ConnRequest) (int, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	for _, entry := range cache.appCache {
		if entry.Cmd == r.Command {
			return entry.Verdict, nil
		}
	}

	return snitch.UNKNOWN, nil
}

func (cache *SessionCache) AddAppRule(r snitch.ConnRequest, verdict int) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	cache.appCache = append(cache.appCache, SessionAppCacheEntry{
		Cmd:     r.Command,
		Verdict: verdict,
	})

	return nil
}

func (cache *SessionCache) GetConnRule(r snitch.ConnRequest) (int, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	for _, entry := range cache.connCache {
		if entry.Cmd == r.Command && entry.DstIp == r.DstIp && entry.DstPort == r.DstPort && entry.Proto == r.Proto && entry.User == r.User {
			return entry.Verdict, nil
		}
	}

	return snitch.UNKNOWN, nil
}

func (cache *SessionCache) AddConnRule(r snitch.ConnRequest, verdict int) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	cache.connCache = append(cache.connCache, SessionConnCacheEntry{
		Cmd:     r.Command,
		Verdict: verdict,
		DstIp:   r.DstIp,
		DstPort: r.DstPort,
		Proto:   r.Proto,
		User:    r.User,
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
