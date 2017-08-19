package rules

import (
	"fmt"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/snitch"
)

func NewRuleCache(dbpath string) *RuleCache {
	db := NewRuleDB(dbpath)

	cache := &RuleCache{
		backend:   db,
		appCache:  make([]AppCacheEntry, MAX_CACHE_SIZE),
		connCache: make([]ConnCacheEntry, MAX_CACHE_SIZE),
	}

	return cache
}

func (cache *RuleCache) GetAppRule(r snitch.ConnRequest) (netfilter.Verdict, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	for _, entry := range cache.appCache {
		if entry.Cmd == r.Command {
			if entry.User == USER_ANY || entry.User == r.User {
				return entry.Verdict, nil
			}
		}
	}

	return netfilter.NF_UNDEF, nil
}

func (cache *RuleCache) AddAppRule(r snitch.ConnRequest, verdict netfilter.Verdict, filter int) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	err := cache.backend.AddAppRule(r, verdict, filter)
	if err != nil {
		return fmt.Errorf("RuleCache: %v", err)
	}

	user := r.User
	if filter == FILTER_SYSTEM {
		cache.mutex.Unlock()
		cache.DeleteAppUserRules(r)
		cache.mutex.Lock()
		user = USER_ANY
	}

	cache.appCache = append(cache.appCache, AppCacheEntry{
		Cmd:     r.Command,
		Verdict: verdict,
		User:    user,
	})

	return nil
}

func (cache *RuleCache) DeleteAppUserRules(r snitch.ConnRequest) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	err := cache.backend.DeleteAppUserRules(r)
	if err != nil {
		return err
	}

	newAppCache := make([]AppCacheEntry, MAX_CACHE_SIZE)
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

	return nil
}

func (cache *RuleCache) GetConnRule(r snitch.ConnRequest) (netfilter.Verdict, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	for _, entry := range cache.connCache {
		if entry.Cmd == r.Command && entry.DstIp == r.DstIp && entry.DstPort == r.DstPort && entry.Proto == r.Proto {
			if entry.User == USER_ANY || entry.User == r.User {
				return entry.Verdict, nil
			}
		}
	}

	return netfilter.NF_UNDEF, nil
}

func (cache *RuleCache) DeleteConnUserRules(r snitch.ConnRequest) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	err := cache.backend.DeleteConnUserRules(r)
	if err != nil {
		return err
	}

	newConnCache := make([]ConnCacheEntry, MAX_CACHE_SIZE)
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

	return nil
}

func (cache *RuleCache) AddConnRule(r snitch.ConnRequest, verdict netfilter.Verdict, filter int) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	err := cache.backend.AddConnRule(r, verdict, filter)
	if err != nil {
		return fmt.Errorf("RuleCache: %v", err)
	}

	user := r.User
	if filter == FILTER_SYSTEM {
		cache.mutex.Unlock()
		cache.DeleteConnUserRules(r)
		cache.mutex.Lock()
		user = USER_ANY
	}

	cache.connCache = append(cache.connCache, ConnCacheEntry{
		Cmd:     r.Command,
		Verdict: verdict,
		DstIp:   r.DstIp,
		DstPort: r.DstPort,
		Proto:   r.Proto,
		User:    user,
	})

	return nil
}

func (cache *RuleCache) Prime() error {
	appEntries, err := cache.backend.GetAllAppEntries()
	if err != nil {
		return err
	}
	cache.appCache = appEntries

	connEntries, err := cache.backend.GetAllConnEntries()
	if err != nil {
		return err
	}
	cache.connCache = connEntries

	return nil
}

func (cache *RuleCache) GetVerdict(r snitch.ConnRequest) (netfilter.Verdict, error) {
	verdict := netfilter.NF_UNDEF

	verdict, err := cache.GetAppRule(r)
	if err != nil {
		return netfilter.NF_UNDEF, err
	}

	if verdict != netfilter.NF_UNDEF {
		return verdict, nil
	}

	verdict, err = cache.GetConnRule(r)
	if err != nil {
		return netfilter.NF_UNDEF, err
	}

	return verdict, nil
}
