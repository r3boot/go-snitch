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
			return entry.Verdict, nil
		}
	}

	return netfilter.NF_UNDEF, nil
}

func (cache *RuleCache) AddAppRule(r snitch.ConnRequest, verdict netfilter.Verdict) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	err := cache.backend.AddAppRule(r, verdict)
	if err != nil {
		return fmt.Errorf("RuleCache: %v", err)
	}

	cache.appCache = append(cache.appCache, AppCacheEntry{
		Cmd:     r.Command,
		Verdict: verdict,
	})

	return nil
}

func (cache *RuleCache) GetConnRule(r snitch.ConnRequest) (netfilter.Verdict, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	for _, entry := range cache.connCache {
		if entry.Cmd == r.Command && entry.DstIp == r.DstIp && entry.DstPort == r.DstPort && entry.Proto == r.Proto && entry.User == r.User {
			return entry.Verdict, nil
		}
	}

	return netfilter.NF_UNDEF, nil
}

func (cache *RuleCache) AddConnRule(r snitch.ConnRequest, verdict netfilter.Verdict) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	err := cache.backend.AddConnRule(r, verdict)
	if err != nil {
		return fmt.Errorf("RuleCache: %v", err)
	}

	cache.connCache = append(cache.connCache, ConnCacheEntry{
		Cmd:     r.Command,
		Verdict: verdict,
		DstIp:   r.DstIp,
		DstPort: r.DstPort,
		Proto:   r.Proto,
		User:    r.User,
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
