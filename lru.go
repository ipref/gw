/* Copyright (c) 2025 Waldemar Augustyn */

package main

import (
	"sync"
	"time"
)

type lruEntry[K comparable, V any] struct {
	key K
	val V
	added time.Time
	prev *lruEntry[K, V] // the previous most recently used (less recent)
	next *lruEntry[K, V] // the next most recently used (more recent)
}

// Called with the lock acquired
type LRUEvictCallback[K comparable, V any] func(K, V)

type LRU[K comparable, V any] struct {
	Lock sync.Mutex
	ents map[K]*lruEntry[K, V]
	oldest *lruEntry[K, V]
	newest *lruEntry[K, V]
	nents int
	maxents int
	TTL time.Duration
	OnEvict LRUEvictCallback[K, V]
	kill chan bool
}

// Expiration only happens if you call Expire or ExpireLoop. If you don't call
// those methods, then ttl is ignored.
func NewLRU[K comparable, V any](maxents int, ttl time.Duration,
	on_evict LRUEvictCallback[K, V]) (c *LRU[K, V]) {

	if maxents < 1 {
		panic("maxents must be >= 1")
	}
	return &LRU[K, V]{
		ents: make(map[K]*lruEntry[K, V]),
		maxents: maxents,
		TTL: ttl,
		OnEvict: on_evict,
	}
}

// Add an entry to the cache. If an entry already exists with the given key, it
// is replaced, it's recency is updated, and the previous value is returned.
//
// The evict callback is not called if the value is replaced.
func (c *LRU[K, V]) Add(key K, val V, on_evict, lock bool) (prev V, found, evicted bool) {

	if lock {
		c.Lock.Lock()
		defer c.Lock.Unlock()
	}

	prev, found = c.Get(key, false)
	if found {
		c.newest.val = val
	} else {
		_, evicted = c.Append(key, val, on_evict, false)
	}
	return
}

// Add an entry to the cache only if it does not already exist. The recency is
// not updated.
func (c *LRU[K, V]) Append(key K, val V, on_evict, lock bool) (added, evicted bool) {

	if lock {
		c.Lock.Lock()
		defer c.Lock.Unlock()
	}

	_, exists := c.ents[key]
	if exists {
		return
	}
	ent := &lruEntry[K, V]{
		key: key,
		val: val,
		added: time.Now(),
		prev: c.newest,
		next: nil,
	}
	c.ents[key] = ent
	if c.newest == nil {
		c.oldest = ent
	} else {
		c.newest.next = ent
	}
	c.newest = ent
	c.nents++
	if c.nents > c.maxents {
		c.RemoveOldest(on_evict, false)
		evicted = true
	}
	added = true
	return
}

// Lookup the key in the cache, and move it to the most recent position if it
// exists.
func (c *LRU[K, V]) Get(key K, lock bool) (val V, exists bool) {

	if lock {
		c.Lock.Lock()
		defer c.Lock.Unlock()
	}

	var ent *lruEntry[K, V]
	ent, exists = c.ents[key]
	if !exists {
		return
	}
	if ent.next == nil {
		return ent.val, true
	}

	// remove from list
	if ent.prev == nil {
		c.oldest = ent.next
	} else {
		ent.prev.next = ent.next
	}
	ent.next.prev = ent.prev

	// add to end of list
	ent.prev = c.newest
	ent.next = nil
	c.newest = ent
	ent.prev.next = ent

	return ent.val, true
}

// Lookup the key in the cache, but don't update its recency.
func (c *LRU[K, V]) Peek(key K, lock bool) (val V, exists bool) {

	if lock {
		c.Lock.Lock()
		defer c.Lock.Unlock()
	}

	var ent *lruEntry[K, V]
	ent, exists = c.ents[key]
	if exists {
		val = ent.val
	}
	return
}

// Get the oldest entry in the cache without updated its recency.
func (c *LRU[K, V]) PeekOldest(lock bool) (key K, val V, exists bool) {

	if lock {
		c.Lock.Lock()
		defer c.Lock.Unlock()
	}

	if c.oldest != nil {
		return c.oldest.key, c.oldest.val, true
	}
	return
}

// Remove an entry from the cache, and return its previous value (if it existed).
func (c *LRU[K, V]) Remove(key K, on_evict, lock bool) (val V, found bool) {

	if lock {
		c.Lock.Lock()
		defer c.Lock.Unlock()
	}

	var ent *lruEntry[K, V]
	ent, found = c.ents[key]
	if !found {
		return
	}
	val = ent.val
	found = true

	if ent.prev == nil {
		c.oldest = ent.next
	} else {
		ent.prev.next = ent.next
	}
	if ent.next == nil {
		c.newest = ent.prev
	} else {
		ent.next.prev = ent.prev
	}
	*ent = lruEntry[K, V]{}
	delete(c.ents, key)
	c.nents--

	if on_evict {
		c.OnEvict(key, val)
	}
	return
}

func (c *LRU[K, V]) RemoveOldest(on_evict, lock bool) (key K, val V, found bool) {

	if lock {
		c.Lock.Lock()
		defer c.Lock.Unlock()
	}

	ent := c.oldest
	if ent == nil {
		return
	}
	key, val = ent.key, ent.val
	found = true
	if ent.next != nil {
		ent.next.prev = nil
		c.oldest = ent.next
		if ent.prev != nil {
			panic("unexpected")
		}
		c.nents--
	} else {
		c.oldest = nil
		c.newest = nil
		c.nents = 0
	}
	*ent = lruEntry[K, V]{}
	delete(c.ents, ent.key)

	if on_evict {
		c.OnEvict(key, val)
	}
	return
}

func (c *LRU[K, V]) Clear(on_evict, lock bool) (evicted int) {

	if lock {
		c.Lock.Lock()
		defer c.Lock.Unlock()
	}

	for c.nents != 0 {
		c.RemoveOldest(on_evict, false)
		evicted++
	}
	return
}

func (c *LRU[K, V]) Expire(on_evict, lock bool) (evicted int) {

	if lock {
		c.Lock.Lock()
		defer c.Lock.Unlock()
	}

	for c.oldest != nil && (c.TTL <= 0 || time.Since(c.oldest.added) > c.TTL) {
		c.RemoveOldest(on_evict, false)
		evicted++
	}
	return
}

func (c *LRU[K, V]) ExpireLoop(on_evict bool, precision int64) {

	interval := c.TTL / time.Duration(precision)
	for {
		c.Lock.Lock()
		if c.kill != nil {
			c.kill <- true
			return // Deliberately does not release the lock.
		}
		c.Expire(on_evict, false)
		c.Lock.Unlock()
		time.Sleep(interval)
	}
}

// Not re-entrant.
func (c *LRU[K, V]) KillExpireLoop() {

	c.Lock.Lock()
	if c.kill != nil {
		panic("unexpected")
	}
	c.kill = make(chan bool, 0)
	c.Lock.Unlock()
	<-c.kill // Lock is acquired.
	c.kill = nil
	c.Lock.Unlock()
}
