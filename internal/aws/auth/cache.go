package auth

import (
	"container/list"
	"sync"
)

// lruCache keeps at most size values, dropping the least recently used.
type lruCache[K comparable, V any] struct {
	mu    sync.Mutex
	size  int
	order *list.List // front is most recently used
	items map[K]*list.Element
}

type lruEntry[K comparable, V any] struct {
	key   K
	value V
}

func newLRUCache[K comparable, V any](size int) *lruCache[K, V] {
	return &lruCache[K, V]{
		size:  size,
		order: list.New(),
		items: make(map[K]*list.Element, size),
	}
}

// getOrCreate returns the value stored under key, creating it on first use.
func (c *lruCache[K, V]) getOrCreate(key K, create func() V) V {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)

		entry, _ := elem.Value.(*lruEntry[K, V])

		return entry.value
	}

	value := create()
	c.items[key] = c.order.PushFront(&lruEntry[K, V]{key: key, value: value})

	if c.order.Len() > c.size {
		oldest := c.order.Back()
		c.order.Remove(oldest)

		entry, _ := oldest.Value.(*lruEntry[K, V])
		delete(c.items, entry.key)
	}

	return value
}
