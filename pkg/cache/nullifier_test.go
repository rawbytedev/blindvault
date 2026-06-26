package cache

import "testing"

func TempSetup(t *testing.T) *BadgerCache {
	badger, err := NewBadgerCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return badger
}

func TestCacheEntry(t *testing.T) {
	badger := TempSetup(t)
	err := badger.MarkSpent([]byte{0x1, 0x2})
	if err != nil {
		t.Fatal(err)
	}
	res, err := badger.MightBeSpent([]byte{0x1, 0x2})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res)
	badger.Close()
}
