package cache

import (
	"time"

	"github.com/dgraph-io/badger/v4"
)

type NullifierCache interface {
	MightBeSpent(nullifier []byte) (bool, error)
	MarkSpent(nullifier []byte) error
	Close() error
}

type BadgerCache struct {
	db *badger.DB
}

func NewBadgerCache(path string) (*BadgerCache, error) {
	opts := badger.DefaultOptions(path).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &BadgerCache{db: db}, nil
}

func (c *BadgerCache) MightBeSpent(nullifier []byte) (bool, error) {
	err := c.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(nullifier)
		return err
	})
	if err == badger.ErrKeyNotFound {
		return false, nil
	}
	return err == nil, err
}

func (c *BadgerCache) MarkSpent(nullifier []byte) error {
	return c.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(nullifier, []byte{1}).WithTTL(24 * time.Hour)
		return txn.SetEntry(e)
	})
}

func (c *BadgerCache) Close() error {
	return c.db.Close()
}
