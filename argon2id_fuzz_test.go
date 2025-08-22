//go:build go1.18
// +build go1.18

package argon2id

import (
	"testing"
)

func FuzzCreateHashNoError(f *testing.F) {
	f.Fuzz(func(t *testing.T, password string) {
		_, err := CreateHash(password, DefaultParams)
		if err != nil {
			t.Errorf("CreateHash error: %v", err)
		}
	})
}

func FuzzCreateHashUnique(f *testing.F) {
	f.Fuzz(func(t *testing.T, password string) {
		hash1, err1 := CreateHash(password, DefaultParams)
		hash2, err2 := CreateHash(password, DefaultParams)
		if err1 != nil || err2 != nil {
			t.Skipf("CreateHash error: %v, %v", err1, err2)
		}
		if hash1 == hash2 {
			t.Errorf("Hashes should be unique for same password: %q == %q", hash1, hash2)
		}
	})
}

func FuzzComparePasswordAndHash(f *testing.F) {
	f.Add("fuzz#short#long", "hashwew#1#kx,09")
	f.Add("badtoken", "hash123132123123")
	f.Add("password123", "DUMMY$argon3id$v=19$m=65536,t=4,p=1$Y29udGVudCBzYWx0$Y29udGVudCBrZXk=")
	f.Add("password123", "DUMMY$argon3id$v=19$m=65536,t=4,p=1$Y29udGVudCBzYWx0$Y29udGVudCBrZXk=")
	f.Fuzz(func(t *testing.T, password, hash string) {
		_, _ = ComparePasswordAndHash(password, hash)
	})
}
