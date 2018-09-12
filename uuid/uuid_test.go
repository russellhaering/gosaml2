package uuid

import (
	"testing"
)

func TestUUID(t *testing.T) {
	s := NewV4()
	s2 := NewV4()
	if len(s) != 16 {
		t.Errorf("Expecting len of 16, got %d\n", len(s))
	}
	if len(s.String()) != 36 {
		t.Errorf("Expecting uuid hex string len of 36, got %d\n", len(s.String()))
	}
	if s == s2 {
		t.Errorf("Expecting different UUIDs to be different, but they are the same.\n")
	}
}

func TestString(t *testing.T) {
	u := UUID{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	s := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

	if u.String() != s {
		t.Errorf("Expecting uuid string %q, got %q\n", s, u.String())
	}
}
