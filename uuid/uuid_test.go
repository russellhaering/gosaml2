// Copyright 2016 Russell Haering et al.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
