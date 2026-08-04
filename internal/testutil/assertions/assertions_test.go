// Copyright 2026 Russell Haering et al.
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

package assertions

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

type recordingT struct {
	messages []string
}

func (*recordingT) Helper() {}

func (t *recordingT) Errorf(format string, args ...any) {
	t.messages = append(t.messages, fmt.Sprintf(format, args...))
}

func expectPass(t *testing.T, assertion func(TestingT) bool) {
	t.Helper()
	recorder := new(recordingT)
	if !assertion(recorder) {
		t.Fatal("assertion unexpectedly returned false")
	}
	if len(recorder.messages) != 0 {
		t.Fatalf("passing assertion reported errors: %v", recorder.messages)
	}
}

func expectFailure(t *testing.T, assertion func(TestingT) bool) {
	t.Helper()
	recorder := new(recordingT)
	if assertion(recorder) {
		t.Fatal("assertion unexpectedly returned true")
	}
	if len(recorder.messages) != 1 {
		t.Fatalf("failing assertion reported %d errors, want 1", len(recorder.messages))
	}
}

func TestEqualityAssertions(t *testing.T) {
	expectPass(t, func(t TestingT) bool { return Equal(t, []int{1, 2}, []int{1, 2}) })
	expectFailure(t, func(t TestingT) bool { return Equal(t, 1, 2, "numbers differ") })
	expectPass(t, func(t TestingT) bool { return EqualValues(t, int32(7), uint64(7)) })
	expectFailure(t, func(t TestingT) bool { return EqualValues(t, int8(-1), uint8(255)) })
	expectPass(t, func(t TestingT) bool { return NotEqual(t, 1, 2) })
	expectFailure(t, func(t TestingT) bool { return NotEqual(t, "same", "same") })
}

func TestBooleanAndEmptinessAssertions(t *testing.T) {
	var nilPointer *int
	expectPass(t, func(t TestingT) bool { return True(t, true) })
	expectFailure(t, func(t TestingT) bool { return True(t, false) })
	expectPass(t, func(t TestingT) bool { return False(t, false) })
	expectFailure(t, func(t TestingT) bool { return False(t, true) })
	expectPass(t, func(t TestingT) bool { return Nil(t, nilPointer) })
	expectFailure(t, func(t TestingT) bool { return Nil(t, 1) })
	expectPass(t, func(t TestingT) bool { return NotNil(t, 1) })
	expectFailure(t, func(t TestingT) bool { return NotNil(t, nilPointer) })
	expectPass(t, func(t TestingT) bool { return Empty(t, []byte{}) })
	expectFailure(t, func(t TestingT) bool { return Empty(t, []byte{1}) })
	expectPass(t, func(t TestingT) bool { return NotEmpty(t, "x") })
	expectFailure(t, func(t TestingT) bool { return NotEmpty(t, "") })
	expectPass(t, func(t TestingT) bool { return Zero(t, 0) })
	expectFailure(t, func(t TestingT) bool { return Zero(t, 1) })
	expectPass(t, func(t TestingT) bool { return Positive(t, time.Second) })
	expectFailure(t, func(t TestingT) bool { return Positive(t, -1) })
}

func TestCollectionAssertions(t *testing.T) {
	expectPass(t, func(t TestingT) bool { return Len(t, []int{1, 2}, 2) })
	expectFailure(t, func(t TestingT) bool { return Len(t, 42, 1) })
	expectPass(t, func(t TestingT) bool { return Contains(t, "abcdef", "bcd") })
	expectPass(t, func(t TestingT) bool { return Contains(t, []int{1, 2}, 2) })
	expectPass(t, func(t TestingT) bool { return Contains(t, map[string]int{"x": 1}, "x") })
	expectFailure(t, func(t TestingT) bool { return Contains(t, []int{1, 2}, 3) })
	expectPass(t, func(t TestingT) bool { return NotContains(t, "abcdef", "xyz") })
	expectFailure(t, func(t TestingT) bool { return NotContains(t, "abcdef", "abc") })
}

type markedError struct{}

func (*markedError) Error() string { return "marked" }

func TestErrorAssertions(t *testing.T) {
	sentinel := errors.New("sentinel")
	wrapped := fmt.Errorf("wrapped: %w", sentinel)
	expectPass(t, func(t TestingT) bool { return NoError(t, nil) })
	expectFailure(t, func(t TestingT) bool { return NoError(t, sentinel) })
	expectPass(t, func(t TestingT) bool { return Error(t, sentinel) })
	expectFailure(t, func(t TestingT) bool { return Error(t, nil) })
	expectFailure(t, func(t TestingT) bool { return Errorf(t, nil, "missing %s", "error") })
	expectPass(t, func(t TestingT) bool { return EqualError(t, sentinel, "sentinel") })
	expectFailure(t, func(t TestingT) bool { return EqualError(t, nil, "sentinel") })
	expectPass(t, func(t TestingT) bool { return ErrorIs(t, wrapped, sentinel) })
	expectFailure(t, func(t TestingT) bool { return ErrorIs(t, wrapped, errors.New("other")) })
	expectPass(t, func(t TestingT) bool {
		var target *markedError
		return ErrorAs(t, &markedError{}, &target)
	})
}

func TestIdentityAndOrderingAssertions(t *testing.T) {
	value := 1
	other := 1
	expectPass(t, func(t TestingT) bool { return Same(t, &value, &value) })
	expectFailure(t, func(t TestingT) bool { return Same(t, &value, &other) })
	expectPass(t, func(t TestingT) bool { return NotSame(t, &value, &other) })
	expectFailure(t, func(t TestingT) bool { return NotSame(t, &value, &value) })
	expectPass(t, func(t TestingT) bool { return Greater(t, 2, 1) })
	expectFailure(t, func(t TestingT) bool { return Greater(t, 1, 1) })
	expectPass(t, func(t TestingT) bool { return GreaterOrEqual(t, 1, 1) })
	expectPass(t, func(t TestingT) bool { return Less(t, -1, uint(1)) })
	expectFailure(t, func(t TestingT) bool { return Less(t, 2, 1) })
	expectPass(t, func(t TestingT) bool { return LessOrEqual(t, 1, 1) })
}

func TestTimeAndPanicAssertions(t *testing.T) {
	now := time.Now()
	expectPass(t, func(t TestingT) bool { return WithinDuration(t, now, now.Add(time.Second), time.Second) })
	expectFailure(t, func(t TestingT) bool { return WithinDuration(t, now, now.Add(2*time.Second), time.Second) })
	expectPass(t, func(t TestingT) bool { return NotPanics(t, func() {}) })
	expectFailure(t, func(t TestingT) bool { return NotPanics(t, func() { panic("boom") }) })
}
