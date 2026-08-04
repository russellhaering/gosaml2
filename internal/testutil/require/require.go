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

// Package require provides fatal, standard-library-only test assertions.
package require

import (
	"time"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/assertions"
)

type TestingT interface {
	assertions.TestingT
	FailNow()
}

func must(t TestingT, ok bool) {
	t.Helper()
	if !ok {
		t.FailNow()
	}
}

func Contains(t TestingT, a, b any, m ...any) {
	t.Helper()
	must(t, assertions.Contains(t, a, b, m...))
}
func Empty(t TestingT, a any, m ...any)    { t.Helper(); must(t, assertions.Empty(t, a, m...)) }
func Equal(t TestingT, a, b any, m ...any) { t.Helper(); must(t, assertions.Equal(t, a, b, m...)) }
func EqualError(t TestingT, err error, s string, m ...any) {
	t.Helper()
	must(t, assertions.EqualError(t, err, s, m...))
}
func EqualValues(t TestingT, a, b any, m ...any) {
	t.Helper()
	must(t, assertions.EqualValues(t, a, b, m...))
}
func Error(t TestingT, err error, m ...any) { t.Helper(); must(t, assertions.Error(t, err, m...)) }
func ErrorAs(t TestingT, err error, target any, m ...any) {
	t.Helper()
	must(t, assertions.ErrorAs(t, err, target, m...))
}
func ErrorIs(t TestingT, err, target error, m ...any) {
	t.Helper()
	must(t, assertions.ErrorIs(t, err, target, m...))
}
func Errorf(t TestingT, err error, format string, args ...any) {
	t.Helper()
	must(t, assertions.Errorf(t, err, format, args...))
}
func False(t TestingT, a bool, m ...any)     { t.Helper(); must(t, assertions.False(t, a, m...)) }
func Greater(t TestingT, a, b any, m ...any) { t.Helper(); must(t, assertions.Greater(t, a, b, m...)) }
func GreaterOrEqual(t TestingT, a, b any, m ...any) {
	t.Helper()
	must(t, assertions.GreaterOrEqual(t, a, b, m...))
}
func Len(t TestingT, a any, n int, m ...any) { t.Helper(); must(t, assertions.Len(t, a, n, m...)) }
func LessOrEqual(t TestingT, a, b any, m ...any) {
	t.Helper()
	must(t, assertions.LessOrEqual(t, a, b, m...))
}
func Nil(t TestingT, a any, m ...any)         { t.Helper(); must(t, assertions.Nil(t, a, m...)) }
func NoError(t TestingT, err error, m ...any) { t.Helper(); must(t, assertions.NoError(t, err, m...)) }
func NotContains(t TestingT, a, b any, m ...any) {
	t.Helper()
	must(t, assertions.NotContains(t, a, b, m...))
}
func NotEmpty(t TestingT, a any, m ...any) { t.Helper(); must(t, assertions.NotEmpty(t, a, m...)) }
func NotEqual(t TestingT, a, b any, m ...any) {
	t.Helper()
	must(t, assertions.NotEqual(t, a, b, m...))
}
func NotNil(t TestingT, a any, m ...any) { t.Helper(); must(t, assertions.NotNil(t, a, m...)) }
func NotPanics(t TestingT, fn func(), m ...any) {
	t.Helper()
	must(t, assertions.NotPanics(t, fn, m...))
}
func Positive(t TestingT, a any, m ...any) { t.Helper(); must(t, assertions.Positive(t, a, m...)) }
func Same(t TestingT, a, b any, m ...any)  { t.Helper(); must(t, assertions.Same(t, a, b, m...)) }
func True(t TestingT, a bool, m ...any)    { t.Helper(); must(t, assertions.True(t, a, m...)) }
func WithinDuration(t TestingT, a, b time.Time, d time.Duration, m ...any) {
	t.Helper()
	must(t, assertions.WithinDuration(t, a, b, d, m...))
}
func Zero(t TestingT, a any, m ...any) { t.Helper(); must(t, assertions.Zero(t, a, m...)) }
