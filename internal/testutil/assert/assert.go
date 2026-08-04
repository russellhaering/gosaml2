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

// Package assert provides non-fatal, standard-library-only test assertions.
package assert

import (
	"time"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/assertions"
)

type TestingT = assertions.TestingT

func Contains(t TestingT, a, b any, m ...any) bool { return assertions.Contains(t, a, b, m...) }
func Empty(t TestingT, a any, m ...any) bool       { return assertions.Empty(t, a, m...) }
func Equal(t TestingT, a, b any, m ...any) bool    { return assertions.Equal(t, a, b, m...) }
func Error(t TestingT, err error, m ...any) bool   { return assertions.Error(t, err, m...) }
func False(t TestingT, a bool, m ...any) bool      { return assertions.False(t, a, m...) }
func Greater(t TestingT, a, b any, m ...any) bool  { return assertions.Greater(t, a, b, m...) }
func GreaterOrEqual(t TestingT, a, b any, m ...any) bool {
	return assertions.GreaterOrEqual(t, a, b, m...)
}
func Len(t TestingT, a any, n int, m ...any) bool  { return assertions.Len(t, a, n, m...) }
func Less(t TestingT, a, b any, m ...any) bool     { return assertions.Less(t, a, b, m...) }
func Nil(t TestingT, a any, m ...any) bool         { return assertions.Nil(t, a, m...) }
func NoError(t TestingT, err error, m ...any) bool { return assertions.NoError(t, err, m...) }
func NotContains(t TestingT, a, b any, m ...any) bool {
	return assertions.NotContains(t, a, b, m...)
}
func NotEqual(t TestingT, a, b any, m ...any) bool { return assertions.NotEqual(t, a, b, m...) }
func NotNil(t TestingT, a any, m ...any) bool      { return assertions.NotNil(t, a, m...) }
func NotSame(t TestingT, a, b any, m ...any) bool  { return assertions.NotSame(t, a, b, m...) }
func Same(t TestingT, a, b any, m ...any) bool     { return assertions.Same(t, a, b, m...) }
func True(t TestingT, a bool, m ...any) bool       { return assertions.True(t, a, m...) }
func WithinDuration(t TestingT, a, b time.Time, d time.Duration, m ...any) bool {
	return assertions.WithinDuration(t, a, b, d, m...)
}
