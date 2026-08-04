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

package require

import (
	"testing"
)

type recordingT struct {
	errors int
	fatals int
}

func (*recordingT) Helper() {}

func (t *recordingT) Errorf(string, ...any) { t.errors++ }

func (t *recordingT) FailNow() { t.fatals++ }

func TestRequireStopsAfterFailure(t *testing.T) {
	recorder := new(recordingT)
	Equal(recorder, 1, 2, "failure %d", 1)
	if recorder.errors != 1 || recorder.fatals != 1 {
		t.Fatalf("got %d errors and %d fatal calls, want one each", recorder.errors, recorder.fatals)
	}
}

func TestRequireDoesNotStopAfterSuccess(t *testing.T) {
	recorder := new(recordingT)
	Equal(recorder, 1, 1)
	if recorder.errors != 0 || recorder.fatals != 0 {
		t.Fatal("successful assertion reported a failure")
	}
}
