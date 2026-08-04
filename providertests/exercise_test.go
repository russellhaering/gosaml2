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

//go:build go1.7

package providertests

import (
	"context"
	"testing"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	"github.com/russellhaering/gosaml2/v2/sp"
)

func ExerciseProviderTestScenarios(t *testing.T, scenarios []ProviderTestScenario) {
	for _, scenario := range scenarios {
		t.Run(scenario.ScenarioName, func(t *testing.T) {
			_, err := sp.DecodeUnverifiedBaseResponse(scenario.Response)
			// DecodeUnverifiedBaseResponse is more permissive than RetrieveAssertionInfo.
			// If an error _is_ returned it should match, but it is OK for no error to be
			// returned even when one is expected during full validation.
			if err != nil {
				scenario.CheckError(t, err)
			}

			ctx := context.Background()
			_, err = scenario.ServiceProvider.RetrieveAssertionInfo(ctx, scenario.Response)
			if scenario.CheckError != nil {
				scenario.CheckError(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
