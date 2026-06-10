// Copyright 2025 Russell Haering et al.
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

package sp

import xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"

// strictParseErr reports the strict parser's verdict on raw XML. Tests that
// previously consulted xml-roundtrip-validator as a parser-differential
// oracle now use the strict parser directly — it is the validation gate for
// both the POST and redirect bindings, so the differential those tests
// guarded against is structurally impossible.
func strictParseErr(rawXML string) error {
	_, err := xmltree.Parse([]byte(rawXML))
	return err
}
