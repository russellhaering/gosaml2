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

package saml2

import (
	"bytes"
	"html/template"
)

var postFormTemplate = template.Must(template.New("saml-post-form").Parse(
	`<form method="POST" action="{{.URL}}" id="SAMLForm">` +
		`<input type="hidden" name="{{.ParamName}}" value="{{.ParamValue}}" />` +
		`{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}" />{{end}}` +
		`<input id="SAMLSubmitButton" type="submit" value="Submit" />` +
		`</form>` +
		`<script>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLForm').submit();</script>`))

func buildPOSTForm(actionURL, paramName, paramValue, relayState string) ([]byte, error) {
	data := struct {
		URL        string
		ParamName  string
		ParamValue string
		RelayState string
	}{
		URL:        actionURL,
		ParamName:  paramName,
		ParamValue: paramValue,
		RelayState: relayState,
	}
	var buf bytes.Buffer
	if err := postFormTemplate.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
