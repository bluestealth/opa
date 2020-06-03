// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/ast"
)

func TestURIParse(t *testing.T) {

	cases := []struct {
		note     string
		uri      string
		expected interface{}
	}{
		{
			note: "url with query",
			uri:  "https://www.openpolicyagent.org?id=7&sorted=false",
			expected: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"encoded_query": "id=7&sorted=false",
				"path": "",
				"query": {
					"id": ["7"],
					"sorted": ["false"]
				}
			}`,
		},
		{
			note: "url with fragment",
			uri:  "https://www.openpolicyagent.org#3aef",
			expected: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "",
				"fragment": "3aef"
			}`,
		},
		{
			note: "url with username",
			uri:  "https://user@www.openpolicyagent.org/login",
			expected: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "/login",
				"username": "user"
			}`,
		},
		{
			note: "url with username and password",
			uri:  "https://user:pass@www.openpolicyagent.org/login",
			expected: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "/login",
				"username": "user",
				"password": "pass"
			}`,
		},
		{
			note: "url with port",
			uri:  "https://www.openpolicyagent.org:443",
			expected: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "",
				"port": 443
			}`,
		},
		{
			note: "opaque uri",
			uri:  "mailto:user@openpolicyagent.org?valid?=false#3afe",
			expected: `{
				"scheme": "mailto",
				"path": "user@openpolicyagent.org",
				"encoded_query": "valid%3F=false",
				"fragment": "3afe",
				"query": {
					"valid?": ["false"]
				}
			}`,
		},
		{
			note: "url with invalid port",
			uri:  "https://www.openpolicyagent.org:3a9",
			expected: &Error{
				Code: BuiltinErr,
				Message: fmt.Sprintf("%s: parse \"%s\": invalid port \":%s\" after host",
					ast.URIParse.Name, "https://www.openpolicyagent.org:3a9", "3a9")},
		},
	}

	for _, tc := range cases {
		rules := []string{
			fmt.Sprintf("p = x { x := uri.parse(\"%s\") }", tc.uri),
		}
		runTopDownTestCase(t, map[string]interface{}{}, tc.note, rules, tc.expected)
	}

}
