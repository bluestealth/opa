// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/ast"
)

func TestURIFormat(t *testing.T) {

	cases := []struct {
		note     string
		fields   string
		expected interface{}
	}{
		{
			note: "url with encoded query",
			fields: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"encoded_query": "id=7&sorted=false",
				"path": ""
			}`,
			expected: `"https://www.openpolicyagent.org?id=7&sorted=false"`,
		},
		{
			note: "url with query object",
			fields: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "",
				"query": {
					"id": ["7"],
					"sorted": ["false"]
				}
			}`,
			expected: `"https://www.openpolicyagent.org?id=7&sorted=false"`,
		},
		{
			note: "url with fragment",

			fields: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "",
				"fragment": "3aef"
			}`,
			expected: `"https://www.openpolicyagent.org#3aef"`,
		},
		{
			note: "url with username",
			fields: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "/login",
				"username": "user"
			}`,
			expected: `"https://user@www.openpolicyagent.org/login"`,
		},
		{
			note: "url with username and password",
			fields: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "/login",
				"username": "user",
				"password": "pass",
			}`,
			expected: `"https://user:pass@www.openpolicyagent.org/login"`,
		},
		{
			note: "url with port",
			fields: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "",
				"port": 443
			}`,
			expected: `"https://www.openpolicyagent.org:443"`,
		},
		{
			note: "opaque uri",
			fields: `{
				"scheme": "mailto",
				"path": "user@openpolicyagent.org",
				"encoded_query": "valid%3F=false",
				"fragment": "3afe",
				"query": {
					"valid?": ["false"]
				}
			}`,
			expected: `"mailto:user@openpolicyagent.org?valid%3F=false#3afe"`,
		},
		{
			note: "url with string port",
			fields: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "",
				"port": "0x1BB"
			}`,
			expected: `"https://www.openpolicyagent.org:443"`,
		},
		{
			note: "url with invalid port",
			fields: `{
				"scheme": "https",
				"hostname": "www.openpolicyagent.org",
				"path": "",
				"port": -1
			}`,
			expected: &Error{
				Code: BuiltinErr,
				Message: fmt.Sprintf("%s: parse \"%s\": invalid port \":%s\" after host",
					ast.URIFormat.Name, "https://www.openpolicyagent.org:-1", "-1")},
		},
	}

	for _, tc := range cases {
		rules := []string{
			fmt.Sprintf("p = x { x := uri.format(%s) }", tc.fields),
		}
		runTopDownTestCase(t, map[string]interface{}{}, tc.note, rules, tc.expected)
	}

}

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
