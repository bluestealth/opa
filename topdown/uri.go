// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

func convertStringSliceToInterfaceSlice(arr []string) (result []interface{}) {
	result = make([]interface{}, len(arr))
	for i, v := range arr {
		result[i] = v
	}
	return
}

func convertValuesToMap(values url.Values) (result map[string]interface{}) {
	result = make(map[string]interface{})
	for k, v := range values {
		result[k] = convertStringSliceToInterfaceSlice(v)
	}
	return
}

func builtinURIParse(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) (err error) {
	var uriString ast.String
	var value ast.Value
	var parsed *url.URL
	var result = make(map[string]interface{})

	if uriString, err = builtins.StringOperand(operands[0].Value, 1); err != nil {
		return
	}

	if parsed, err = url.Parse(string(uriString)); err != nil {
		return
	}

	result["scheme"] = parsed.Scheme

	if parsed.Opaque != "" {
		// Opaque URIs do not have an authority, only set the path
		result["path"] = parsed.Opaque
	} else {
		// Extract the authority fields from URI
		if parsed.User != nil {
			result["username"] = parsed.User.Username()
			if password, passwordSet := parsed.User.Password(); passwordSet {
				result["password"] = password
			}
		}
		result["hostname"] = parsed.Hostname()
		if parsed.Port() != "" {
			if result["port"], err = strconv.Atoi(parsed.Port()); err != nil {
				return
			}
		}
		result["path"] = parsed.EscapedPath()
	}

	if parsed.RawQuery != "" || parsed.ForceQuery {
		result["query"] = convertValuesToMap(parsed.Query())
		result["encoded_query"] = parsed.Query().Encode()
	}

	if parsed.Fragment != "" || strings.ContainsRune(string(uriString), '#') {
		result["fragment"] = parsed.Fragment
	}

	if value, err = ast.InterfaceToValue(result); err != nil {
		return
	}

	err = iter(ast.NewTerm(value))

	return
}

func init() {
	RegisterBuiltinFunc(ast.URIParse.Name, builtinURIParse)
}
