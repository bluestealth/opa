// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"encoding/json"
	"fmt"
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

var requiredURIKeys = []string{
	"scheme",
	"path",
}

var evaluatedURIKeys = []string{
	"scheme",
	"path",
	"username",
	"password",
	"hostname",
	"path",
	"encoded_query",
	"query",
	"fragment",
}

func validateURIFormatOperand(term *ast.Term, pos int) (object ast.Object, keySet ast.Set, err error) {
	if object, err = builtins.ObjectOperand(term.Value, pos); err != nil {
		return
	}

	keySet = ast.NewSet(object.Keys()...)

	for _, key := range requiredURIKeys {
		if !keySet.Contains(ast.NewTerm(ast.String(key))) {
			err = builtins.NewOperandErr(pos, fmt.Sprintf("%s is a required parameter", key))
			return
		}
	}

	for _, keyValue := range keySet.Slice() {
		key := string(keyValue.Value.(ast.String))
		value := object.Get(keyValue).Value
		switch key {
		case "port":
			_, isString := value.(ast.String)
			_, isNumber := value.(ast.Number)
			if !isString && !isNumber {
				err = builtins.NewOperandErr(pos, fmt.Sprintf("parameter %s should be a number but is type %T", key, value))
				return
			}
		case "query":
			if _, isObject := value.(ast.Object); !isObject {
				err = builtins.NewOperandErr(pos, fmt.Sprintf("parameter %s should be a object but is type %T", key, value))
				return
			}
		default:
			if _, isString := value.(ast.String); !isString {
				err = builtins.NewOperandErr(pos, fmt.Sprintf("parameter %s should be a string but is type %T", key, value))
				return
			}
		}
	}

	return
}

func builtinURIFormat(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) (err error) {
	var parsed *url.URL = &url.URL{}
	var object ast.Object
	var keySet ast.Set
	var value ast.Value

	if object, keySet, err = validateURIFormatOperand(operands[0], 1); err != nil {
		return
	}

	parsed.Scheme = string(object.Get(ast.NewTerm(ast.String("scheme"))).Value.(ast.String))

	if keySet.Contains(ast.NewTerm(ast.String("fragment"))) {
		parsed.Fragment = string(object.Get(ast.NewTerm(ast.String("fragment"))).Value.(ast.String))
	}

	if keySet.Contains(ast.NewTerm(ast.String("encoded_query"))) {
		parsed.RawQuery = string(object.Get(ast.NewTerm(ast.String("encoded_query"))).Value.(ast.String))
		parsed.ForceQuery = true
	} else if keySet.Contains(ast.NewTerm(ast.String("query"))) {
		var values url.Values
		if err = ast.As(object.Get(ast.NewTerm(ast.String("query"))).Value, &values); err != nil {
			return
		}
		parsed.RawQuery = values.Encode()
		parsed.ForceQuery = true
	}

	if keySet.Contains(ast.NewTerm(ast.String("hostname"))) {
		// not opaque URI extract authority and path
		hostname := string(object.Get(ast.NewTerm(ast.String("hostname"))).Value.(ast.String))

		if keySet.Contains(ast.NewTerm(ast.String("username"))) {
			username := string(object.Get(ast.NewTerm(ast.String("username"))).Value.(ast.String))
			if keySet.Contains(ast.NewTerm(ast.String("password"))) {
				password := string(object.Get(ast.NewTerm(ast.String("password"))).Value.(ast.String))
				parsed.User = url.UserPassword(username, password)
			} else {
				parsed.User = url.User(username)
			}
		}

		if keySet.Contains(ast.NewTerm(ast.String("port"))) {
			var port interface{}
			var intValue int64
			if port, err = ast.JSON(object.Get(ast.NewTerm(ast.String("port"))).Value); err != nil {
				return
			}
			switch port := port.(type) {
			case string:
				if intValue, err = strconv.ParseInt(port, 0, 0); err != nil {
					return
				}
			case json.Number:
				if intValue, err = port.Int64(); err != nil {
					return
				}
			}

			parsed.Host = fmt.Sprintf("%s:%d", hostname, intValue)
		} else {
			parsed.Host = hostname
		}

		parsed.Path = string(object.Get(ast.NewTerm(ast.String("path"))).Value.(ast.String))
	} else {
		// opaque URI extract path only
		parsed.Opaque = string(object.Get(ast.NewTerm(ast.String("path"))).Value.(ast.String))
	}

	if parsed, err = url.Parse(parsed.String()); err != nil {
		return
	}

	uriString := parsed.String()

	// Empty fragment passed, append it to uri
	if keySet.Contains(ast.NewTerm(ast.String("fragment"))) && !strings.ContainsRune(uriString, '#') {
		uriString += "#"
	}

	if value, err = ast.InterfaceToValue(uriString); err != nil {
		return
	}

	err = iter(ast.NewTerm(value))

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
	RegisterBuiltinFunc(ast.URIFormat.Name, builtinURIFormat)
	RegisterBuiltinFunc(ast.URIParse.Name, builtinURIParse)
}
