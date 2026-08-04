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

// Package assertions implements the small assertion vocabulary used by this
// repository's tests. It intentionally depends only on the standard library.
package assertions

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"time"
)

// TestingT is the portion of testing.TB needed by non-fatal assertions.
type TestingT interface {
	Helper()
	Errorf(format string, args ...any)
}

func report(t TestingT, failure string, msgAndArgs ...any) bool {
	t.Helper()
	if message := formatMessage(msgAndArgs); message != "" {
		failure += ": " + message
	}
	t.Errorf("%s", failure)
	return false
}

func formatMessage(msgAndArgs []any) string {
	if len(msgAndArgs) == 0 {
		return ""
	}
	if len(msgAndArgs) == 1 {
		return fmt.Sprintf("%v", msgAndArgs[0])
	}
	if format, ok := msgAndArgs[0].(string); ok {
		return fmt.Sprintf(format, msgAndArgs[1:]...)
	}
	return fmt.Sprint(msgAndArgs...)
}

// Equal checks values using reflect.DeepEqual.
func Equal(t TestingT, expected, actual any, msgAndArgs ...any) bool {
	t.Helper()
	if reflect.DeepEqual(expected, actual) {
		return true
	}
	return report(t, fmt.Sprintf("not equal\nexpected: %#v\nactual:   %#v", expected, actual), msgAndArgs...)
}

// EqualValues also considers numerically equal values with different numeric types equal.
func EqualValues(t TestingT, expected, actual any, msgAndArgs ...any) bool {
	t.Helper()
	if reflect.DeepEqual(expected, actual) {
		return true
	}
	expectedNumber, expectedIsNumber := number(expected)
	actualNumber, actualIsNumber := number(actual)
	if expectedIsNumber && actualIsNumber {
		if expectedNumber.Cmp(actualNumber) == 0 {
			return true
		}
		return report(t, fmt.Sprintf("values are not equal\nexpected: %#v\nactual:   %#v", expected, actual), msgAndArgs...)
	}
	ev, av := reflect.ValueOf(expected), reflect.ValueOf(actual)
	if ev.IsValid() && av.IsValid() && ev.Type().ConvertibleTo(av.Type()) &&
		reflect.DeepEqual(ev.Convert(av.Type()).Interface(), actual) {
		return true
	}
	return report(t, fmt.Sprintf("values are not equal\nexpected: %#v\nactual:   %#v", expected, actual), msgAndArgs...)
}

func NotEqual(t TestingT, expected, actual any, msgAndArgs ...any) bool {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		return true
	}
	return report(t, fmt.Sprintf("values unexpectedly equal: %#v", actual), msgAndArgs...)
}

func True(t TestingT, value bool, msgAndArgs ...any) bool {
	t.Helper()
	if value {
		return true
	}
	return report(t, "expected true", msgAndArgs...)
}

func False(t TestingT, value bool, msgAndArgs ...any) bool {
	t.Helper()
	if !value {
		return true
	}
	return report(t, "expected false", msgAndArgs...)
}

func Nil(t TestingT, value any, msgAndArgs ...any) bool {
	t.Helper()
	if isNil(value) {
		return true
	}
	return report(t, fmt.Sprintf("expected nil, got %#v", value), msgAndArgs...)
}

func NotNil(t TestingT, value any, msgAndArgs ...any) bool {
	t.Helper()
	if !isNil(value) {
		return true
	}
	return report(t, "expected a non-nil value", msgAndArgs...)
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func Empty(t TestingT, value any, msgAndArgs ...any) bool {
	t.Helper()
	if isEmpty(value) {
		return true
	}
	return report(t, fmt.Sprintf("expected empty, got %#v", value), msgAndArgs...)
}

func NotEmpty(t TestingT, value any, msgAndArgs ...any) bool {
	t.Helper()
	if !isEmpty(value) {
		return true
	}
	return report(t, "expected a non-empty value", msgAndArgs...)
}

func isEmpty(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	default:
		return v.IsZero()
	}
}

func Zero(t TestingT, value any, msgAndArgs ...any) bool {
	t.Helper()
	if isEmpty(value) {
		return true
	}
	return report(t, fmt.Sprintf("expected zero, got %#v", value), msgAndArgs...)
}

func Positive(t TestingT, value any, msgAndArgs ...any) bool {
	t.Helper()
	n, ok := number(value)
	if ok && n.Sign() > 0 {
		return true
	}
	return report(t, fmt.Sprintf("expected a positive number, got %#v", value), msgAndArgs...)
}

func Len(t TestingT, value any, expected int, msgAndArgs ...any) bool {
	t.Helper()
	v := reflect.ValueOf(value)
	if v.IsValid() {
		switch v.Kind() {
		case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
			if v.Len() == expected {
				return true
			}
			return report(t, fmt.Sprintf("unexpected length: got %d, want %d", v.Len(), expected), msgAndArgs...)
		}
	}
	return report(t, fmt.Sprintf("value of type %T has no length", value), msgAndArgs...)
}

func Contains(t TestingT, container, element any, msgAndArgs ...any) bool {
	t.Helper()
	if contains(container, element) {
		return true
	}
	return report(t, fmt.Sprintf("%#v does not contain %#v", container, element), msgAndArgs...)
}

func NotContains(t TestingT, container, element any, msgAndArgs ...any) bool {
	t.Helper()
	if !contains(container, element) {
		return true
	}
	return report(t, fmt.Sprintf("%#v unexpectedly contains %#v", container, element), msgAndArgs...)
}

func contains(container, element any) bool {
	if text, ok := container.(string); ok {
		needle, ok := element.(string)
		return ok && strings.Contains(text, needle)
	}
	v := reflect.ValueOf(container)
	if !v.IsValid() {
		return false
	}
	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if reflect.DeepEqual(v.Index(i).Interface(), element) {
				return true
			}
		}
	case reflect.Map:
		key := reflect.ValueOf(element)
		if key.IsValid() && key.Type().AssignableTo(v.Type().Key()) {
			return v.MapIndex(key).IsValid()
		}
	}
	return false
}

func NoError(t TestingT, err error, msgAndArgs ...any) bool {
	t.Helper()
	if err == nil {
		return true
	}
	return report(t, fmt.Sprintf("unexpected error: %v", err), msgAndArgs...)
}

func Error(t TestingT, err error, msgAndArgs ...any) bool {
	t.Helper()
	if err != nil {
		return true
	}
	return report(t, "expected an error", msgAndArgs...)
}

func Errorf(t TestingT, err error, format string, args ...any) bool {
	t.Helper()
	if err != nil {
		return true
	}
	message := append([]any{format}, args...)
	return report(t, "expected an error", message...)
}

func EqualError(t TestingT, err error, expected string, msgAndArgs ...any) bool {
	t.Helper()
	if err != nil && err.Error() == expected {
		return true
	}
	if err == nil {
		return report(t, fmt.Sprintf("expected error %q, got nil", expected), msgAndArgs...)
	}
	return report(t, fmt.Sprintf("unexpected error text: got %q, want %q", err.Error(), expected), msgAndArgs...)
}

func ErrorIs(t TestingT, err, target error, msgAndArgs ...any) bool {
	t.Helper()
	if errors.Is(err, target) {
		return true
	}
	return report(t, fmt.Sprintf("error %v does not match target %v", err, target), msgAndArgs...)
}

func ErrorAs(t TestingT, err error, target any, msgAndArgs ...any) bool {
	t.Helper()
	if errors.As(err, target) {
		return true
	}
	return report(t, fmt.Sprintf("error %v cannot be assigned to %T", err, target), msgAndArgs...)
}

func Same(t TestingT, expected, actual any, msgAndArgs ...any) bool {
	t.Helper()
	ep, eok := pointer(expected)
	ap, aok := pointer(actual)
	if eok && aok && ep == ap {
		return true
	}
	return report(t, fmt.Sprintf("values do not point to the same object: %#v != %#v", expected, actual), msgAndArgs...)
}

func NotSame(t TestingT, expected, actual any, msgAndArgs ...any) bool {
	t.Helper()
	ep, eok := pointer(expected)
	ap, aok := pointer(actual)
	if eok && aok && ep != ap {
		return true
	}
	return report(t, "values unexpectedly point to the same object", msgAndArgs...)
}

func pointer(value any) (uintptr, bool) {
	if value == nil {
		return 0, false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Ptr, reflect.Slice, reflect.UnsafePointer:
		return v.Pointer(), true
	default:
		return 0, false
	}
}

func Greater(t TestingT, actual, threshold any, msgAndArgs ...any) bool {
	return ordered(t, actual, threshold, 1, "greater than", msgAndArgs...)
}

func GreaterOrEqual(t TestingT, actual, threshold any, msgAndArgs ...any) bool {
	return ordered(t, actual, threshold, 0, "greater than or equal to", msgAndArgs...)
}

func Less(t TestingT, actual, threshold any, msgAndArgs ...any) bool {
	return ordered(t, actual, threshold, -1, "less than", msgAndArgs...)
}

func LessOrEqual(t TestingT, actual, threshold any, msgAndArgs ...any) bool {
	return ordered(t, actual, threshold, 0, "less than or equal to", msgAndArgs...)
}

func ordered(t TestingT, actual, threshold any, boundary int, description string, msgAndArgs ...any) bool {
	t.Helper()
	comparison, ok := compare(actual, threshold)
	passed := ok && comparison == boundary
	if boundary == 0 {
		if strings.HasPrefix(description, "greater") {
			passed = ok && comparison >= 0
		} else {
			passed = ok && comparison <= 0
		}
	}
	if passed {
		return true
	}
	return report(t, fmt.Sprintf("expected %#v to be %s %#v", actual, description, threshold), msgAndArgs...)
}

func compare(a, b any) (int, bool) {
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		if !ok {
			return 0, false
		}
		return strings.Compare(as, bs), true
	}
	an, aok := number(a)
	bn, bok := number(b)
	if !aok || !bok {
		return 0, false
	}
	return an.Cmp(bn), true
}

func number(value any) (*big.Rat, bool) {
	if value == nil {
		return nil, false
	}
	v := reflect.ValueOf(value)
	n := new(big.Rat)
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return n.SetInt64(v.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return n.SetUint64(v.Uint()), true
	case reflect.Float32, reflect.Float64:
		if n.SetFloat64(v.Float()) == nil {
			return nil, false
		}
		return n, true
	default:
		return nil, false
	}
}

func WithinDuration(t TestingT, expected, actual time.Time, delta time.Duration, msgAndArgs ...any) bool {
	t.Helper()
	difference := expected.Sub(actual)
	if difference < 0 {
		difference = -difference
	}
	if difference <= delta {
		return true
	}
	return report(t, fmt.Sprintf("times differ by %s, exceeding %s", difference, delta), msgAndArgs...)
}

func NotPanics(t TestingT, fn func(), msgAndArgs ...any) (ok bool) {
	t.Helper()
	ok = true
	defer func() {
		if recovered := recover(); recovered != nil {
			ok = report(t, fmt.Sprintf("function panicked: %v", recovered), msgAndArgs...)
		}
	}()
	fn()
	return ok
}
