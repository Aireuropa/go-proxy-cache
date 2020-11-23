//                                                                         __
// .-----.-----.______.-----.----.-----.--.--.--.--.______.----.---.-.----|  |--.-----.
// |  _  |  _  |______|  _  |   _|  _  |_   _|  |  |______|  __|  _  |  __|     |  -__|
// |___  |_____|      |   __|__| |_____|__.__|___  |      |____|___._|____|__|__|_____|
// |_____|            |__|                   |_____|
//
// Copyright (c) 2020 Fabio Cicerchia. https://fabiocicerchia.it. MIT License
// Repo: https://github.com/fabiocicerchia/go-proxy-cache
// +build unit

package utils_test

import (
	"os"
	"testing"

	"github.com/fabiocicerchia/go-proxy-cache/config"
	"github.com/fabiocicerchia/go-proxy-cache/utils"
	"github.com/stretchr/testify/assert"
)

// --- GetEnv

func TestGetEnvEmptyFallback(t *testing.T) {
	os.Setenv("testing", "1")

	value := utils.GetEnv("testing", "")

	assert.Equal(t, "1", value)

	tearDown()
}

func TestGetEnvFilledFallback(t *testing.T) {
	os.Setenv("testing", "2")

	value := utils.GetEnv("testing", "3")

	assert.Equal(t, "2", value)

	tearDown()
}

func TestGetEnvMissingEnv(t *testing.T) {
	value := utils.GetEnv("testing", "1")

	assert.Equal(t, "1", value)

	tearDown()
}

// --- IfEmpty

func TestIfEmptyWithValue(t *testing.T) {
	value := utils.IfEmpty("text", "fallback")

	assert.Equal(t, "text", value)

	tearDown()
}

func TestIfEmptyWithoutValue(t *testing.T) {
	value := utils.IfEmpty("", "fallback")

	assert.Equal(t, "fallback", value)

	tearDown()
}

// --- ContainsInt

func TestContainsIntEmpty(t *testing.T) {
	match := utils.ContainsInt([]int{}, 1)

	assert.False(t, match)

	tearDown()
}

func TestContainsIntNoValue(t *testing.T) {
	match := utils.ContainsInt([]int{1, 2, 3}, 4)

	assert.False(t, match)

	tearDown()
}

func TestContainsIntValue(t *testing.T) {
	match := utils.ContainsInt([]int{1, 2, 3}, 3)

	assert.True(t, match)

	tearDown()
}

// --- ContainsString

func TestContainsStringEmpty(t *testing.T) {
	match := utils.ContainsString([]string{}, "d")

	assert.False(t, match)

	tearDown()
}

func TestContainsStringNoValue(t *testing.T) {
	match := utils.ContainsString([]string{"a", "b", "c"}, "d")

	assert.False(t, match)

	tearDown()
}

func TestContainsStringValue(t *testing.T) {
	match := utils.ContainsString([]string{"a", "b", "c"}, "c")

	assert.True(t, match)

	tearDown()
}

// --- Unique

func TestUniqueEmpty(t *testing.T) {
	input := []string{}
	value := utils.Unique(input)

	assert.Equal(t, []string{}, value)

	tearDown()
}

func TestUniqueOneElement(t *testing.T) {
	input := []string{"a"}
	value := utils.Unique(input)

	assert.Equal(t, []string{"a"}, value)

	tearDown()
}

func TestUniqueTwoElements(t *testing.T) {
	input := []string{"a", "b"}
	value := utils.Unique(input)

	assert.Equal(t, []string{"a", "b"}, value)

	tearDown()
}

func TestUniqueTwoElementsWithDuplicates(t *testing.T) {
	input := []string{"a", "b", "c", "b", "a"}
	value := utils.Unique(input)

	assert.Equal(t, []string{"a", "b", "c"}, value)

	tearDown()
}

// --- LenSliceBytes

func TestLenSliceByteEmpty(t *testing.T) {
	input := [][]byte{}
	value := utils.LenSliceBytes(input)

	assert.Equal(t, 0, value)

	tearDown()
}

func TestLenSliceBytesOneItem(t *testing.T) {
	input := make([][]byte, 0)
	input = append(input, []byte("testing"))

	value := utils.LenSliceBytes(input)

	assert.Equal(t, 7, value)

	tearDown()
}

func TestLenSliceBytesTwosItems(t *testing.T) {
	input := make([][]byte, 1)
	input = append(input, []byte("testing"))
	input = append(input, []byte("sample"))

	value := utils.LenSliceBytes(input)

	assert.Equal(t, 13, value)

	tearDown()
}

func tearDown() {
	config.Config = config.Configuration{}
	os.Unsetenv("testing")
}
