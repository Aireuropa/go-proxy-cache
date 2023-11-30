package jwt

import (
	"testing"
)

func TestContains(t *testing.T) {

	v := []string{"a", "b"}
	res := Contains(v, "a")
	if !res {
		t.Error("Expected true but got", res)
	}

	res = Contains(v, "c")
	if res {
		t.Error("Expected false but got", res)
	}
	res = Contains(v, "")
	if res {
		t.Error("Expected false but got", res)
	}

	v = []string{}
	res = Contains(v, "a")
	if res {
		t.Error("Expected false but got", res)
	}

	res = Contains(v, "")
	if res {
		t.Error("Expected false but got", res)
	}

}

func TestIsExcluded(t *testing.T) {
	co = &JwtConfig{Excluded_paths: []string{"/a"}}
	res := IsExcluded(co.Excluded_paths, "/a")
	if !res {
		t.Error("Expected false but got", res)
	}

	res = IsExcluded(co.Excluded_paths, "/b")
	if res {
		t.Error("Expected true  but got", res)
	}
	co = &JwtConfig{Excluded_paths: []string{}}
	res = IsExcluded(co.Excluded_paths, "/b")
	if res {
		t.Error("Expected true  but got", res)
	}

}
