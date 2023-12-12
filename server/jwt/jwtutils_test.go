package jwt

import (
	"testing"

	"github.com/fabiocicerchia/go-proxy-cache/config"
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
	co = &config.Jwt{Included_paths: []string{"/a"}}
	res := IsIncluded(co.Included_paths, "/a")
	if !res {
		t.Error("Expected false but got", res)
	}

	res = IsIncluded(co.Included_paths, "/b")
	if res {
		t.Error("Expected true  but got", res)
	}
	co = &config.Jwt{Included_paths: []string{}}
	res = IsIncluded(co.Included_paths, "/b")
	if res {
		t.Error("Expected true  but got", res)
	}

}
