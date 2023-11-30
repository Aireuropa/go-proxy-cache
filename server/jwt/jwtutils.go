package jwt

import "strings"

func Contains(s []string, searchterm string) bool {
	for _, v := range s {
		if v == searchterm {
			return true
		}
	}
	return false
}

func IsExcluded(paths []string, searchterm string) bool {
	for _, v := range paths {
		hasprefix := strings.HasPrefix(searchterm, v)
		if hasprefix {
			return true
		}
	}
	return false
}
