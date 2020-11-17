package handler

import (
	"fmt"
	"net/http"

	"github.com/fabiocicerchia/go-proxy-cache/cache"
	"github.com/fabiocicerchia/go-proxy-cache/config"
)

func HandlePurge(res http.ResponseWriter, req *http.Request) {
	forwarding := config.GetForwarding()

	proxyURL := fmt.Sprintf("%s://%s", forwarding.Scheme, forwarding.Host)
	fullURL := proxyURL + req.URL.String()

	status, err := cache.PurgeFullPage(req.Method, fullURL)

	if !status || err != nil {
		res.WriteHeader(http.StatusNotModified)
		res.Write(([]byte)("KO"))
		return
	}

	res.WriteHeader(http.StatusOK)
	res.Write(([]byte)("OK"))
}
