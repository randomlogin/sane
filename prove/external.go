package prove

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type UrkelJson struct {
	Urkel string `json:"urkel"`
}

type DNSSECJson struct {
	Dnssec string `json:"dnssec"`
}

var defaultURL = "https://sdaneproofs.htools.work/proofs/"

func fetchDNSSEC(domain, server string) ([]byte, error) {
	if !strings.HasSuffix(server, "/") {
		server += "/"
	}
	url := server + domain + "?dnssec"
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error making GET request: %s", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code is not OK: %s", response.Status)
	}

	var data DNSSECJson
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("error decoding JSON: %s", err)
	}

	val, err := hex.DecodeString(data.Dnssec)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func fetchUrkel(domain, server string) ([]byte, error) {
	if !strings.HasSuffix(server, "/") {
		server += "/"
	}
	url := server + domain + "?urkel"
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Error making GET request: %s", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error: Status code is not OK: %s", response.Status)
	}

	var data UrkelJson
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("Error decoding JSON: %s", err)
	}

	val, err := hex.DecodeString(data.Urkel)
	if err != nil {
		return nil, err
	}
	return val, nil
}
