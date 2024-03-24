package prove

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/randomlogin/sane/debuglog"
)

type UrkelJson struct {
	Urkel string `json:"urkel"`
}

type DNSSECJson struct {
	Dnssec string `json:"dnssec"`
}

var timeout = 1 * time.Second

func fetchDNSSEC(domain string, externalServices []string) ([]byte, error) {
	for _, link := range externalServices {
		//fetch full domain
		if result, err := fetchOneDNSSEC(domain, link); err == nil {
			return result, nil
		}
		debuglog.Logger.Debugf("couldn't fetch dnssec data for domain %s from %s", domain, link)
	}
	return nil, fmt.Errorf("could not fetch any external services")
}

func fetchUrkel(domain string, externalServices []string) ([]byte, error) {

	labels := dns.SplitDomainName(domain)
	tld := labels[len(labels)-1]
	for _, link := range externalServices {
		//fetch only tld
		if result, err := fetchOneUrkel(tld, link); err == nil {
			return result, nil
		}
		debuglog.Logger.Debugf("couldn't fetch urkel data for domain %s from %s", domain, link)
	}
	return nil, fmt.Errorf("could not fetch any external services")
}

func fetchOneDNSSEC(domain, server string) ([]byte, error) {

	if !strings.HasSuffix(server, "/") {
		server += "/"
	}
	url := server + domain + "?dnssec"
	client := http.Client{
		Timeout: timeout,
	}
	response, err := client.Get(url)
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

func fetchOneUrkel(domain, server string) ([]byte, error) {
	if !strings.HasSuffix(server, "/") {
		server += "/"
	}
	url := server + domain + "?urkel"
	client := http.Client{
		Timeout: timeout,
	}
	response, err := client.Get(url)
	// response, err := http.Get(url)
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
