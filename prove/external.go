package prove

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type UrkelJson struct {
	Urkel string `json:"urkel"`
}

type DNSSECJson struct {
	Dnssec string `json:"dnssec"`
}

func fetchDNSSEC(domain string) ([]byte, error) {
	url := "https://sdaneproofs.htools.work/proofs/" + domain + "?dnssec"
	// url2 := "https://sdaneproofs.htools.work/proofs/collate?urkel"
	// log.Print(url)
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Error making GET request:", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error: Status code is not OK:", response.Status)
	}

	var data DNSSECJson
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("Error decoding JSON:", err)
	}
	log.Print("urk", data.Dnssec)

	val, err := hex.DecodeString(data.Dnssec)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func fetchUrkel(domain string) ([]byte, error) {
	// url := "https://sdaneproofs.htools.work/proofs/" + domain + "?dnssec"
	url := "https://sdaneproofs.htools.work/proofs/collate?urkel"
	// log.Print(url)
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Error making GET request:", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error: Status code is not OK:", response.Status)
	}

	var data UrkelJson
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("Error decoding JSON:", err)
	}
	// log.Print("urk", data.Urkeljkg)

	val, err := hex.DecodeString(data.Urkel)
	if err != nil {
		return nil, err
	}
	return val, nil
}
