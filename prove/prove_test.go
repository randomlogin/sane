package prove

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/randomlogin/sane/sync"
)

func TestVerifyCertificateExtensions(t *testing.T) {
	roots, err := sync.ReadStoredRoots("/home/shevtsov/.sane/roots.json")
	if err != nil {
		log.Fatal(err)
	}

	certFile, err := os.ReadFile("../test_certs/0F.pem")
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(certFile)
	if block == nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return
	}

	log.Print(cert.DNSNames)
	a := cert.DNSNames[0]
	y, z := dns.IsDomainName(a)
	log.Print(y, z)
	x := dns.SplitDomainName(a)
	log.Print(x)
	// log.Print(len(cert.DNSNames))

	err = VerifyCertificateExtensions(roots, *cert)
	if err != nil {
		log.Fatal(err)
	}

}
