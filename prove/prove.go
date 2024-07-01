package prove

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
	"github.com/randomlogin/sane/sync"
)

const urkelExt = "1.3.6.1.4.1.54392.5.1620"
const dnssecExt = "1.3.6.1.4.1.54392.5.1621"

type tlsError struct {
	err string
}

func (t *tlsError) Error() string {
	return t.err
}

// extracts proof data from the certificate then verifies if the proof is correct
func VerifyCertificateExtensions(roots []sync.BlockInfo, cert x509.Certificate, tlsa *dns.TLSA, externalServices []string) error {
	if len(cert.DNSNames) == 0 {
		return fmt.Errorf("certificate has empty dns names")
	}
	labels := dns.SplitDomainName(tlsa.Header().Name)
	if len(labels) < 3 {
		return fmt.Errorf("tlsa record has less than 3 labels")
	}
	tlsaDomain := strings.Join(labels[2:], ".")

	for _, domain := range cert.DNSNames {
		err := verifyDomain(tlsaDomain, cert, roots, tlsa, externalServices)
		if err == nil {
			log.Printf("successfully verified certificate extensions for the domain %s", domain)
			return nil
		}
		log.Printf("during verification of the domain %s got error: %s", domain, err)
	}
	return fmt.Errorf("failed to verify certificate extensions")
}

// verifyDomain is called to check every domain listed in the certificate
func verifyDomain(domain string, cert x509.Certificate, roots []sync.BlockInfo, tlsa *dns.TLSA, externalServices []string) error {
	var foundUrkel, foundDnssec bool
	var urkelExtension, dnssecExtension []byte
	var UrkelVerificationError, DNSSECVerificationError error = errors.New("urkel tree proof extension not found"), errors.New("DNSSEC chain extension not found")
	var err error
	var tld string
	labels := dns.SplitDomainName(domain)
	tld = labels[len(labels)-1]

	for _, elem := range cert.Extensions {
		if elem.Id.String() == urkelExt {
			foundUrkel = true
			urkelExtension = elem.Value
		}
		if elem.Id.String() == dnssecExt {
			foundDnssec = true
			dnssecExtension = elem.Value
		}
	}

	if !foundUrkel {
		if len(externalServices) == 0 {
			return fmt.Errorf("certificate does not have an urkel proof extension and external service is disabled")
		}
		urkelExtension, err = fetchUrkel(domain, externalServices)
		if err != nil {
			return err
		}
	}

	if !foundDnssec {
		if len(externalServices) == 0 {
			return fmt.Errorf("certificate does not have dnssec chain extension and external service is disabled")
		}
		dnssecExtension, err = fetchDNSSEC(domain, externalServices)
		if err != nil {
			return err
		}
	}

	UrkelVerificationError = verifyUrkelExt(urkelExtension, tld, roots)
	if UrkelVerificationError != nil {
		return UrkelVerificationError
	}

	DNSSECVerificationError = verifyDNSSECChain(dnssecExtension, domain, tlsa)
	if DNSSECVerificationError != nil {
		return DNSSECVerificationError
	}

	if (UrkelVerificationError == nil) && (DNSSECVerificationError == nil) {
		return nil
	} else {
		return fmt.Errorf("could not verify SANE for the domain %s: %s, %s", domain, UrkelVerificationError, DNSSECVerificationError)
	}
}
