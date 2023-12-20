package prove

// #cgo LDFLAGS: -lurkel
// #include "urkel.h"
import "C"
import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/randomlogin/sane/sync"
	"golang.org/x/crypto/sha3"
)

const urkelExt = "1.3.6.1.4.1.54392.5.1620"
const dnssecExt = "1.3.6.1.4.1.54392.5.1621"

// i need a function to parse value obtained from the proof and to exctract cerificate identifier from it
func getCertificateFingerprintFromProofValue() {}

type tlsError struct {
	err string
}

func (t *tlsError) Error() string {
	return t.err
}

// cert calculate fingerprint of the certificate
// func fingerprint(cert x509.Certificate) string {
// 	fingerprint := sha3.Sum(cert.Raw)
// 	x := hex.EncodeToString(fingerprint) // to make sure it's a hex string
// 	log.Print(x)
// 	return x
// }

func verifyUrkelExt(extensionValue []byte, domain string, rootsPath string) bool {
	h := sha3.New256()
	h.Write([]byte(domain))
	key := h.Sum(nil)

	certRoot := extensionValue[1 : 1+32] //Magic numbers, should be checked
	certProof := extensionValue[33:]

	proofResult := verifyUrkelProof(key, certProof, certRoot)
	if !proofResult {
		log.Print("The prove in certificate is not valid.")
		return false
	}

	// check that root is one of the stored ones
	blocks := sync.ReadStoredRoots(rootsPath)
	hexstr := hex.EncodeToString(certRoot)
	for _, block := range blocks {
		if hexstr == block.TreeRoot {
			log.Print("Found tree root ", block.TreeRoot, " from the certificate in the stored ones.")
			return true
		}
	}
	log.Print("Couldn't find the tree root from the certificate in the stored ones.")
	return false
}

// TODO implement
func verifyDNSSEC(val []byte) bool {
	return true
}

// extracts proof data from the certificate then verifies if the proof is correct
func MyVerifyCertificate(rootsPath string) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("no certificate found")
		}
		cert := cs.PeerCertificates[0]
		extensions := cert.Extensions
		log.Print("servername ", cs.ServerName)
		if err := cs.PeerCertificates[0].VerifyHostname(cs.ServerName); err != nil {
			return fmt.Errorf("tls: %v", err)
		}
		var verifiedProof, verifiedDNSSEC bool
		for _, elem := range extensions {
			if elem.Id.String() == urkelExt {
				verifiedProof = verifyUrkelExt(elem.Value, cert.DNSNames[0], rootsPath)
			}
			if elem.Id.String() == dnssecExt {
				verifiedDNSSEC = verifyDNSSEC(elem.Value)
			}
		}
		if verifiedProof && verifiedDNSSEC {
			return nil
		} else {
			return &tlsError{err: "tls: stateless dane verification failed"}
			// return fmt.Errorf("Could not verify certificate correctedness.")
		}
	}
}

// verifies key in the urkel tree with a given proof against a given root
func verifyUrkelProof(key, proof, root []byte) bool {
	proofLen := C.size_t(len(proof))
	var exists C.int
	value := make([]byte, len(proof))
	// log.Print(hex.EncodeToString(value))
	var valueLen C.size_t

	intres := C.urkel_verify(
		&exists,
		(*C.uchar)(&value[0]),
		&valueLen,
		(*C.uchar)(&proof[0]),
		proofLen,
		(*C.uchar)(&key[0]),
		(*C.uchar)(&root[0]))

	// log.Print(hex.EncodeToString(value))

	if intres == 1 {
		return true
	} else {
		return false
	}
}
