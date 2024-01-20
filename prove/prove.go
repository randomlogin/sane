package prove

// #cgo LDFLAGS: -lurkel
// #include "urkel.h"
import "C"
import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/randomlogin/sane/dnssec"
	"github.com/randomlogin/sane/sync"
	"golang.org/x/crypto/sha3"
)

const urkelExt = "1.3.6.1.4.1.54392.5.1620"
const dnssecExt = "1.3.6.1.4.1.54392.5.1621"


type tlsError struct {
	err string
}

func (t *tlsError) Error() string {
	return t.err
}

func verifyUrkelExt(extensionValue []byte, domain string, roots *[]sync.BlockInfo) error {
	h := sha3.New256()
	h.Write([]byte(domain))
	key := h.Sum(nil)

	certRoot := extensionValue[1 : 1+32] //Magic numbers, should be checked
	certProof := extensionValue[33:]

	proofResult := verifyUrkelProof(key, certProof, certRoot)
	if !proofResult {
		return fmt.Errorf("the proof in the certificate is not valid")
	}

	// check that root is one of the stored ones
	hexstr := hex.EncodeToString(certRoot)
	for _, block := range *roots {
		if hexstr == block.TreeRoot {
			// log.Print("Found tree root ", block.TreeRoot, " from the certificate in the stored ones.")
			return nil
		}
	}
	return fmt.Errorf("urkel tree root %s from the certificate was not found among the stored ones", hexstr)
}

// extracts proof data from the certificate then verifies if the proof is correct
func VerifyCertificateExtensions(roots *[]sync.BlockInfo, cert x509.Certificate) error {
	extensions := cert.Extensions
	if len(extensions) < 2 {
		return fmt.Errorf("not found enough extensions in the certificate")
	}

	var UrkelVerificationError, DNSSECVerificationError error = errors.New("urkel tree proof extension was not found"), errors.New("DNSSEC chain extension was not found")
	for _, elem := range extensions {
		slog.Debug("found an extenson in certificate, its id is ", elem.Id.String())
		if elem.Id.String() == urkelExt {
			UrkelVerificationError = verifyUrkelExt(elem.Value, cert.DNSNames[0], roots)
			if UrkelVerificationError != nil {
				slog.Debug("UrkelVerificationError", UrkelVerificationError)
				return UrkelVerificationError
			}
		}
		if elem.Id.String() == dnssecExt {
			DNSSECVerificationError = dnssec.VerifyDNSSECChain(cert)
			if DNSSECVerificationError != nil {
				slog.Debug("DNSSECVerificationError", DNSSECVerificationError)
				return DNSSECVerificationError
			}
		}
	}

	if (UrkelVerificationError == nil) && (DNSSECVerificationError == nil) {
		slog.Debug("DANE extensions from certificate are both valid")
		return nil
	} else {
		return fmt.Errorf("could not verify SANE: %s, %s", UrkelVerificationError, DNSSECVerificationError)
	}
}

// verifies key in the urkel tree with a given proof against a given root
func verifyUrkelProof(key, proof, root []byte) bool {
	proofLen := C.size_t(len(proof))
	var exists C.int
	value := make([]byte, len(proof))
	var valueLen C.size_t

	intres := C.urkel_verify(
		&exists,
		(*C.uchar)(&value[0]),
		&valueLen,
		(*C.uchar)(&proof[0]),
		proofLen,
		(*C.uchar)(&key[0]),
		(*C.uchar)(&root[0]))

	if intres == 1 {
		return true
	} else {
		return false
	}
}
