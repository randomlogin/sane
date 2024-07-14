package prove

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/nodech/go-hsd-utils/proof"
	"github.com/randomlogin/sane/sync"
	"golang.org/x/crypto/sha3"
)

func checkUrkelProof(certProof, certRoot, key []byte) (*int, error) {
	urkelProof, err := proof.NewFromBytes(certProof)
	if err != nil {
		return nil, fmt.Errorf("urkel verification: %s", err)
	}

	treeRoot := proof.UrkelHash(certRoot)
	urkelKey := proof.UrkelHash(key)
	resultCode, _ := urkelProof.Verify(treeRoot, urkelKey)
	if resultCode != proof.ProofOk {
		return nil, fmt.Errorf("urkel proof verification failed")
	}

	var buf bytes.Buffer
	err = urkelProof.Serialize(&buf)
	if err != nil {
		return nil, fmt.Errorf("serialization err: %s ", err)
	}
	var x = len(buf.Bytes())
	return &x, nil
}

func verifyUrkelExt(extensionValue []byte, domain string, roots []sync.BlockInfo) error {
	h := sha3.New256()
	h.Write([]byte(domain))
	key := h.Sum(nil)

	if len(extensionValue) < 0 {
		return fmt.Errorf("urkel data is corrupted")
	}

	var numberOfProofs, i uint8 = extensionValue[0], 0
	if numberOfProofs == 0 {
		return fmt.Errorf("urkel extension is empty")
	}
	extensionValue = extensionValue[1:]
	for ; i < numberOfProofs; i++ {
		certRoot := extensionValue[:32] //Magic numbers, should be checked
		hexstr := hex.EncodeToString(certRoot)

		certProof := extensionValue[32:]
		length, err := checkUrkelProof(certProof, certRoot, key)
		if err != nil {
			//found invalid proof
			log.Printf("urkel verification failed: %s", err)
			return err
		}
		for _, block := range roots {
			// found tree root among stored ones
			if hexstr == block.TreeRoot {
				log.Printf("found tree root %s from the certificate in the stored roots", hexstr)
				return nil
			}
		}
		extensionValue = extensionValue[32+*length:]
		log.Printf("could not find tree root %s from the certificate in the stored roots", hexstr)
	}
	return fmt.Errorf("could not find tree root in the stored ones")
}
