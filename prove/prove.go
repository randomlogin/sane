package prove

// #cgo LDFLAGS: -lurkel
// #include "urkel.h"
import "C"
import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"os"

	"golang.org/x/crypto/sha3"
)

const firstId = "1.3.6.1.4.1.54392.5.1620"
const secondId = "1.3.6.1.4.1.54392.5.1621"
const certFileName = "a.pem"

// i need a function to parse value obtained from the proof and to exctract cerificate identifier from it
func getCertificateFingerprintFromProofValue() {

}

// cert calculate fingerprint of the certificate
// func fingerprint(cert x509.Certificate) string {
// 	fingerprint := sha3.Sum(cert.Raw)
// 	x := hex.EncodeToString(fingerprint) // to make sure it's a hex string
// 	log.Print(x)
// 	return x
// }

// extracts proof data from the certificate then verifies if the proof is correct
// TODO: tidy up
func processCertificate(path string) bool {

	certFile, e := os.ReadFile(path)
	if e != nil {
		panic("Could not load certificate.")
	}
	cpb, _ := pem.Decode(certFile)
	crt, e := x509.ParseCertificate(cpb.Bytes)
	extensions := crt.Extensions
	for _, elem := range extensions {
		log.Print(elem.Id)
		if elem.Id.String() == firstId {
			log.Print("found needed extension")
		}

	}
	// log.Print(extensions)
	a := extensions[1]
	b := a.Value

	// a2 := extensions[2]
	// b2 := a2.Value

	h := sha3.New256()
	h.Write([]byte(crt.DNSNames[0]))
	key := h.Sum(nil)

	certRoot := b[1 : 1+32] //Magic nubmers, should be parsed properly
	certProof := b[33:]

	return AnotherNewVerifyProof(key, certProof, certRoot)
}

// verifies key in the urkel tree with a given proof against a given root
func AnotherNewVerifyProof(key, proof, root []byte) bool {
	proofLen := C.size_t(len(proof))
	var exists C.int
	value := make([]byte, len(proof))
	log.Print(hex.EncodeToString(value))
	var valueLen C.size_t

	intres := C.urkel_verify(
		&exists,
		(*C.uchar)(&value[0]),
		&valueLen,
		(*C.uchar)(&proof[0]),
		proofLen,
		(*C.uchar)(&key[0]),
		(*C.uchar)(&root[0]))

	log.Print(hex.EncodeToString(value))

	if intres == 1 {
		return true
	} else {
		return false
	}
}

func VerifyFile(filename string) {
	// key, _ := hex.DecodeString("72921db7a1c32240181397074cead573a9427ce434644b2452336483aaa3d369")
	// proof, _ := hex.DecodeString("19c01900000000002b97a9aef8b85fe170022abe6380d4a76f7ab074132225b0c4717b2a5c7c71a2b21a8ac9be594216293682d5114df6d6c4d2598004e0575e1fa1f13a58a76cd46b357121e540e284d7595fadf915959d4616230ce5d022effd155ecc909325b228d0f07c94cd3a7423f5051d6354db5b386ebc43b429f3f1d430beed26e36ef2295063d80a4da9a954375685752e1a17968f70b344a39cb96f58ac423036ae87f1c291b8209c888183a5b895218d182709d42efe27c49831bbe8251c128d4d4b8535614bb2921d74d15bad40a08c3bafaf2b188c849574a7b1d46f3047ef4df74c1997fb793b32c0415adc667bf5aeac3498331dc999895d37493ebdeb015bcaf823a531b9484ef4bd8c50327cf6dc6a02af7f6211bce70d74d867e8fdae9fe0a503e5452c2ff2d478a892a3166a9344ecf497989e7e47a0093b89695923e4a9342a38f22ed9bf48d8b3d1620e539338d8d8b9304c6be533af3b6502f933e3f5b7e02db689f6b71b972d2e0fa9fea637d56b760c82331356117f8a686ae8081f27b1482059801efc959f85f4b935f4de9cb65106bd5ae654ff3377088af350f74b856dda5e7c26d7d5297fe27c0cb085e3c26e8fa5702253f9a68c6d3107cf77dcba8b18d9491e25ef49ae883128c58ea626b2d9d8e583c2e4a382f56da163d4c4a0e72770b79aa9d3950cbab13e43bbcd8af056f2c5fc63ce13a2fab43ef3e0826c305fd82c86360558f96df28252bde7a0437e7875ed868dc538c8f6994078b44ec0a2378a0cbefb13fac5fb72377a0110d4d93d146f4b34d282d442833f6cafddb5ec7016702ef2803af0ce2969b23411c63aea8939478f227e7f53143285c12ee7bb98efc9689d756c4abbc9e82025c0f3f390f9ebd8e6885e224d01a265c16e8b849aef6e3830663fa12cf4bd2713d2d20d705e5eff05322e72d99f793066aa0441e6bab48d3f9fc136f4f4f344903c1bd190de4cf234b22a1833f4718f43f52c6d779afc9313c0d415e5f5c96b29f3a4ee7548d13cff3d871bd73829f591dbdc0e2669332283f1f12938438497d89d4484ab48502cc36b5fa47583990468182ffe35f07e87ef0a0b53dbf170b9c3ef73e794746f0832a1f06bfca049c22c01087468657368616b65f0000001036e73310568736875620006012d664138674a434f66426152657372704b2b2f4834714e4d7766464d33374862614f505a506355436d326453636f06012f63617074696f6e3d41207075626c69636174696f6e206f6e2048616e647368616b6520616e64207468652044576562060113747769747465723d446f745468655368616b650601276176617461723d68747470733a2f2f692e6172786975732e696f2f62656136383865352e6a706700637b0d0220bb52dd623f328bc52febf65fd8db0421a7ffcb46685c16bf1894cc15815f0eba01036e7332c006060111736869656c643d3136302c2037392c203420790000bce90100c500af89a565a8971fec08a7f3871a7fed2aa91a03120edf5d83b807b41a0a1379cd00fe40420f0001")
	// root, _ := hex.DecodeString("bcd2df276a4aa7c81bacecd09d713970776d9f364e7fcca317385e4711b6812d")
	// res := AnotherNewVerifyProof(key, proof, root)
	res := processCertificate(filename)
	log.Print(res)
}
