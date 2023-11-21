package prove

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/miekg/dns"
)

func main() {
	// Create a DNS message for a query
	msg2 := new(dns.Msg)
	msg2.SetQuestion("example.com.", dns.TypeA)

	// Pack the DNS message into binary format
	rawData2, err := msg2.Pack()
	if err != nil {
		log.Fatal(err)
	}

	// Print the raw binary data as hexadecimal
	fmt.Println("Raw Data (Hex):", hex.EncodeToString(rawData2))

	// Replace this with your raw DNS record data in hexadecimal format
	// rawDataHex := "087468657368616b65f0000001036e73310568736875620006012d664138674a434f66426152657372704b2b2f4834714e4d7766464d33374862614f505a506355436d326453636f06012f63617074696f6e3d41207075626c69636174696f6e206f6e2048616e647368616b6520616e64207468652044576562060113747769747465723d446f745468655368616b650601276176617461723d68747470733a2f2f692e6172786975732e696f2f62656136383865352e6a706700637b0d0220bb52dd623f328bc52febf65fd8db0421a7ffcb46685c16bf1894cc15815f0eba01036e7332c006060111736869656c643d3136302c2037392c203420790000bce90100c500af89a565a8971fec08a7f3871a7fed2aa91a03120edf5d83b807b41a0a1379cd00fe40420f0001"

	// Decode the hexadecimal data
	// rawData, err := hex.DecodeString(rawDataHex)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Print("test1")

}
