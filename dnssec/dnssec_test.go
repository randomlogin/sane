package dnssec

import "testing"

const test_waste = "_443._tcp.www.ietf.org. TLSA 3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B56664C5D3D6"
const test_waste2 = "_443._tcp.host-dane.weberdns.de. 3066 IN RRSIG TLSA 8 5 3600 20160929094014 20160830084014 57909 weberdns.de. aZgVX1C6uxACoNnPo4m36CRzMjfe2Gk7pciV2knGrb5PHbq1UVu2EdFJD6v5Dhd4JAquuM7OW9CQVfE1f0g380HsUMzg6eZeOr3sMR2ERZXv4hut4sikdtjGhVmA6jSbfgEQFM0BELYz/+Xzh9uJYoqzkbJ54uKCpapaWgELs="

const another_waste = "weberdns.de	3600	DNSKEY	256 3 8 AwEAAb1nejZV1j3QV1Sc+e26sSNO2mOdJHaXSef+KXmquDizG8K+ZD6LKOTMzQY48025tlgm7HCIQcmXhnwe8cVYKtO0ejzxtrH01ivmZrUJJANi2mwfOlpGKjRg4sStTbv0r7h7k4Q4Nr61LE+vcvyZZ/D75GRQACyLrHZPz0cgoIL9"

const waste2 = "example.com.	3600	IN	DNSKEY	257	3	13	ZhCa3rGLofZcndFN2aVd=="
const test_waste3 = "   dskey.example.com. 86400 IN DS 60485 5 1 ( 2BB183AF5F22588179A53B0A98631FAD1A292118 )"

func TestVerifyDNSSECChain(t *testing.T) {
	t.Error("yoyo")

}
