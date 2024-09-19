package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/buffrr/hsig0"
	"github.com/miekg/dns"
	sane "github.com/randomlogin/sane"
	rs "github.com/randomlogin/sane/resolver"
	"github.com/randomlogin/sane/sync"
	"github.com/randomlogin/sane/tld"
)

const KSK2017 = `. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D`

var (
	raddr              = flag.String("r", "", "dns resolvers to use (default: /etc/resolv.conf)")
	output             = flag.String("o", "", "path to export the public CA file")
	conf               = flag.String("conf", "", "dir path to store configuration (default: ~/.sane)")
	addr               = flag.String("addr", ":8080", "host:port of the proxy")
	certPath           = flag.String("cert", "", "filepath to custom CA")
	keyPath            = flag.String("key", "", "filepath to the CA's private key")
	pass               = flag.String("pass", "", "CA passphrase or use DANE_CA_PASS environment variable to decrypt CA file (if encrypted)")
	anchor             = flag.String("anchor", "", "path to trust anchor file (default: hardcoded 2017 KSK)")
	hsd                = flag.String("hsd", "", "url to the prefered hsd node")
	verbose            = flag.Bool("verbose", false, "verbose output for debugging")
	skipICANN          = flag.Bool("skip-icann", false, "skip TLSA lookups for ICANN tlds and include them in the CA name constraints extension")
	validity           = flag.Duration("validity", time.Hour, "window of time generated DANE certificates are valid")
	skipNameChecks     = flag.Bool("skip-namechecks", false, "disable name checks when matching DANE-EE TLSA reocrds.")
	version            = flag.Bool("version", false, "Show version")
	hnsdPath           = flag.String("hnsd", os.Getenv("HNSD_PATH"), "path to hnsd executable, also may be set as environment variable HNSD_PATH")
	hnsdCheckpointPath = flag.String("checkpoint", "", "path to hnsd checkpoint location, default ~/.hnsd")
	resyncInterval     = flag.Duration("resync-interval", 24*time.Hour, "interval for roots resyncronization")
	externalService    = flag.String("external-service", "", "uri to an external service providing SANE data, comma-separated list of URIs")
)

func getConfPath() string {
	if *conf != "" {
		return *conf
	}

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("failed to get home dir: %v", err)
	}

	p := path.Join(home, ".sane")

	if _, err := os.Stat(p); err != nil {
		if err := os.Mkdir(p, 0700); err != nil {
			log.Fatalf("failed to create conf dir: %v", err)
		}
	}

	return p
}

func getOrCreateCA() (string, string) {
	if *certPath != "" && *keyPath != "" {
		return *certPath, *keyPath
	}
	p := getConfPath()
	certPath := path.Join(p, "cert.crt")
	keyPath := path.Join(p, "cert.key")

	if _, err := os.Stat(certPath); err != nil {
		if _, err := os.Stat(keyPath); err != nil {
			ca, priv, err := sane.NewAuthority("Stateless DANE", "Stateless DANE", 365*24*time.Hour, tld.NameConstraints)
			if err != nil {
				log.Fatalf("couldn't generate CA: %v", err)
			}

			certOut, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatalf("couldn't create CA file: %v", err)
			}
			defer certOut.Close()

			pem.Encode(certOut, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: ca.Raw,
			})

			privOut := bytes.NewBuffer([]byte{})
			pem.Encode(privOut, &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(priv),
			})

			kOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				log.Fatalf("couldn't create CA private key file: %v", err)
			}
			defer kOut.Close()

			kOut.Write(privOut.Bytes())
			return certPath, keyPath
		}
	}
	return certPath, keyPath
}

func loadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	block, _ := pem.Decode(keyPEMBlock)
	var decryptedBlock []byte

	if x509.IsEncryptedPEMBlock(block) {
		if *pass == "" {
			*pass = os.Getenv("DANE_CA_PASS")
		}

		decryptedBlock, err = x509.DecryptPEMBlock(block, []byte(*pass))
		if err != nil {
			log.Fatalf("decryption failed: %v", err)
		}
	} else {
		decryptedBlock = keyPEMBlock
	}

	return tls.X509KeyPair(certPEMBlock, decryptedBlock)
}

func loadCA() (*x509.Certificate, interface{}) {
	var x509c *x509.Certificate
	var priv interface{}

	*certPath, *keyPath = getOrCreateCA()
	if *certPath != "" && *keyPath != "" {
		cert, err := loadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			log.Fatal(err)
		}

		priv = cert.PrivateKey
		x509c, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}

		return x509c, priv
	}

	return nil, nil
}

func isLoopback(r string) bool {
	var ip net.IP
	host, _, err := net.SplitHostPort(r)

	if err == nil {
		ip = net.ParseIP(host)
	} else {
		ip = net.ParseIP(r)
	}

	return ip != nil && ip.IsLoopback()
}

func exportCA() {
	b, err := os.ReadFile(*certPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(*output, b, 0600); err != nil {
		log.Fatal(err)
	}
}

var errNoKey = errors.New("no key found")

// parses hsd format: key@host:port
func splitHostPortKey(addr string) (hostport string, key *hsig0.PublicKey, err error) {
	s := strings.Split(strings.TrimSpace(addr), "@")
	if len(s) != 2 {
		return "", nil, errNoKey
	}

	hostport = s[1]
	key, err = hsig0.ParsePublicKey(s[0])
	return
}

func main() {

	flag.Parse()
	p := getConfPath()
	if *version {
		fmt.Printf("Version %s\n", sane.Version)
		return
	}

	services := strings.Split(*externalService, ",")

	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	if *hnsdPath == "" {
		log.Fatal("path to hnsd is not provided")
	}

	ctx := context.Background()
	sync.GetRoots(ctx, *hnsdPath, p, *hnsdCheckpointPath)
	go func() {
		for {
			time.Sleep(*resyncInterval)
			sync.GetRoots(ctx, *hnsdPath, p, *hnsdCheckpointPath)
		}
	}()

	if !*skipICANN {
		tld.NameConstraints = nil
	}

	ca, priv := loadCA()
	if *output != "" {
		exportCA()
		return
	}

	var resolver rs.Resolver
	var sig0 bool

	hostport, key, err := splitHostPortKey(*raddr)
	switch err {
	case errNoKey:
		sig0 = false
	case nil:
		sig0 = true
		*raddr = hostport
	default:
		log.Fatal(err)
	}

	ad, err := rs.NewStub(*raddr)
	if err != nil {
		log.Fatal(err)
	}
	if sig0 {
		ad.Verify = func(m *dns.Msg) error {
			return hsig0.Verify(m, key)
		}
	}
	resolver = ad

	c := &sane.Config{
		Certificate:     ca,
		PrivateKey:      priv,
		Validity:        *validity,
		Resolver:        resolver,
		Constraints:     tld.NameConstraints,
		SkipNameChecks:  *skipNameChecks,
		Verbose:         *verbose,
		RootsPath:       path.Join(p, "roots.json"),
		ExternalService: services,
	}
	log.Printf("Listening on %s", *addr)
	log.Fatal(c.Run(*addr))
}
