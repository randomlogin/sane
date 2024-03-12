//go:build ignore
// +build ignore

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:generate go run gen.go

func main() {
	source := "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	resp, err := http.Get(source)
	if err != nil {
		log.Fatalf("error requesting tld list: %v", err)
	}
	defer resp.Body.Close()
	var sb bytes.Buffer

	h := fmt.Sprintf(`// source: %s

var NameConstraints = map[string]struct{} {
`, source)

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line != "" && line[0] == '#' {
			sb.WriteString("package tld\n\n")
			sb.WriteString("// auto generated do not edit\n")
			sb.WriteString("//" + line[1:] + "\n")
			sb.WriteString(h)
			continue
		}

		sb.WriteString(`	"`)
		sb.WriteString(line)
		sb.WriteRune('"')
		sb.WriteString(": {}, \n")
	}
	sb.WriteString("}\n")

	path, _ := filepath.Abs("")
	last := filepath.Base(path)
	path = filepath.Dir(path)
	prelast := filepath.Base(path)
	if last != "sane" || prelast != "cmd" {
		log.Fatal(fmt.Errorf("tld list must be generated in cmd/sane directory"))
	}

	if err := os.WriteFile("../../tld/tld.go", sb.Bytes(), 0600); err != nil {
		log.Fatal(err)
	}

}
