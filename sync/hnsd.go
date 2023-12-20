package sync

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

func contains(s []BlockInfo, str string) bool {
	for _, v := range s {
		if v.TreeRoot == str {
			return true
		}
	}
	return false
}

const (
	BlocksToStore = 40
	dnsServer     = "127.0.0.1"
	dnsPort       = "5350"
	dnsAddress    = dnsServer + ":" + dnsPort
	qtype         = "TXT"
	qclass        = "HS"
	qname         = "progress.chain.hnsd"
	timeToNotify  = 2
)

var (
	rootsFileName = "roots.json"
	neededVersion = "2.99.1 (main)\n"
)

// checks if hnsd has synced all blocks in order to kill the subprocess
// does it by invoking hesoid DNS request which
// TODO export params
func checkIfSynced() (bool, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.StringToType[qtype])
	msg.SetEdns0(4096, true)

	// Set the query class
	if qclass != "" {
		msg.Question[0].Qclass = dns.StringToClass[qclass]
	}

	// Use the net package to send the DNS query with a timeout
	client := new(dns.Client)
	// client.Timeout = dnsTimeout
	response, _, err := client.Exchange(msg, dnsAddress)
	if err != nil {
		return false, fmt.Errorf("DNS query failed: %v", err)
	}

	// Check the DNS response for synchronization status
	if len(response.Answer) > 0 {
		if txtRecord, ok := response.Answer[0].(*dns.TXT); ok {
			if txtRecord.Txt[0] == "1.000000" {
				return true, nil
			}
		}
	} else {
		return false, errors.New("No answer in the DNS response")
	}

	return false, nil
}

func GetRoots(pathToExecutable string, confPath string, pathToCheckpoint string) {

	rootPath := path.Join(confPath, rootsFileName)
	checkVersion := exec.Command(pathToExecutable, "--version")
	out, err := checkVersion.Output()
	if err != nil {
		log.Fatalf("Error checking version: %v", err)
	}

	if string(out) != neededVersion {
		log.Fatalf("Wrong hnsd version. Aborting.")
	}
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, pathToExecutable, "-n", dnsAddress, "-p", "4", "-r", "127.0.0.1:12345", "-t", "-x", pathToCheckpoint)
	defer cancel()
	cmd.Stderr = os.Stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Error creating stdout pipe: %v", err)
	}

	signalChannel := make(chan os.Signal, 1)
	scanner := bufio.NewScanner(stdoutPipe)
	if err := cmd.Start(); err != nil {
		log.Fatalf("Error starting command: %v", err)
	}

	slidingWindow := make([]BlockInfo, 0, BlocksToStore)

	// Run a goroutine to handle process termination and write to file
	go func() {
		var isSynced bool
		for {
			if !isSynced {
				log.Printf("Waiting %d seconds to finish sync.", timeToNotify)
				time.Sleep(timeToNotify * time.Second)
				isSynced, err = checkIfSynced()
				if err != nil {
					log.Printf("Error checking synchronization: %v", err)
				}
			}

			if cmd.Process != nil && isSynced {
				myjson, _ := json.Marshal(slidingWindow)
				if err := os.WriteFile(rootPath, myjson, 0777); err != nil {
					log.Fatal(err)
				}
				if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
					log.Print("Error killing hnsd: ", err)
				}

				if _, err := cmd.Process.Wait(); err != nil {
					log.Print("Error waiting hnsd ", err)
				}
				log.Print("Successfully synced last tree roots")
				break
			}
		}
		signalChannel <- syscall.SIGUSR2
		return
	}()

	re := regexp.MustCompile(`chain \((\d+)\): tree_root ([a-fA-F0-9]+) timestamp (\d+)`) // Regular expression for parsing output lines

	// Process command output
	for {
		select {
		case <-signalChannel:
			// log.Print("got signal ", int(sign.(syscall.Signal)))
			return
		default:
			for scanner.Scan() {
				line := scanner.Text()
				match := re.FindStringSubmatch(line)

				if len(match) >= 4 {
					blockNumberStr, treeRoot, timestampStr := match[1], match[2], match[3]
					blockNumber, err := strconv.ParseUint(blockNumberStr, 10, 32)
					if err != nil {
						log.Printf("failed to parse block height: %v", err)
						continue
					}

					timestamp, err := strconv.ParseUint(timestampStr, 10, 64)
					if err != nil {
						log.Printf("failed to parse timestamp: %v", err)
						continue
					}

					if !contains(slidingWindow, treeRoot) {
						blockInfo := BlockInfo{
							Height:    uint32(blockNumber),
							Timestamp: timestamp,
							TreeRoot:  treeRoot,
						}

						slidingWindow = append(slidingWindow, blockInfo)
						if len(slidingWindow) > BlocksToStore {
							slidingWindow = slidingWindow[1:]
						}
					}
				}
			}
		}
	}
}