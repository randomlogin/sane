package sync

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	BlocksToStore  = 40
	dnsServer      = "127.0.0.1"
	dnsPort        = "5350"
	dnsAddress     = dnsServer + ":" + dnsPort
	qtype          = "TXT"
	qclass         = "HS"
	qname          = "synced.chain.hnsd"
	timeToNotify   = 2
	secondsForHNSD = 5
)

var (
	rootsFileName = "roots.json"
)

func CheckHNSDVersion() error {
	qname := "chain.hnsd"

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.StringToType[qtype])
	msg.SetEdns0(4096, true)
	msg.Question[0].Qclass = dns.StringToClass[qclass]

	client := new(dns.Client)
	response, _, err := client.Exchange(msg, dnsAddress)
	if err != nil {
		return err
	}

	if len(response.Answer) > 0 {
		for _, x := range response.Answer {
			n := x.Header().Name
			if n == "name_root.tip.chain.hnsd." {
				return nil
			}
		}
	}
	return fmt.Errorf("name_root is not output by hnsd")
}

// checks if hnsd has synced all blocks in order to kill the subprocess
// does it by invoking hesiod DNS request which
// TODO export params
func checkIfSynced() (bool, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.StringToType[qtype])
	msg.SetEdns0(4096, true)
	msg.Question[0].Qclass = dns.StringToClass[qclass]

	client := new(dns.Client)
	response, _, err := client.Exchange(msg, dnsAddress)
	if err != nil {
		return false, fmt.Errorf("DNS query failed: %v", err)
	}

	if len(response.Answer) > 0 {
		if txtRecord, ok := response.Answer[0].(*dns.TXT); ok {
			if txtRecord.Txt[0] == "true" {
				return true, nil
			}
		}
	} else {
		return false, errors.New("No answer in the DNS response")
	}

	return false, nil
}

func GetRoots(pathToExecutable string, confPath string, pathToCheckpoint string) {
	if pathToCheckpoint == "" {
		home, _ := os.UserHomeDir() //above already fails if it doesn't exist
		pathToCheckpoint = path.Join(home, ".hnsd")
	}
	if err := os.MkdirAll(pathToCheckpoint, 0777); err != nil {
		log.Fatalf("error creating directory at %s : %s", pathToCheckpoint, err)
	}

	//writes the empty array for the sync time
	rootPath := path.Join(confPath, rootsFileName)
	if _, err := os.Stat(rootPath); os.IsNotExist(err) {
		if err := os.WriteFile(rootPath, []byte("[]"), 0644); err != nil {
			log.Fatal(err)
		}
	} else if err != nil {
		log.Fatal(err)
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
	if err := cmd.Start(); err != nil {
		log.Fatalf("Error starting command: %v", err)
	}

	time.Sleep(100 * time.Millisecond) //0.1 second should suffice for the most of the computers
	for i := 1; i <= secondsForHNSD; i++ {
		if err := CheckHNSDVersion(); err == nil {
			break
		}
		if i == secondsForHNSD {
			cancel()
			log.Fatalf("hnsd version is not compatible with SANE or cannot be run properly: %v", err)
		}
		time.Sleep(1000 * time.Millisecond) //time hnsd needs to start running
	}

	slidingWindow := make([]BlockInfo, 0, BlocksToStore)

	// Run a goroutine to handle process termination and write to file
	go func() {
		var isSynced bool
		for {
			if !isSynced {
				log.Printf("Waiting %d seconds to finish the synchronization of tree roots.", timeToNotify)
				time.Sleep(timeToNotify * time.Second)
				isSynced, err = checkIfSynced()
				if err != nil {
					log.Printf("Error checking synchronization: %v", err)
				}
			}

			if cmd.Process != nil && isSynced {
				// if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
				if err := cmd.Process.Kill(); err != nil {
					log.Fatal("Error killing hnsd: ", err)
				}

				if _, err := cmd.Process.Wait(); err != nil {
					log.Fatal("Error waiting hnsd ", err)
				}
				log.Print("Successfully synced last tree roots")
				break
			}
		}
		signalChannel <- syscall.SIGINT
		return
	}()

	parseAndWriteOutput(stdoutPipe, signalChannel, slidingWindow, rootPath)
}

func parseAndWriteOutput(stdoutPipe io.ReadCloser, signalChannel chan os.Signal, slidingWindow []BlockInfo, rootPath string) {
	scanner := bufio.NewScanner(stdoutPipe)
	re := regexp.MustCompile(`chain \((\d+)\): tree_root ([a-fA-F0-9]+) timestamp (\d+)`)
	rejectRe := regexp.MustCompile(`chain \((\d+)\): +rejected:`)

	var tempBlock *BlockInfo

	for {
		select {
		case <-signalChannel:
			myjson, _ := json.Marshal(slidingWindow)
			if err := os.WriteFile(rootPath, myjson, 0777); err != nil {
				log.Fatal(err)
			}
			return
		default:
			for scanner.Scan() {
				line := scanner.Text()

				if rejectMatch := rejectRe.FindStringSubmatch(line); len(rejectMatch) >= 2 {
					if tempBlock != nil {
						tempBlock = nil // Discard the tempBlock as it has been rejected
					}
					continue
				}

				// Check for tree_root line
				if match := re.FindStringSubmatch(line); len(match) >= 4 {
					blockNumber, err := strconv.ParseUint(match[1], 10, 32)
					if err != nil {
						log.Printf("failed to parse block height: %v", err)
						continue
					}
					timestamp, err := strconv.ParseUint(match[3], 10, 64)
					if err != nil {
						log.Printf("failed to parse timestamp: %v", err)
						continue
					}
					treeRoot := match[2]

					// if there's a tempBlock already, add it to the slidingWindow
					if tempBlock != nil && !contains(slidingWindow, tempBlock.TreeRoot) {
						slidingWindow = append(slidingWindow, *tempBlock)
						if len(slidingWindow) > BlocksToStore {
							slidingWindow = slidingWindow[1:]
						}
					}
					tempBlock = &BlockInfo{
						Height:    uint32(blockNumber),
						Timestamp: timestamp,
						TreeRoot:  treeRoot,
					}
				}
			}
			//add last block
			if !scanner.Scan() && tempBlock != nil {
				slidingWindow = append(slidingWindow, *tempBlock)
				if len(slidingWindow) > BlocksToStore {
					slidingWindow = slidingWindow[1:]
				}
			}

		}
	}

}
