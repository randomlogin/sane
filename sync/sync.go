package sync

import (
	"encoding/json"
	"log"
	"os"
)

type BlockInfo struct {
	Height    uint32 `json:"height"`
	Timestamp uint64 `json:"timestamp"`
	TreeRoot  string `json:"tree_root"`
}

// TODO check if there is more than a week between sync then fail lookup
// have a flag to override this failing behaviour
// reads local file and get Roots object from it
func ReadStoredRoots(filepath string) []BlockInfo {
	fileContent, err := os.ReadFile(filepath)
	if err != nil {
		log.Fatal(err)
	}

	var roots []BlockInfo
	err = json.Unmarshal(fileContent, &roots)
	if err != nil {
		log.Fatal(err)
	}

	return roots
}
