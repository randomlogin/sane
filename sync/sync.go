package sync

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"
)

type Roots struct {
	Updated   int64   `json:"updated_at"`
	TreeRoots []Bytes `json:"tree_roots"`
}

// const updateInterval = 100
const treeRootsCount = 2 // how many latest roots to store, should be 40
const treeUpdateBlockLength = 36
const fileName = "tree_roots.json"
const updateInterval = 24 * 3600 * time.Second

// TODO check if there is more than a week between sync then fail lookup
// have a flag to override this failing behaviour
// reads local file and get Roots object from it
func readStoredRoots(filepath string) {
	fileContent, err := os.ReadFile(filepath)
	if err != nil {
		log.Fatal(err)
	}

	var roots Roots
	err = json.Unmarshal(fileContent, &roots)
	if err != nil {
		log.Fatal(err)
	}
}

//i need a fucntion which will get a tree root from certificate and look if i have
//this tree root and if so then check proof for it

func SyncRoots(nodeURL, apiKey, myfilepath string) {
	// myfilepath := filepath.Join(dirpath, fileName)
	// updateInterval, err := strconv.Atoi(os.Getenv("UPDATE_DB_INTERVAL"))
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// var nodeURL "http://127.0.0.1:12037"
	// var apiKey = "xxx"

	// nc := node.NewClient(os.Getenv("NODE_API_ORIGIN"), os.Getenv("NODE_API_KEY"))
	nc := NewClient(nodeURL, apiKey)

	var roo Roots
	for {
		height, err := nc.GetBlocksHeight(context.Background())
		if err != nil {
			log.Println("err", err)
			time.Sleep(time.Second) //TODO return to outer loop
		}

		//TODO: verify proof of work of the blocks, maybe add it to what i store
		//TODO: think what should i get first: timestamp or blocks in case there will be a new block when i query the old
		//ones and treeroot change occurs in this block
		for i := 0; i < treeRootsCount; i++ {
			blockHeight := height - (i * treeUpdateBlockLength)
			log.Printf("Processing block %d", blockHeight)

			//TODO: ensure that there are enough blocks
			block, err := nc.GetBlockByHeight(context.Background(), blockHeight)
			if err != nil {
				log.Println("err", err)
				time.Sleep(time.Second)
			}
			roo.TreeRoots = append(roo.TreeRoots, block.TreeRoot)
			// log.Printf("%+v", block)
		}

		currentTimestamp := time.Now().Unix()
		roo.Updated = currentTimestamp
		myjson, _ := json.Marshal(roo)

		if err := os.WriteFile(myfilepath, myjson, 0777); err != nil {
			log.Fatal(err)
		}

		log.Print("Successfully updated tree roots.")

		time.Sleep(updateInterval)
	}
}
