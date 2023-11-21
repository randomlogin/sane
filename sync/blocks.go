package sync

import (
	"context"
	"log"
	// "github.com/handshake-labs/blockexplorer/pkg/types"
)

type Bytes []byte
type Block struct {
	Hash           Bytes   `json:"hash"`
	PrevBlockHash  Bytes   `json:"previousblockhash"`
	Height         int32   `json:"height"`
	Weight         int32   `json:"weight"`
	Size           int64   `json:"size"`
	Version        int32   `json:"version"`
	HashMerkleRoot Bytes   `json:"merkleRoot"`
	WitnessRoot    Bytes   `json:"witnessRoot"`
	TreeRoot       Bytes   `json:"treeRoot"`
	ReservedRoot   Bytes   `json:"reservedRoot"`
	Mask           Bytes   `json:"mask"`
	Time           int32   `json:"time"`
	Bits           Bytes   `json:"bits"`
	Difficulty     float64 `json:"difficulty"`
	Chainwork      Bytes   `json:"chainwork"`
	Nonce          int64   `json:"nonce"`
	ExtraNonce     Bytes   `json:"extraNonce"`
	// Transactions   []Transaction `json:"tx"`
}

type ProofResult struct {
	Hash   string `json:"hash"`
	Height int    `json:"height"`
	Root   string `json:"root"`
	Name   string `json:"name"`
	Key    string `json:"key"`
	Proof  struct {
		Type  string      `json:"type"`
		Depth int         `json:"depth"`
		Nodes [][2]string `json:"nodes"`
		Value string      `json:"value"`
	} `json:"proof"`
}

// type NameProof

func (client *Client) GetBlockByHeight(ctx context.Context, height int) (*Block, error) {
	block := new(Block)
	err := client.rpc(ctx, "getblockbyheight", []interface{}{height, true, true}, block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (client *Client) GetNameProof(ctx context.Context, name string) (ProofResult, error) {
	var proof ProofResult
	err := client.rpc(ctx, "getnameproof", []interface{}{name, nil}, &proof)
	if err != nil {

		log.Println(err)
		// 	return -1, err
	}
	return proof, nil
}

func (client *Client) GetBlocksHeight(ctx context.Context) (int, error) {
	var height int
	err := client.rpc(ctx, "getblockcount", nil, &height)
	if err != nil {
		return -1, err
	}
	return height, nil
}
