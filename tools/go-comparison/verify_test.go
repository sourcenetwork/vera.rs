package main

import (
	"os"
	"path/filepath"
	"testing"

	cmtjson "github.com/cometbft/cometbft/libs/json"
)

func TestCertifiedExecution(t *testing.T) {
	root := os.Getenv("VERA_GO_EVIDENCE")
	genesis := os.Getenv("VERA_GO_GENESIS")
	if root == "" || genesis == "" {
		t.Fatal("VERA_GO_EVIDENCE and VERA_GO_GENESIS are required")
	}
	chain, vals, err := genesisTrust(genesis)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*evidence)
		valid  bool
	}{
		{"valid signed execution", func(*evidence) {}, true},
		{"forged receipt success", func(e *evidence) { e.Tx.TxResult.Code++ }, false},
		{"forged committed result", func(e *evidence) { e.Results.TxsResults[e.Tx.Index].Code++ }, false},
		{"wrong result height", func(e *evidence) { e.Results.Height++ }, false},
		{"changed result data", func(e *evidence) { e.Results.TxsResults[e.Tx.Index].Data = []byte("forged") }, false},
		{"changed proof root", func(e *evidence) { e.Tx.Proof.RootHash[0] ^= 1 }, false},
		{"uncommitted log is not trusted", func(e *evidence) { e.Tx.TxResult.Log = "not certified" }, true},
		{"wrong transaction index", func(e *evidence) { e.Tx.Index++ }, false},
		{"wrong transaction bytes", func(e *evidence) { e.Tx.Tx[0] ^= 1 }, false},
		{"missing result", func(e *evidence) { e.Results.TxsResults[e.Tx.Index] = nil }, false},
		{"wrong signer set", func(e *evidence) { e.Current.ValidatorsHash[0] ^= 1 }, false},
		{"invalid signatures", func(e *evidence) {
			for i := range e.Next.Commit.Signatures {
				if len(e.Next.Commit.Signatures[i].Signature) > 0 {
					e.Next.Commit.Signatures[i].Signature[0] ^= 1
				}
			}
		}, false},
		{"broken header link", func(e *evidence) { e.Next.LastBlockID.Hash[0] ^= 1 }, false},
		{"wrong network", func(e *evidence) { e.Current.ChainID = "another-network" }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var e evidence
			if err := cmtjson.Unmarshal(raw, &e); err != nil {
				t.Fatal(err)
			}
			expected := append([]byte(nil), e.Tx.Hash...)
			test.mutate(&e)
			err := verifyExecution(chain, vals, expected, e.Tx, e.Current, e.Next, e.Results)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}
