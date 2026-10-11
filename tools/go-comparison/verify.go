package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	rpctypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
)

// This fixture has four equally staked validators and no membership changes.
// Trust comes from the local genesis, never the RPC server's validator response.
type evidence struct {
	Tx      *rpctypes.ResultTx           `json:"tx"`
	Current *rpctypes.ResultCommit       `json:"current"`
	Next    *rpctypes.ResultCommit       `json:"next"`
	Results *rpctypes.ResultBlockResults `json:"results"`
}

func genesisTrust(path string) (string, *cmttypes.ValidatorSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var genesis struct {
		ChainID  string `json:"chain_id"`
		AppState struct {
			Genutil struct {
				Txs []struct {
					Body struct {
						Messages []struct {
							Type   string `json:"@type"`
							PubKey struct {
								Type string `json:"@type"`
								Key  string `json:"key"`
							} `json:"pubkey"`
							Value struct {
								Denom  string `json:"denom"`
								Amount string `json:"amount"`
							} `json:"value"`
						} `json:"messages"`
					} `json:"body"`
				} `json:"gen_txs"`
			} `json:"genutil"`
		} `json:"app_state"`
	}
	if err = json.Unmarshal(data, &genesis); err != nil {
		return "", nil, err
	}
	vals := make([]*cmttypes.Validator, 0, 4)
	seen := map[string]bool{}
	for _, tx := range genesis.AppState.Genutil.Txs {
		if len(tx.Body.Messages) != 1 {
			return "", nil, fmt.Errorf("unexpected genesis messages")
		}
		msg := tx.Body.Messages[0]
		key, err := base64.StdEncoding.DecodeString(msg.PubKey.Key)
		amount, parseErr := strconv.ParseInt(msg.Value.Amount, 10, 64)
		if err != nil || parseErr != nil || len(key) != ed25519.PubKeySize || seen[string(key)] || msg.Type != "/cosmos.staking.v1beta1.MsgCreateValidator" || msg.PubKey.Type != "/cosmos.crypto.ed25519.PubKey" || msg.Value.Denom != "uopen" || amount != 100000000 {
			return "", nil, fmt.Errorf("unexpected genesis validator")
		}
		seen[string(key)] = true
		vals = append(vals, cmttypes.NewValidator(ed25519.PubKey(key), 100))
	}
	if len(vals) != 4 || genesis.ChainID == "" {
		return "", nil, fmt.Errorf("expected four genesis validators")
	}
	return genesis.ChainID, cmttypes.NewValidatorSet(vals), nil
}

func verifyHeader(chain string, vals *cmttypes.ValidatorSet, commit *rpctypes.ResultCommit, height int64) error {
	if commit == nil || commit.Header == nil || commit.Commit == nil {
		return fmt.Errorf("missing signed header")
	}
	if err := commit.SignedHeader.ValidateBasic(chain); err != nil {
		return err
	}
	if commit.Height != height || !bytes.Equal(commit.ValidatorsHash, vals.Hash()) || !bytes.Equal(commit.NextValidatorsHash, vals.Hash()) {
		return fmt.Errorf("height or validator set differs from static fixture")
	}
	return vals.VerifyCommitLight(chain, commit.Commit.BlockID, height, commit.Commit)
}

func verifyExecution(chain string, vals *cmttypes.ValidatorSet, expected []byte, tx *rpctypes.ResultTx, current, next *rpctypes.ResultCommit, results *rpctypes.ResultBlockResults) error {
	if tx == nil || tx.Height < 1 || results == nil {
		return fmt.Errorf("missing transaction evidence")
	}
	if err := verifyHeader(chain, vals, current, tx.Height); err != nil {
		return err
	}
	if err := verifyHeader(chain, vals, next, tx.Height+1); err != nil {
		return err
	}
	if !bytes.Equal(next.LastBlockID.Hash, current.Header.Hash()) {
		return fmt.Errorf("headers are not adjacent")
	}
	if !bytes.Equal(tx.Tx.Hash(), expected) || !bytes.Equal(tx.Hash, expected) || !bytes.Equal(tx.Proof.Data, tx.Tx) || int64(tx.Index) != tx.Proof.Proof.Index {
		return fmt.Errorf("transaction binding mismatch")
	}
	if err := tx.Proof.Validate(current.DataHash); err != nil {
		return err
	}
	if results.Height != tx.Height || uint64(tx.Index) >= uint64(len(results.TxsResults)) || int64(len(results.TxsResults)) != tx.Proof.Proof.Total {
		return fmt.Errorf("execution result index mismatch")
	}
	for _, result := range results.TxsResults {
		if result == nil {
			return fmt.Errorf("missing execution result")
		}
	}
	deterministic := cmttypes.NewResults(results.TxsResults)
	if !bytes.Equal(deterministic.Hash(), next.LastResultsHash) {
		return fmt.Errorf("execution commitment mismatch")
	}
	if !bytes.Equal(cmttypes.NewResults([]*abci.ExecTxResult{&tx.TxResult}).Hash(), cmttypes.NewResults([]*abci.ExecTxResult{results.TxsResults[tx.Index]}).Hash()) {
		return fmt.Errorf("receipt differs from committed execution result")
	}
	return nil
}
