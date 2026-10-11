package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	cmtjson "github.com/cometbft/cometbft/libs/json"
	cmtclient "github.com/cometbft/cometbft/rpc/client"
	cmthttp "github.com/cometbft/cometbft/rpc/client/http"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/std"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	coretypes "github.com/sourcenetwork/acp_core/pkg/types"
	vera "github.com/sourcenetwork/vera/sdk"
	"github.com/sourcenetwork/vera/x/acp/did"
	acp "github.com/sourcenetwork/vera/x/acp/types"
	"google.golang.org/grpc"
)

type sequenceAccount struct {
	authtypes.QueryClient
	account authtypes.BaseAccount
}

func (a *sequenceAccount) Account(_ context.Context, req *authtypes.QueryAccountRequest, _ ...grpc.CallOption) (*authtypes.QueryAccountResponse, error) {
	if req.Address != a.account.Address {
		return nil, fmt.Errorf("unexpected signer address")
	}
	packed, err := codectypes.NewAnyWithValue(&a.account)
	return &authtypes.QueryAccountResponse{Account: packed}, err
}

type observation struct {
	Owner     string  `json:"owner"`
	Index     int     `json:"index"`
	Object    string  `json:"object"`
	Status    string  `json:"status"`
	Hash      string  `json:"hash,omitempty"`
	Height    int64   `json:"height,omitempty"`
	LatencyMS float64 `json:"certified_execution_ms"`
	Error     string  `json:"error,omitempty"`
}

type lane struct {
	owner   string
	signer  vera.TxSigner
	account *sequenceAccount
	builder vera.TxBuilder
}

type job struct {
	index   int
	arrival time.Time
}

func confirm(ctx context.Context, rpc cmtclient.Client, chain string, vals *cmttypes.ValidatorSet, hash []byte, capture string) (int64, uint32, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		tx, err := rpc.Tx(ctx, hash, true)
		if err == nil {
			height, after := tx.Height, tx.Height+1
			current, e1 := rpc.Commit(ctx, &height)
			next, e2 := rpc.Commit(ctx, &after)
			results, e3 := rpc.BlockResults(ctx, &height)
			if e1 == nil && e2 == nil && e3 == nil {
				if err = verifyExecution(chain, vals, hash, tx, current, next, results); err != nil {
					return 0, 0, fmt.Errorf("invalid evidence: %w", err)
				}
				if capture != "" {
					data, err := cmtjson.Marshal(evidence{tx, current, next, results})
					if err != nil {
						return 0, 0, err
					}
					file, err := os.OpenFile(capture, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
					if err != nil {
						return 0, 0, err
					}
					_, writeErr := io.Copy(file, bytes.NewReader(data))
					closeErr := file.Close()
					if writeErr != nil {
						return 0, 0, writeErr
					}
					if closeErr != nil {
						return 0, 0, closeErr
					}
				}
				return height, results.TxsResults[tx.Index].Code, nil
			}
		}
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

func objectID(prefix string, index int) string {
	if prefix == "" {
		return fmt.Sprint(index)
	}
	return fmt.Sprintf("%s-%d", prefix, index)
}

func run() error {
	root := flag.String("network", "", "private four-validator fixture directory")
	policy := flag.String("policy", "", "existing policy ID")
	prefix := flag.String("prefix", "", "optional unique object prefix; empty uses numeric IDs")
	workers := flag.Int("workers", 4, "pre-funded signing accounts")
	capture := flag.String("verification-evidence", "", "new private file for one verified execution proof")
	count := flag.Int("count", 100, "offered registrations")
	rate := flag.Int("rate", 10, "offered registrations per second")
	max := flag.Int("outstanding", 256, "maximum outstanding workflows")
	timeout := flag.Duration("deadline", 90*time.Second, "per-workflow confirmation deadline")
	flag.Parse()
	if *root == "" || *policy == "" || *count < 1 || *count > 100000 || *rate < 1 || *rate > 10000 || *max < 1 || *max > 1024 || *timeout <= 0 || *workers < 1 || *workers > *count || *workers > 1024 {
		return fmt.Errorf("invalid workload arguments")
	}
	chain, vals, err := genesisTrust(filepath.Join(*root, "node0/verad/config/genesis.json"))
	if err != nil {
		return err
	}
	client, err := vera.NewClient(vera.WithCometRPCAddr("http://127.0.0.1:28657"), vera.WithGRPCAddr("127.0.0.1:28090"))
	if err != nil {
		return err
	}
	defer client.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 64
	transport.MaxIdleConnsPerHost = 64
	transport.MaxConnsPerHost = 64
	defer transport.CloseIdleConnections()
	rpcClient, err := cmthttp.NewWithClient("http://127.0.0.1:28657", "/websocket", &http.Client{Transport: transport, Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*count)*time.Second/time.Duration(*rate)+*timeout+30*time.Second)
	defer cancel()
	registry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(registry)
	lanes := make([]lane, *workers)
	for i := range lanes {
		ring, err := keyring.New("vera", keyring.BackendTest, filepath.Join(*root, "workers"), nil, codec.NewProtoCodec(registry))
		if err != nil {
			return err
		}
		signer, err := vera.NewTxSignerFromKeyringKey(ring, fmt.Sprintf("worker%d", i))
		if err != nil {
			return err
		}
		response, err := client.AuthQueryClient().Account(ctx, &authtypes.QueryAccountRequest{Address: signer.GetAccAddress()})
		if err != nil {
			return err
		}
		account := &sequenceAccount{QueryClient: client.AuthQueryClient()}
		if response.Account == nil || response.Account.TypeUrl != "/cosmos.auth.v1beta1.BaseAccount" {
			return fmt.Errorf("expected base signer account")
		}
		if err = account.account.Unmarshal(response.Account.Value); err != nil {
			return err
		}
		builder, err := vera.NewTxBuilder(vera.WithChainID(chain), vera.WithAuthQueryClient(account), vera.WithMicroCredit(), vera.WithGasLimit(200000), vera.WithFeeAmount(2000))
		if err != nil {
			return err
		}
		ownerAccount := account.account
		if err := ownerAccount.SetPubKey(signer.GetPrivateKey().PubKey()); err != nil {
			return err
		}
		owner, err := did.IssueDID(&ownerAccount)
		if err != nil {
			return err
		}
		lanes[i] = lane{owner: owner, signer: signer, account: account, builder: builder}
	}
	signingStart := time.Now()
	prepared := make([][]byte, *count)
	for index := range prepared {
		l := &lanes[index%len(lanes)]
		msg := acp.NewMsgDirectPolicyCmd(l.signer.GetAccAddress(), *policy, acp.NewRegisterObjectCmd(coretypes.NewObject("file", objectID(*prefix, index))))
		tx, err := l.builder.BuildFromMsgs(ctx, l.signer, msg)
		if err != nil {
			return err
		}
		prepared[index], err = authtx.DefaultTxEncoder()(tx)
		if err != nil {
			return err
		}
		l.account.account.Sequence++
	}
	fmt.Fprintf(os.Stderr, "signing_seconds=%.6f\n", time.Since(signingStart).Seconds())

	var outputMu sync.Mutex
	encoder := json.NewEncoder(os.Stdout)
	failed, completed := 0, 0
	var outputErr error
	emit := func(row observation) {
		outputMu.Lock()
		defer outputMu.Unlock()
		if row.Status == "completed" {
			completed++
		} else {
			failed++
		}
		if err := encoder.Encode(row); err != nil {
			outputErr = err
		}
	}
	permits := make(chan struct{}, *max)
	queues := make([]chan job, len(lanes))
	var senders, workflows sync.WaitGroup
	start := time.Now()
	for i := range lanes {
		queues[i] = make(chan job, *max)
		senders.Add(1)
		go func(l *lane, queue <-chan job) {
			defer senders.Done()
			stopped := false
			for work := range queue {
				row := observation{Owner: l.owner, Index: work.index, Object: objectID(*prefix, work.index), Status: "not_sent"}
				finish := func() {
					row.LatencyMS = float64(time.Since(work.arrival)) / float64(time.Millisecond)
					emit(row)
					<-permits
					workflows.Done()
				}
				if stopped {
					row.Error = "signer lane stopped after failed submission"
					finish()
					continue
				}
				requestCtx, requestCancel := context.WithDeadline(ctx, work.arrival.Add(*timeout))
				encoded := prepared[work.index]
				hash := cmttypes.Tx(encoded).Hash()
				row.Hash = hex.EncodeToString(hash)
				response, err := rpcClient.BroadcastTxSync(requestCtx, encoded)
				if err != nil {
					requestCancel()
					row.Status = "unknown"
					row.Error = err.Error()
					stopped = true
					finish()
					continue
				}
				if response.Code != 0 {
					requestCancel()
					row.Status = "rejected"
					row.Error = response.Log
					stopped = true
					finish()
					continue
				}
				go func(row observation, work job) {
					defer workflows.Done()
					defer func() { <-permits }()
					defer requestCancel()
					proof := ""
					if work.index == 0 {
						proof = *capture
					}
					height, code, err := confirm(requestCtx, rpcClient, chain, vals, hash, proof)
					row.Height = height
					row.Status = "completed"
					if err != nil {
						row.Status = "unconfirmed"
						row.Error = err.Error()
					} else if code != 0 {
						row.Status = "reverted"
						row.Error = fmt.Sprintf("committed execution code %d", code)
					}
					row.LatencyMS = float64(time.Since(work.arrival)) / float64(time.Millisecond)
					emit(row)
				}(row, work)
			}
		}(&lanes[i], queues[i])
	}
	for index := 0; index < *count; index++ {
		arrival := start.Add(time.Duration(index) * time.Second / time.Duration(*rate))
		timer := time.NewTimer(time.Until(arrival))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		work := job{index, arrival}
		if ctx.Err() != nil {
			emit(observation{Index: index, Object: objectID(*prefix, index), Status: "not_sent", Error: ctx.Err().Error()})
			continue
		}
		select {
		case permits <- struct{}{}:
			workflows.Add(1)
			queues[index%len(lanes)] <- work
		default:
			emit(observation{Index: index, Object: objectID(*prefix, index), Status: "not_sent", Error: "outstanding workflow limit"})
		}
	}
	for _, queue := range queues {
		close(queue)
	}
	senders.Wait()
	workflows.Wait()
	seconds := time.Since(start).Seconds()
	fmt.Fprintf(os.Stderr, "offered=%d completed=%d failed=%d duration_seconds=%.6f completed_per_second=%.6f\n", *count, completed, failed, seconds, float64(completed)/seconds)
	if outputErr != nil {
		return outputErr
	}
	if failed != 0 {
		return fmt.Errorf("%d workflows did not complete successfully", failed)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
