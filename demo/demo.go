package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	// To change these parameters, you must first delete the text fixture files in test/_fixtures/ and then run the keygen test alone.
	// Then the signing and resharing tests will work with the new n, t configuration using the newly written fixture files.
	TestParticipants = 6
	TestThreshold    = 2
)
const (
	testFixtureDirFormat  = "%s/_fixtures"
	testFixtureFileFormat = "keygen_data_%d.json"
)

var (
	valid_s = false
)

func makeTestFixtureFilePath(partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}

func tryWriteTestFixtureFile(index int, data keygen.LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Errorf("unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			fmt.Errorf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			fmt.Errorf("unable to write to fixture file %s", fixtureFileName)
		}
		fmt.Errorf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		fmt.Errorf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}

func getAddressUser(filename string) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error when opening file: ", err)
	}
	var payload keygen.LocalPartySaveData
	err = json.Unmarshal(content, &payload)
	if err != nil {
		fmt.Println("Error during Unmarshal(): ", err)
	}
	param := payload.ECDSAPub
	pk := ecdsa.PublicKey{
		Curve: param.Curve(),
		X:     param.X(),
		Y:     param.Y(),
	}
	publicKeyBytes := crypto.FromECDSAPub(&pk)
	fmt.Println("Address of User: ", eth_common.BytesToAddress(crypto.Keccak256(publicKeyBytes[1:])[12:]).Hex())

}

func prefixHash(data []byte) eth_common.Hash {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256Hash([]byte(msg))
}

func LoadKeygenTestFixtures(qty int, optionalStart ...int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		for _, kbxj := range key.BigXj {
			kbxj.SetCurve(tss.S256())
		}
		key.ECDSAPub.SetCurve(tss.S256())
		keys = append(keys, key)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	for i, key := range keys {
		pMoniker := fmt.Sprintf("%d", i+start+1)
		partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return keys, sortedPIDs, nil
}

func LoadKeygenTestFixturesRandomSet(qty, fixtureCount int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	plucked := make(map[int]interface{}, qty)
	for i := 0; len(plucked) < qty; i = (i + 1) % fixtureCount {
		_, have := plucked[i]
		if pluck := rand.Float32() < 0.5; !have && pluck {
			plucked[i] = new(struct{})
		}
	}
	for i := range plucked {
		fixtureFilePath := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		for _, kbxj := range key.BigXj {
			kbxj.SetCurve(tss.S256())
		}
		key.ECDSAPub.SetCurve(tss.S256())
		keys = append(keys, key)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	j := 0
	for i := range plucked {
		key := keys[j]
		pMoniker := fmt.Sprintf("%d", i+1)
		partyIDs[j] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
		j++
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ShareID.Cmp(keys[j].ShareID) == -1 })

	return keys, sortedPIDs, nil
}

func testDistibutedKeyGeneration() {
	testThreshold := TestThreshold
	testParticipants := TestParticipants

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan keygen.LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *keygen.LocalParty
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), testThreshold)
		if i < len(fixtures) {
			P = keygen.NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*keygen.LocalParty)
		} else {
			P = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
		}
		parties = append(parties, P)
		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)

	}

	// PHASE: keygen
	var ended int32
keygen:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					fmt.Errorf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, _ := save.OriginalIndex()
			tryWriteTestFixtureFile(index, save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				fmt.Printf("Done. Received save data from %d participants \n", ended)
				fmt.Printf("Start goroutines: %d, End goroutines: %d \n", startGR, runtime.NumGoroutine())

				break keygen

			}
		}
	}
	getAddressUser(filepath.Join("_fixtures", "keygen_data_1.json"))

}

func testDistibutedSigning(message eth_common.Hash) {
	testThreshold := TestThreshold
	testParticipants := TestParticipants

	z := new(big.Int)
	z.SetBytes(message.Bytes())

	keys, signPIDs, err := LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	if err != nil {
		common.Logger.Error("should load keygen fixtures")
	}
	for {
		if valid_s {
			break
		}

		// PHASE: signing
		// use a shuffled selection of the list of parties for this test
		// init the parties
		p2pCtx := tss.NewPeerContext(signPIDs)
		parties := make([]*signing.LocalParty, 0, len(signPIDs))

		errCh := make(chan *tss.Error, len(signPIDs))
		outCh := make(chan tss.Message, len(signPIDs))
		endCh := make(chan common.SignatureData, len(signPIDs))

		updater := test.SharedPartyUpdater

		// init the parties
		for i := 0; i < len(signPIDs); i++ {
			params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), testThreshold)

			P := signing.NewLocalParty(z, params, keys[i], outCh, endCh).(*signing.LocalParty)
			parties = append(parties, P)
			go func(P *signing.LocalParty) {
				if err := P.Start(); err != nil {
					errCh <- err
				}
			}(P)
		}

		var ended int32
	signing:
		for {
			select {
			case err := <-errCh:
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(nil, err.Error())
				break signing

			case msg := <-outCh:
				dest := msg.GetTo()
				if dest == nil {
					for _, P := range parties {
						if P.PartyID().Index == msg.GetFrom().Index {
							continue
						}
						go updater(P, msg, errCh)
					}
				} else {
					if dest[0].Index == msg.GetFrom().Index {
						common.Logger.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					}
					go updater(parties[dest[0].Index], msg, errCh)
				}

			case <-endCh:
				atomic.AddInt32(&ended, 1)
				if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
					common.Logger.Debug("Done. Received signature data from %d participants", ended)
					R := parties[0].Temp.BigR
					modN := common.ModInt(tss.S256().Params().N)

					// BEGIN check s correctness
					sumS := big.NewInt(0)
					for _, p := range parties {
						sumS = modN.Add(sumS, p.Temp.Si)
					}
					// END check s correctness

					// BEGIN ECDSA verify
					pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
					pk := ecdsa.PublicKey{
						Curve: tss.EC(),
						X:     pkX,
						Y:     pkY,
					}
					publicKeyBytes := crypto.FromECDSAPub(&pk)

					r_sig := hex.EncodeToString(R.X().Bytes())
					s_sig := hex.EncodeToString(sumS.Bytes())
					s := "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"
					i := new(big.Int)
					i.SetString(s, 16)
					if sumS.Cmp(i) == -1 { // As per eip 2717
						valid_s = true
						v := ""
						if R.X().Cmp(tss.S256().Params().N) == 1 {
							if R.Y().Int64()%2 == 0 {
								v = "1d"
							} else {
								v = "1e"
							}
						} else {
							if R.Y().Int64()%2 == 0 {
								v = "1b"
							} else {
								v = "1c"
							}
						}

						sig, _ := hex.DecodeString(r_sig + s_sig + v)
						signatureNoRecoverID := sig[:len(sig)-1]
						//Verify signature
						verified := crypto.VerifySignature(publicKeyBytes, message.Bytes(), signatureNoRecoverID)
						assert.True(nil, verified, "ecdsa verify must pass")

						fmt.Println("Signature: ", hexutil.Encode(sig))
						fmt.Println("address: ", eth_common.BytesToAddress(crypto.Keccak256(publicKeyBytes[1:])[12:]).Hex())
						fmt.Print("ECDSA signing test done.")

					}

					// END ECDSA verify
					break signing
				}
			}
		}
	}
}

func main() {
	message := []byte("Hello guy! Welcome to Vietnam")
	messageHash := crypto.Keccak256Hash(message)
	hash := prefixHash(messageHash.Bytes())
	fmt.Println("Message Bytes: ", message)
	fmt.Println("Message to be signed: ", hash)

	// Generate key
	testDistibutedKeyGeneration()

	// Signing
	testDistibutedSigning(hash)

}
