package main

import (
	"crypto/ed25519"
	"crypto/elliptic"
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

	"github.com/agl/ed25519/edwards25519"
	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/eddsa/signing"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	// To change these parameters, you must first delete the text fixture files in test/_fixtures/ and then run the keygen test alone.
	// Then the signing and resharing tests will work with the new n, t configuration using the newly written fixture files.
	TestParticipants = 5
	TestThreshold    = 2
)
const (
	testFixtureDirFormat          = "%s/_fixtures"
	testFixtureDirFormatResharing = "%s/_fixtures_resharing"
	testFixtureFileFormat         = "keygen_data_%d.json"
)

var (
	valid_s     = false
	newthresold = 3
)

func makeTestFixtureFilePath(typeFixtures string, partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(typeFixtures, srcDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}

func tryWriteTestFixtureFile(typeFixtures string, index int, data keygen.LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(typeFixtures, index)

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
	param := payload.EDDSAPub
	pk := edwards.PublicKey{
		Curve: tss.Edwards(),
		X:     param.X(),
		Y:     param.Y(),
	}
	publicKeyBytes := pk.Serialize()
	fmt.Println("Public key: ", hexutil.Encode(publicKeyBytes)[:])

}

func LoadKeygenTestFixtures(typeFixtures string, qty int, optionalStart ...int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(typeFixtures, i)
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
			kbxj.SetCurve(tss.Edwards())
		}
		key.EDDSAPub.SetCurve(tss.Edwards())
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

func LoadKeygenTestFixturesRandomSet(typeFixtures string, qty, fixtureCount int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	plucked := make(map[int]interface{}, qty)
	for i := 0; len(plucked) < qty; i = (i + 1) % fixtureCount {
		_, have := plucked[i]
		if pluck := rand.Float32() < 0.5; !have && pluck {
			plucked[i] = new(struct{})
		}
	}
	for i := range plucked {
		fixtureFilePath := makeTestFixtureFilePath(typeFixtures, i)
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
			kbxj.SetCurve(tss.Edwards())
		}
		key.EDDSAPub.SetCurve(tss.Edwards())
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

	fixtures, pIDs, err := LoadKeygenTestFixtures(testFixtureDirFormat, testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *keygen.LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater
	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *keygen.LocalParty
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], len(pIDs), testThreshold)
		if i < len(fixtures) {
			P = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
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
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(nil, err.Error())
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
			index, err := save.OriginalIndex()
			assert.NoErrorf(nil, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(testFixtureDirFormat, index, *save)

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

func Reconstruct(threshold int, ec elliptic.Curve, shares []keygen.LocalPartySaveData) (*edwards.PrivateKey, error) {
	var vssShares = make(vss.Shares, len(shares))
	for i, share := range shares {
		vssShare := &vss.Share{
			Threshold: threshold,
			ID:        share.ShareID,
			Share:     share.Xi,
		}
		vssShares[i] = vssShare
	}

	d, err := vssShares.ReConstruct(ec)
	if err != nil {
		fmt.Println("ERROR ", err)
	}
	d = new(big.Int).Mod(d, tss.Edwards().Params().N)
	scalar := make([]byte, 0, 32)
	copy(scalar, d.Bytes())

	sk, _, _ := edwards.PrivKeyFromScalar(common.PadToLengthBytesInPlace(d.Bytes(), 32))
	return sk, nil
}

func reConstructionPrivateKey(typeFixtures string, threshold int) {
	keys, _, err := LoadKeygenTestFixturesRandomSet(typeFixtures, threshold+2, TestParticipants)
	if err != nil {
		fmt.Println("ERROR: ", err)
	}
	privateKey, err := Reconstruct(threshold, tss.Edwards(), keys)
	if err != nil {
		fmt.Println("ERROR: ", err)
	}

	fmt.Println("Private Key: ", hex.EncodeToString(privateKey.Serialize()))

}

func testDistibutedSigning(typeFixtures string, message eth_common.Hash, threshold int) {
	testParticipants := TestParticipants
	z := new(big.Int)
	z.SetBytes(message.Bytes())
	keys, signPIDs, err := LoadKeygenTestFixturesRandomSet(typeFixtures, threshold+1, testParticipants)
	if err != nil {
		common.Logger.Error("should load keygen fixtures")
	}

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*signing.LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

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
					common.Logger.Debug("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				common.Logger.Debug("Done. Received signature data from %d participants", ended)
				R, _ := parties[0].Temp.GetData()

				// BEGIN check s correctness
				_, sumS := parties[0].Temp.GetData()
				for i, p := range parties {
					if i == 0 {
						continue
					}
					var tmpSumS [32]byte
					var _, tempSi = p.Temp.GetData()
					edwards25519.ScMulAdd(&tmpSumS, sumS, signing.BigIntToEncodedBytes(big.NewInt(1)), tempSi)
					sumS = &tmpSumS
				}
				fmt.Printf("S: %s\n", signing.EncodedBytesToBigInt(sumS).String())
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN EDDSA verify
				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
				pk := edwards.PublicKey{
					Curve: tss.Edwards(),
					X:     pkX,
					Y:     pkY,
				}
				pubkey := pk.SerializeCompressed()
				fmt.Println("public key ", hex.EncodeToString(pubkey))

				//newSig, err := edwards.ParseSignature(parties[0].GetSignature())
				if err != nil {
					println("new sig error, ", err.Error())
				}
				fmt.Println("sig: ", hex.EncodeToString(parties[0].GetSignature()))

				rtn := ed25519.Verify(pubkey, message.Bytes()[:], parties[0].GetSignature())
				fmt.Println("ok ", rtn)
				fmt.Println("ECDSA signing test done.")
				// END EDDSA verify

				break signing
			}
		}
	}

}

func main() {
	message := []byte("Hello guy! Welcome to Vietnam")
	messageHash := crypto.Keccak256Hash(message)
	fmt.Println("Message Bytes: ", message)
	fmt.Println("Message to be signed: ", messageHash)
	testDistibutedKeyGeneration()
	reConstructionPrivateKey(testFixtureDirFormat, TestThreshold)
	testDistibutedSigning(testFixtureDirFormat, messageHash, TestThreshold)
}

//0xcad3924412b991f86e4af6f43f0fb4e1c6c7ec4540ec2aa996b26b695614cdf7
//0xcad3924412b991f86e4af6f43f0fb4e1c6c7ec4540ec2aa996b26b695614cdf7

//cc85fc127d16bf182825693344e3a0a972d12b00dbbfc5db0915e91185374283
//0x50a822d2a9be384e0cb88ff3516ccccffbcec94a4a83e18c3bf0903c24cfba11

//0x47f0c5e614aab1a5bac5bcebe733738a6428a412ca7435b73c1b5395d9af3b030eb2e39d87ffeec1cac59ab96880b5adbcf7beb26425416252c83ea7c7081e5a
