package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
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

<<<<<<< HEAD
func LoadKeygenTestFixtures(typeFixtures string, qty int, optionalStart ...int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
=======
func LoadKeygenTestFixtures(qty int, optionalStart ...int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
>>>>>>> main
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

<<<<<<< HEAD
func testDistibutedSigning(typeFixtures string, message eth_common.Hash, threshold int) {
=======
func testDistibutedSigning(message eth_common.Hash) {
	testThreshold := TestThreshold
>>>>>>> main
	testParticipants := TestParticipants

	z := new(big.Int)
	z.SetBytes(message.Bytes())

	keys, signPIDs, err := LoadKeygenTestFixturesRandomSet(typeFixtures, threshold+1, testParticipants)
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
		endCh := make(chan *common.SignatureData, len(signPIDs))

		updater := test.SharedPartyUpdater

		// init the parties
		for i := 0; i < len(signPIDs); i++ {
			params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

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
<<<<<<< HEAD
						fmt.Println("ECDSA signing test done.")
=======
						fmt.Print("ECDSA signing test done.")
>>>>>>> main

					}

					// END ECDSA verify
					break signing
				}
			}
		}
	}
	valid_s = false

}

func Reconstruct(threshold int, ec elliptic.Curve, shares []keygen.LocalPartySaveData) (*ecdsa.PrivateKey, error) {
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
		return nil, err
	}

	x, y := ec.ScalarBaseMult(d.Bytes())

	privateKey := &ecdsa.PrivateKey{
		D: d,
		PublicKey: ecdsa.PublicKey{
			Curve: ec,
			X:     x,
			Y:     y,
		},
	}

	return privateKey, nil
}

func reConstructionPrivateKey(typeFixtures string, threshold int) {
	keys, _, err := LoadKeygenTestFixturesRandomSet(typeFixtures, threshold+1, TestParticipants)
	if err != nil {
		fmt.Println("ERROR: ", err)
	}
	privateKey, err := Reconstruct(threshold, tss.EC(), keys)
	if err != nil {
		fmt.Println("ERROR: ", err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)

	fmt.Println("Private Key: ", hexutil.Encode(privateKeyBytes)[2:])

}

func reSharing() {

	// PHASE: load keygen fixtures
	oldKeys, oldPIDs, err := LoadKeygenTestFixtures(testFixtureDirFormat, TestParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
	}

	// PHASE: resharing
	oldP2PCtx := tss.NewPeerContext(oldPIDs)
	// init the new parties; re-use the fixture pre-params for speed
	fixtures, _, err := LoadKeygenTestFixtures(testFixtureDirFormat, TestParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
	}
	newPIDs := tss.GenerateTestPartyIDs(TestParticipants)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*resharing.LocalParty, 0, len(oldPIDs))
	newCommittee := make([]*resharing.LocalParty, 0, newPCount)
	bothCommitteesPax := len(oldCommittee) + len(newCommittee)

	errCh := make(chan *tss.Error, bothCommitteesPax)
	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan *keygen.LocalPartySaveData, bothCommitteesPax)

	updater := test.SharedPartyUpdater

	// init the old parties first
	for j, pID := range oldPIDs {
		params := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, pID, TestParticipants, TestThreshold, newPCount, newthresold)
		P := resharing.NewLocalParty(params, oldKeys[j], outCh, endCh).(*resharing.LocalParty) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}
	// init the new parties
	for j, pID := range newPIDs {
		params := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, pID, TestParticipants, TestThreshold, newPCount, newthresold)
		// do not use in untrusted setting
		params.SetNoProofMod()
		// do not use in untrusted setting
		params.SetNoProofFac()
		save := keygen.NewLocalPartySaveData(newPCount)
		if j < len(fixtures) && len(newPIDs) <= len(fixtures) {
			save.LocalPreParams = fixtures[j].LocalPreParams
		}
		P := resharing.NewLocalParty(params, save, outCh, endCh).(*resharing.LocalParty)
		newCommittee = append(newCommittee, P)
	}

	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		go func(P *resharing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		go func(P *resharing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	endedOldCommittee := 0
	var reSharingEnded int32
resharing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(nil, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				log.Fatal("did not expect a msg to have a nil destination during resharing")
			}
			if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest[:len(oldCommittee)] {
					go updater(oldCommittee[destP.Index], msg, errCh)
				}
			}
			if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest {
					go updater(newCommittee[destP.Index], msg, errCh)
				}
			}

		case save := <-endCh:
			// old committee members that aren't receiving a share have their Xi zeroed
			if save.Xi != nil {
				index, err := save.OriginalIndex()
				tryWriteTestFixtureFile(testFixtureDirFormatResharing, index, *save)
				assert.NoErrorf(nil, err, "should not be an error getting a party's index from save data")
			} else {
				endedOldCommittee++
			}
			atomic.AddInt32(&reSharingEnded, 1)
			fmt.Println("TODO old:", len(oldCommittee), "new:", len(newCommittee), "finished:", reSharingEnded)
			if atomic.LoadInt32(&reSharingEnded) == int32(len(oldCommittee)+len(newCommittee)) {
				assert.Equal(nil, len(oldCommittee), endedOldCommittee)
				inform := fmt.Sprintf("Resharing done. Reshared %d participants", reSharingEnded)
				fmt.Println(inform)
				break resharing
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

<<<<<<< HEAD
	//Generate key
	fmt.Println(" Gen key ")
	testDistibutedKeyGeneration()

	//Reconstruct Private key
	fmt.Println(" Reconstruction private key  ")
	reConstructionPrivateKey(testFixtureDirFormat, TestThreshold)

	// Signing
	fmt.Println(" Sign message ")
	testDistibutedSigning(testFixtureDirFormat, hash, TestThreshold)

	//Resharing key
	fmt.Println("Resharing key")
	reSharing()

	//Reconstruct Private key after resharing
	fmt.Println(" Reconstruction private key after resharing")
	reConstructionPrivateKey(testFixtureDirFormatResharing, newthresold)

	// Signing after resharing
	fmt.Println(" Sign message after resharing")
	testDistibutedSigning(testFixtureDirFormatResharing, hash, newthresold)
=======
	// Generate key
	testDistibutedKeyGeneration()

	// Signing
	testDistibutedSigning(hash)
>>>>>>> main

}
