package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {

	msg := "Hello guy! Welcome to Vietnam"

	argCount := len(os.Args[1:])
	if argCount > 0 {
		msg = os.Args[1]
	}

	publ, priv, _ := ed25519.GenerateKey((nil))
	publTest := "5a1eb1b316c3b5342e3c7f4df3c9c0cb427547007b5b36b4b33e18fe6049b026"
	sig := "83c5521d9ec7cd19128f68ea1b4e3d21e781ccddd8fcf345734b82d7779c983f729d4d4fdf6767d1742cd9e622cafde943215e9beeb790af05edfc38f971a10c"
	sigBytes, _ := hex.DecodeString(sig)
	publicTestBytes, _ := hex.DecodeString(publTest)
	fmt.Println(" publicTestBytes ", publicTestBytes)

	m := []byte(msg)
	//digest := sha256.Sum256(m)
	messageHash := crypto.Keccak256Hash(m)
	fmt.Println("messageHash ", messageHash)

	//sig := ed25519.Sign(priv, digest[:])

	fmt.Printf("=== Message ===\n")
	//fmt.Printf("Msg=%s\nHash=%x\n", msg, digest)
	fmt.Printf("\n=== Private key ===\n")
	fmt.Printf("Public key=%x\n\n", publ)
	fmt.Printf("Private key=%x\n\n", priv[0:32])
	fmt.Printf("Signature: (%x,%x)\n\n", sig[0:32], sig[32:64])

	rtn := ed25519.Verify(publicTestBytes, messageHash.Bytes(), sigBytes)

	if rtn {
		fmt.Printf("Signature verifies")
	} else {
		fmt.Printf("Signature does not verify")
	}
}

//dabe1ce99656b1cd7d671798ff35a5a4385ad6a473455e25864f82bdad368612,edbab3c4308e9356b1b39435df8d4bad30d11b766e1c7748ae88578304663108
//0x179a91607857153a77ff600a842f786d143e978f1211029e05ef4ea05fb144b8c79dec540faf7f3de74678876ecf00b558cb35df9c9bcebb251ecd59db50ba
