package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"test/project/utils"
	//"crypto/sha256"
	//"log"
	//"math/big"
	//"golang.org/x/crypto/ripemd160"
)

const addressChecksumLen = 4

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte
	Addr       []byte
}

// 生成钱包（公钥，私钥，地址）
func NewWallet() (*Wallet, error) {
	c := elliptic.P256()
	private, err := ecdsa.GenerateKey(c, rand.Reader) //私钥
	if err != nil {
		return nil, err
	}
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...) //公钥
	address := GetAddress(pubKey)                                                 //生成地址

	return &Wallet{PrivateKey: private, PublicKey: pubKey, Addr: address}, nil
}

//返回钱包地址
func GetAddress(publicKey []byte) []byte {
	pubKeyHash := utils.HashPubKey(publicKey) //将钱包的公钥进行哈希

	//versionedPayload := append([]byte{version}, pubKeyHash...) 不要版本号
	checksum := utils.Checksum(pubKeyHash) //生成pubKeyHash摘要

	fullPayload := append(pubKeyHash, checksum...) //公钥哈希和其摘要放一起

	address := utils.Base58Encode(fullPayload) //转换为58进制

	return address
}
