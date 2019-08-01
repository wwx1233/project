package wallet

import (
	"bytes" //不确定需不需要
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

const addressChecksumLen = 4

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte
}

// 生成钱包（公钥，私钥，地址）
func NewWallet() (*Wallet, []byte, error) {
	c := elliptic.P256()
	private, err := ecdsa.GenerateKey(c, rand.Reader) //私钥
	if err != nil {
		return nil, "", err
	}
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...) //公钥
	address := GetAddress(pubKey)                                                 //生成地址

	return &Wallet{PrivateKey: private, PublicKey: pubKey}, address, nil
}

//返回钱包地址
func (publicKey []byte) GetAddress() []byte {
	pubKeyHash := HashPubKey(publicKey) //将钱包的公钥进行哈希

	//versionedPayload := append([]byte{version}, pubKeyHash...) 不要版本号
	checksum := checksum(pubKeyHash) //生成pubKeyHash摘要

	fullPayload := append(pubKeyHash, checksum...) //公钥哈希和其摘要放一起

	address := base58.Base58Encode(fullPayload) //转换为58进制

	return address
}

//对公钥进行哈希
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New() //ripemd160加密算法
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}

//生成公钥的消息摘要
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload) //生成消息摘要（[32]byte）
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:addressChecksumLen] //addressChecksumLen = 4
}

func Base58Encode(input []byte) []byte {
	var result []byte

	x := big.NewInt(0).SetBytes(input)

	base := big.NewInt(int64(len(b58Alphabet)))
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, b58Alphabet[mod.Int64()])
	}

	// https://en.bitcoin.it/wiki/Base58Check_encoding#Version_bytes
	if input[0] == 0x00 {
		result = append(result, b58Alphabet[0])
	}

	ReverseBytes(result)

	return result
}

func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}
