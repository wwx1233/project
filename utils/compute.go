package utils

import (
	//"crypto/ecdsa"
	//"crypto/elliptic"
	//"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math/big"
	"strconv"

	"golang.org/x/crypto/ripemd160"
)

const addressChecksumLen = 4

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func IntToByte(num int) []byte {
	return []byte(strconv.Itoa(num))
}

func Int64ToByte(num int64) []byte {
	return []byte(strconv.FormatInt(num, 10))
}

func Hash(b []byte) string {
	hash := sha256.New()
	hash.Write(b)
	str := hash.Sum(nil)
	return hex.EncodeToString(str)
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
func Checksum(payload []byte) []byte {
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
