package main

import (
	"fmt"
	"log"
	"os"

	//"test/project/db"

	//"github.com/LazyboyChen7/project/agent"
	"test/project/agent"
	//"github.com/LazyboyChen7/project/transaction"
	"test/project/transaction"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("\n%s \n\n", "Usage: go run main.go [port].")
		return
	}
	log.Println("Process Start...")
	ag, err := agent.NewAgent(os.Args[1])
	if err != nil {
		log.Println("create agent wrong...", err)
		return
	}
	log.Println("The wallet private key  is ", ag.Wlt.PrivateKey.D)
	log.Println("The wallet public key x is ", ag.Wlt.PrivateKey.PublicKey.X)
	log.Println("The wallet public key y is ", ag.Wlt.PrivateKey.PublicKey.Y)
	log.Println("The wallet address is ", string(ag.Wlt.Addr))
	log.Println("The server port is ", ag.Svr.Port)
	log.Println("The blockchain height is ", ag.Blc.Bc.Height)
	log.Println("The blockchain top hash is ", ag.Blc.Bc.TopHash)

	go ag.Start()

	tx := transaction.CreateTx("abc", "abc", "abc")
	fmt.Println(tx.Thash)

	transaction.Nowpool = transaction.NewTxPool() //初始化交易池
	transaction.Send("abc", "bcd", "good")        //发送交易1
	transaction.Send("abc", "bcd", "good1")       //发送交易2
	transaction.ListTxPool(transaction.Nowpool)   //列出交易

	//db.Putdata()  //存数据
	//db.Listdata() //列数据

}
