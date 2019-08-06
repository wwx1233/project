package db

import (
	"fmt"
	"log"
	"time"

	"github.com/boltdb/bolt"
)

type Meta struct {
	Name        []byte // 物品名称
	CraetedTime int64  // 入库时间
	Region      []byte // 存储位置
	LawCase     []byte // 所属案件
}

type CreateMeta interface{}

func NewMetaDate(name, region, lawcase []byte, createdtime int64) *Meta {

	return nil
}

//查询数据库，列出账号拥有的物品信息
func Listdata() {
	//打开数据库
	db, err := bolt.Open("mydb.db", 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.View(func(tx *bolt.Tx) error {

		//取出叫"MyBucket"的表
		b := tx.Bucket([]byte("Mybucket"))

		//往表里面存储数据
		if b != nil {

			data := b.Get([]byte("a"))
			fmt.Printf("%s\n", data)
			data = b.Get([]byte("b"))
			fmt.Printf("%s\n", data)
		}

		//一定要返回nil
		return nil
	})

	//查询数据库失败
	if err != nil {
		log.Fatal(err)
	}

}

//将用户的物品信息放入表中
func Putdata() {

	db, err := bolt.Open("mydb.db", 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	//更新表数据
	err = db.Update(func(tx *bolt.Tx) error {

		//取出叫"MyBucket"的表
		b := tx.Bucket([]byte("Mybucket"))

		if b == nil {
			//创建叫"MyBucket"的表
			b, _ = tx.CreateBucket([]byte("Mybucket"))
			_, err := tx.CreateBucket([]byte("Mybucket"))
			if err != nil {
				log.Fatal(err)
			}
		}

		//往表里面存储数据
		if b != nil {
			//插入的键值对数据类型必须是字节数组
			err := b.Put([]byte("a"), []byte("0x0"))
			err = b.Put([]byte("b"), []byte("0x1"))
			if err != nil {
				log.Fatal(err)
			}
		}

		//一定要返回nil
		return nil
	})

	//更新数据库失败
	if err != nil {
		log.Fatal(err)
	}
}
