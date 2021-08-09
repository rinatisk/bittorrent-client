package main

import (
	"fmt"
	_ "github.com/jackpal/bencode-go"
	"io/ioutil"
)

func main() {
	torrent, err := ioutil.ReadFile("puppy.torrent")
	if err != nil {
		fmt.Println("Invalid name of file")
		return
	}
	fmt.Println(string(torrent))

}
