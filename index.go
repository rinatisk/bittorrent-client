package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/zeebo/bencode"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

type fileInfo struct {
	length int64
	path   []string
}

type info struct {
	pieces    string
	length    int64
	filesInfo []fileInfo
}

type torrentInfo struct {
	announce string
	info     info
	infoHash []byte
}

const (
	connHost = "localHost"
	connPort = "8080"
	connType = "udp"
)

func ParseTorrentFile(fileName string) (*torrentInfo, error) {
	torrent, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Println("Invalid name of file")
		return nil, err
	}
	var decode map[string]interface{}
	err = bencode.DecodeBytes(torrent, &decode)
	if err != nil {
		fmt.Println("Invalid .torrent file, error in decoding")
		return nil, err
	}

	var torrentInfo torrentInfo
	torrentInfo.announce = decode["announce"].(string)

	infoMap := decode["info"].(map[string]interface{})

	var info info

	info.length = infoMap["length"].(int64)
	info.pieces = infoMap["pieces"].(string)

	if length, err := infoMap["length"]; err {
		info.length = length.(int64)
	} else if files, err := infoMap["files"]; err {
		for _, file := range files.([]interface{}) {
			fileMap := file.(map[string]interface{})
			var fileInfo fileInfo
			path := fileMap["path"].(string)
			fileInfo.path = strings.Split(path, string(os.PathSeparator))
			fileInfo.length = fileMap["length"].(int64)
			info.filesInfo = append(info.filesInfo, fileInfo)
		}
	}
	torrentInfo.info = info
	torrentInfo.infoHash, _ = infoHash(infoMap)

	return &torrentInfo, nil
}

func infoHash(decodedInfoMap interface{}) ([]byte, error) {
	info := strings.Builder{}
	enc := bencode.NewEncoder(&info)
	err := enc.Encode(decodedInfoMap)
	if err != nil {
		return nil, fmt.Errorf("failed to encode torrent info: %v", err)
	}
	hash := sha1.New()
	_, _ = io.WriteString(hash, info.String())
	return hash.Sum(nil), nil
}

func main() {

	file, err := ParseTorrentFile("puppy.torrent")
	if err != nil {
		fmt.Println("error in parsing")
		return
	}
	fmt.Println(file)

}
