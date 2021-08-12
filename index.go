package main

import (
	"crypto/sha1"
	"fmt"
	bencode2 "github.com/jackpal/bencode-go"
	"github.com/zeebo/bencode"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type bencodeTrackerResp struct {
	Interval int    `bencode:"interval"`
	Peers    string `bencode:"peers"`
}

type fileInfo struct {
	length int64
	path   []string
}

type info struct {
	pieces    string
	length    int64
	filesInfo []fileInfo
}

type TorrentInfo struct {
	announce string
	info     info
	infoHash []byte
}

const (
	connHost = "localHost"
	connPort = "8080"
	connType = "udp"
)

func (torrent *TorrentInfo) buildTrackerUrl(id []byte, port uint16) (string, error) {
	base, err := url.Parse(torrent.announce)
	if err != nil {
		fmt.Println("error in parsing tracker url")
		return "", err
	}
	params := url.Values{
		"info_hash":  []string{string(torrent.infoHash[:])},
		"peer_id":    []string{string(id[:])},
		"port":       []string{strconv.Itoa(int(port))},
		"uploaded":   []string{"0"},
		"downloaded": []string{"0"},
		"compact":    []string{"1"},
		"left":       []string{strconv.Itoa(int(torrent.info.length))},
	}
	base.RawQuery = params.Encode()
	return base.String(), nil
}

func ParseTorrentFile(fileName string) (*TorrentInfo, error) {
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

	var torrentInfo TorrentInfo
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

	file, err := ParseTorrentFile("ubuntu20.04.torrent")
	if err != nil {
		fmt.Println("error in parsing")
		return
	}
	trackerUrl, err := file.buildTrackerUrl(file.infoHash, 8080)
	if err != nil {
		return
	}
	c := &http.Client{Timeout: 15 * time.Second}
	get, err := c.Get(trackerUrl)
	defer get.Body.Close()
	if err != nil {
		return
	}
	trackerResp := bencodeTrackerResp{}
	bencode2.Unmarshal(get.Body, &trackerResp)

	fmt.Println(get.StatusCode)

}
