package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/zeebo/bencode"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type handshake struct {
	pstr     string
	infoHash []byte
	peerId   []byte
}

type peer struct {
	port uint16
	IP   net.IP
}

func (p peer) String() string {
	return p.IP.String() + ":" + strconv.Itoa(int(p.port))
}

type bencodeTrackerResp struct {
	WarningMessage string
	Interval       int64
	MinInterval    int64
	TrackerId      string
	Complete       int64
	Incomplete     int64
	Peers          []peer
}

func parseTrackerResp(bytes []byte) (bencodeTrackerResp, error) {
	var resp map[string]interface{}
	err := bencode.DecodeBytes(bytes, &resp)
	if err != nil {
		return bencodeTrackerResp{}, fmt.Errorf("oh shit man u broke decoder: %v", err)
	}

	var trackerResp bencodeTrackerResp

	if interval, ok := resp["interval"].(int64); ok {
		trackerResp.Interval = interval
	}

	if id, ok := resp["tracker id"].(string); ok {
		trackerResp.TrackerId = id
	}

	if warning, ok := resp["warning message"].(string); ok {
		trackerResp.WarningMessage = warning
	}

	if complete, ok := resp["complete"].(int64); ok {
		trackerResp.Complete = complete
	}

	if incomplete, ok := resp["incomplete"].(int64); ok {
		trackerResp.Incomplete = incomplete
	}

	if minInterval, ok := resp["min interval"].(int64); ok {
		trackerResp.MinInterval = minInterval
	}
	peers := resp["peers"].(string)
	trackerResp.Peers = parsePeers(peers)

	return trackerResp, nil
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
	connPort = "6969"
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

func (torrent *TorrentInfo) getTrackerResp() (bencodeTrackerResp, error) {
	trackerUrl, err := torrent.buildTrackerUrl(torrent.infoHash, 6969)
	if err != nil {
		return bencodeTrackerResp{}, err
	}
	c := &http.Client{Timeout: 15 * time.Second}
	get, err := c.Get(trackerUrl)
	defer get.Body.Close()
	if err != nil {
		return bencodeTrackerResp{}, err
	}
	bytes, err := ioutil.ReadAll(get.Body)
	if err != nil {
		return bencodeTrackerResp{}, err
	}
	trackerResp, err := parseTrackerResp(bytes)
	if err != nil {
		return bencodeTrackerResp{}, fmt.Errorf("error in decode url response: %v", err)
	}
	return trackerResp, nil
}

func parsePeers(str string) []peer {
	bytes := []byte(str)
	const numberPeerBytes = 6
	var peers []peer
	for i := 0; i < len(bytes); i += numberPeerBytes {
		p := peer{
			port: binary.BigEndian.Uint16(bytes[i+4 : i+6]),
			IP:   bytes[i : i+4],
		}
		peers = append(peers, p)
	}
	return peers
}

func (h handshake) String() []byte {
	toDecode := make([]byte, len(h.pstr)+29+len(h.peerId))
	copy(toDecode[:], h.pstr)
	copy(toDecode[len(h.pstr)+9:], h.infoHash[:])
	copy(toDecode[len(h.pstr)+29:], h.peerId[:])
	_, err := bencode.EncodeBytes(toDecode)
	if err != nil {
		return nil
	}
	return toDecode
}

func downloadPeers(peers []peer) {

}

func main() {

	torrent, err := ParseTorrentFile("ubuntu20.04.torrent")
	if err != nil {
		fmt.Println("Error with parsing torrent file")
		return
	}
	tracker, err := torrent.getTrackerResp()
	if err != nil {
		fmt.Println("Error with get tracker resp")
		return
	}
	//fmt.Println([]byte(tracker.Peers))
	//peers := parsePeers([]byte(tracker.Peers))
	conn, err := net.Dial("tcp", tracker.Peers[1].String())
	defer conn.Close()
	if err != nil {
		return
	}
	h := handshake{
		pstr:     "BitTorrent protocol",
		infoHash: torrent.infoHash,
		peerId:   torrent.infoHash,
	}
	read, err := conn.Write(h.String())
	if err != nil {
		return
	}
	fmt.Println(read)

}
