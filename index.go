package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/zeebo/bencode"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Bitfield []byte

func (bf Bitfield) HasPiece(index int) bool {
	byteIndex := index / 8
	offset := index % 8
	if byteIndex < 0 || byteIndex >= len(bf) {
		return false
	}
	return bf[byteIndex]>>uint(7-offset)&1 != 0
}

func (bf Bitfield) SetPiece(index int) {
	byteIndex := index / 8
	offset := index % 8

	// silently discard invalid bounded index
	if byteIndex < 0 || byteIndex >= len(bf) {
		return
	}
	bf[byteIndex] |= 1 << uint(7-offset)
}

type messageID uint8

const (
	MsgChoke         messageID = 0
	MsgUnchoke       messageID = 1
	MsgInterested    messageID = 2
	MsgNotInterested messageID = 3
	MsgHave          messageID = 4
	MsgBitfield      messageID = 5
	MsgRequest       messageID = 6
	MsgPiece         messageID = 7
	MsgCancel        messageID = 8
)

type Message struct {
	ID      messageID
	Payload []byte
}

type handshake struct {
	pstr     string
	infoHash []byte
	peerId   [20]byte
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
	trackerUrl, err := torrent.buildTrackerUrl(torrent.infoHash, 6881)
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

func (h handshake) toByte() []byte {
	pstrLen := len(h.pstr)
	buf := make([]byte, 49+pstrLen)
	buf[0] = byte(pstrLen)

	idxCurr := 1
	idxCurr += copy(buf[idxCurr:], h.pstr)
	idxCurr += copy(buf[idxCurr:], make([]byte, 8)) // Leave 8 reserved bytes
	idxCurr += copy(buf[idxCurr:], h.infoHash[:])
	idxCurr += copy(buf[idxCurr:], h.peerId[:])

	//	fmt.Println(buf)
	return buf
}

func readHandshake(r io.Reader) (handshake, error) {
	pstrlenBuf := make([]byte, 1)
	_, err := io.ReadFull(r, pstrlenBuf)
	if err != nil {
		return handshake{}, err
	}
	pstrlen := int(pstrlenBuf[0])
	restBuf := make([]byte, (pstrlen)+48)
	_, err = io.ReadFull(r, restBuf)
	if err != nil {
		return handshake{}, err
	}
	infoHash := restBuf[(pstrlen)+8 : (pstrlen)+28]
	var peerId [20]byte
	copy(peerId[:], restBuf[(pstrlen)+28:])
	h := handshake{
		pstr:     string(restBuf[0:(pstrlen)]),
		infoHash: infoHash,
		peerId:   peerId,
	}
	return h, err
}

func checkHandshake(toCheckPeer peer, h *handshake) error {
	conn, err := net.DialTimeout("tcp", toCheckPeer.String(), time.Second*6)
	if err != nil {
		return fmt.Errorf("error with creating socket: %v", err)
	}

	_, err = conn.Write(h.toByte())
	if err != nil {
		return fmt.Errorf("error with write to socket: %v", err)
	}

	message, err := readHandshake(conn)

	if bytes.Equal(message.infoHash, h.infoHash) {
		log.Printf("successfully handshake with peer: %s\n", toCheckPeer.IP)
		return nil
	} else {
		return fmt.Errorf("invalid message from socket, handshake fall: %v", err)
	}

}

func (m *Message) Serialize() []byte {
	if m == nil {
		return make([]byte, 4)
	}
	length := uint32(len(m.Payload) + 1) // +1 for id
	buf := make([]byte, 4+length)
	binary.BigEndian.PutUint32(buf[0:4], length)
	buf[4] = byte(m.ID)
	copy(buf[5:], m.Payload)
	return buf
}

func Read(r io.Reader) (*Message, error) {
	lengthBuf := make([]byte, 4)
	_, err := io.ReadFull(r, lengthBuf)
	if err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBuf)

	// keep-alive message
	if length == 0 {
		return nil, nil
	}

	messageBuf := make([]byte, length)
	_, err = io.ReadFull(r, messageBuf)
	if err != nil {
		return nil, err
	}

	m := Message{
		ID:      messageID(messageBuf[0]),
		Payload: messageBuf[1:],
	}

	return &m, nil
}

func (m *Message) name() string {
	if m == nil {
		return "KeepAlive"
	}
	switch m.ID {
	case MsgChoke:
		return "Choke"
	case MsgUnchoke:
		return "Unchoke"
	case MsgInterested:
		return "Interested"
	case MsgNotInterested:
		return "NotInterested"
	case MsgHave:
		return "Have"
	case MsgBitfield:
		return "Bitfield"
	case MsgRequest:
		return "Request"
	case MsgPiece:
		return "Piece"
	case MsgCancel:
		return "Cancel"
	default:
		return fmt.Sprintf("Unknown#%d", m.ID)
	}
}

func FormatRequest(index, begin, length int) *Message {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[0:4], uint32(index))
	binary.BigEndian.PutUint32(payload[4:8], uint32(begin))
	binary.BigEndian.PutUint32(payload[8:12], uint32(length))
	return &Message{ID: MsgRequest, Payload: payload}
}

func FormatHave(index int) *Message {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(index))
	return &Message{ID: MsgHave, Payload: payload}
}

func ParsePiece(index int, buf []byte, msg *Message) (int, error) {
	if msg.ID != MsgPiece {
		return 0, fmt.Errorf("expected PIECE (ID %d), got ID %d", MsgPiece, msg.ID)
	}
	if len(msg.Payload) < 8 {
		return 0, fmt.Errorf("payload too short. %d < 8", len(msg.Payload))
	}
	parsedIndex := int(binary.BigEndian.Uint32(msg.Payload[0:4]))
	if parsedIndex != index {
		return 0, fmt.Errorf("expected index %d, got %d", index, parsedIndex)
	}
	begin := int(binary.BigEndian.Uint32(msg.Payload[4:8]))
	if begin >= len(buf) {
		return 0, fmt.Errorf("begin offset too high. %d >= %d", begin, len(buf))
	}
	data := msg.Payload[8:]
	if begin+len(data) > len(buf) {
		return 0, fmt.Errorf("data too long [%d] for offset %d with length %d", len(data), begin, len(buf))
	}
	copy(buf[begin:], data)
	return len(data), nil
}

func ParseHave(msg *Message) (int, error) {
	if msg.ID != MsgHave {
		return 0, fmt.Errorf("Expected HAVE (ID %d), got ID %d", MsgHave, msg.ID)
	}
	if len(msg.Payload) != 4 {
		return 0, fmt.Errorf("Expected payload length 4, got length %d", len(msg.Payload))
	}
	index := int(binary.BigEndian.Uint32(msg.Payload))
	return index, nil
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
	var peerId [20]byte
	rand.Read(peerId[:])
	h := &handshake{
		pstr:     "BitTorrent protocol",
		infoHash: torrent.infoHash,
		peerId:   peerId,
	}

	err = checkHandshake(tracker.Peers[0], h)
}
