package com

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
)

const (
	WalletVersion = "2"
)

var (
	WOpenErr    = errors.New("open wallet failed")
	WVerifyErr  = errors.New("verify signature failed")
	WInvalidSig = errors.New("invalid signature data")
)

type CipherData struct {
	KeyParam  `json:"param"`
	Code      string `json:"code"`
	KeyCrypto string `json:"key_crypto"`
	Salt      string `json:"salt"`
	PriCipher string `json:"pri_cipher"`
}
type Wallet struct {
	NickName string      `json:"nick_name"`
	Version  string      `json:"version"`
	Addr     Address     `json:"address"`
	Cipher   *CipherData `json:"cipher"`
	priKey   ed25519.PrivateKey
}

type KeyParam struct {
	S int `json:"s"`
	N int `json:"n"`
	R int `json:"r"`
	P int `json:"p"`
	L int `json:"l"`
}

var KP = KeyParam{
	S: 8,
	N: 1 << 15,
	R: 8,
	P: 1,
	L: 32,
}

func Decrypt(key []byte, cipherTxt []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherTxt) < aes.BlockSize {
		return nil, fmt.Errorf("cipher text too short")
	}

	iv := cipherTxt[:aes.BlockSize]
	cipherTxt = cipherTxt[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherTxt, cipherTxt)

	return cipherTxt, nil
}

func Encrypt(key []byte, plainTxt []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainTxt))

	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainTxt)

	return cipherText, nil
}
func AESKey(salt []byte, password string) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, KP.N, KP.R, KP.P, KP.L)
}

func encryptPriKey(priKey ed25519.PrivateKey, auth string) (*CipherData, error) {
	salt := make([]byte, KP.S)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	aesKey, err := AESKey(salt, auth)
	if err != nil {
		return nil, err
	}
	ci, err := Encrypt(aesKey, priKey[:])
	if err != nil {
		return nil, err
	}

	ciData := &CipherData{
		KeyParam:  KP,
		Code:      "base58",
		KeyCrypto: "scrypt",
		Salt:      base58.Encode(salt),
		PriCipher: base58.Encode(ci),
	}

	return ciData, nil // ,base58.Encode(ci)
}

func PrivateKeyToCurve25519(curve25519Private *[32]byte, privateKey *[64]byte) {
	h := sha512.New()
	h.Write(privateKey[:32])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	copy(curve25519Private[:], digest)
}

func decryptPriKey(ciData *CipherData, auth string) (ed25519.PrivateKey, error) {
	salt := base58.Decode(ciData.Salt)
	aesKey, err := AESKey(salt, auth)
	if err != nil {
		return nil, err
	}
	priBytes := base58.Decode(ciData.PriCipher)
	return Decrypt(aesKey, priBytes)
}

func CreateWallet(auth, name string) (*Wallet, error) {
	pub, pri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cipherTxt, err := encryptPriKey(pri, auth)
	if err != nil {
		return nil, err
	}
	addr, _ := PubToAddr(pub)
	sw := &Wallet{
		NickName: name,
		Version:  WalletVersion,
		Cipher:   cipherTxt,
		Addr:     addr,
		priKey:   pri,
	}

	return sw, nil
}

func LoadByJsonData(jsonStr string) (*Wallet, error) {
	w := new(Wallet)
	if err := json.Unmarshal([]byte(jsonStr), w); err != nil {
		return nil, err
	}
	return w, nil
}

func LoadByFile(path string) (*Wallet, error) {
	bts, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	w := new(Wallet)
	if err := json.Unmarshal(bts, w); err != nil {
		return nil, err
	}
	return w, nil
}

func (sw *Wallet) Close() {
	sw.priKey = nil
}

func (sw *Wallet) Open(auth string) error {
	if sw.priKey != nil {
		return nil
	}

	pri, err := decryptPriKey(sw.Cipher, auth)
	if err != nil {
		return err
	}
	pub := pri.Public().(ed25519.PublicKey)
	addr, _ := PubToAddr(pub)
	if addr != sw.Addr {
		return WOpenErr
	}
	sw.priKey = pri
	return nil
}

func (sw *Wallet) Address() Address {
	return sw.Addr
}
func (sw *Wallet) Verbose() string {
	bts, _ := json.MarshalIndent(sw, "", "\t")
	return string(bts)
}

func (sw *Wallet) Sign(s *RawStamp) *StampSig {
	rawBytes, _ := json.Marshal(s)
	pub := sw.priKey.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(sw.priKey, rawBytes)
	_, suffix := PubToAddr(pub)
	return &StampSig{
		SigData:   hex.EncodeToString(sig),
		PubSuffix: suffix,
	}
}

func VerifyStamp(stamp Stamp) error {
	var (
		err               error
		data, sig, pubBts []byte
	)
	if stamp.Data == nil || stamp.Sig == nil {
		return WInvalidSig
	}
	data, _ = json.Marshal(stamp.Data)

	sig, err = hex.DecodeString(stamp.Sig.Data())
	if err != nil {
		return err
	}

	pubBts, err = RecoverPub(stamp.Data.WAddr, stamp.Sig.Suffix())
	if err != nil {
		return err
	}
	if len(pubBts) != ed25519.PublicKeySize {
		return WVerifyErr
	}
	if !ed25519.Verify(pubBts, data, sig) {
		return WVerifyErr
	}
	return nil
}

func (sw *Wallet) IsOpen() bool {
	return sw.priKey != nil
}

func (sw *Wallet) String() string {
	bs, _ := json.MarshalIndent(sw, "", "\t")
	return string(bs)
}
func (sw *Wallet) Name() string {
	return sw.NickName
}
func (sw *Wallet) SetName(newName string) {
	sw.NickName = newName
}
