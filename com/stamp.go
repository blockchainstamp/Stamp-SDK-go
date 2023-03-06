package com

type RawStamp struct {
	WAddr        Address `json:"wallet_addr"`
	SAddr        string  `json:"stamp_addr"`
	FromMailAddr string  `json:"from_mail_addr"`
	MsgID        string  `json:"msg_id"`
	No           int     `json:"no"`
	Time         int64   `json:"time"`
}
type StampSig struct {
	SigData   string
	PubSuffix string
}

func (ss *StampSig) Data() string {
	return ss.SigData
}
func (ss *StampSig) Suffix() string {
	return ss.PubSuffix
}

type Stamp struct {
	Data *RawStamp
	Sig  *StampSig
}
