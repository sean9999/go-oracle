package oracle

// fields common to both plainText and cipherText.
// It tries to look like [pem.Block]
type fields = struct {
	Type      string            `json:"subject" ion:"subject"`
	Headers   map[string]string `json:"metadata" ion:"metadata"`
	Bytes     []byte            `json:"data" ion:"data"`
	Signature []byte            `json:"sig" ion:"sig"`
	Nonce     []byte            `json:"nonce" ion:"nonce"`
}
