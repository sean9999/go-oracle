package message

import (
	"testing"
)

func TestExtractFields_Coverage(t *testing.T) {
	// 1. Bad Eph Hex
	headers := map[string]string{
		"eph": "zz",
	}
	_, _, _, _, _, err := extractFields(&headers)
	if err == nil {
		t.Error("expected error on bad eph hex")
	}

	// 2. Only AAD header, but bad base64
	headers = map[string]string{
		"aad": "zz",
	}
	_, _, _, _, _, err = extractFields(&headers)
	if err == nil {
		t.Error("expected error on bad aad base64")
	}

	// 3. No headers (len=0)
	headers = map[string]string{}
	_, _, _, _, _, err = extractFields(&headers)
	if err != nil {
		t.Error("unexpected error on empty headers")
	}

	// 4. AAD + other headers
	headers = map[string]string{
		"aad": "someaad",
		"foo": "bar",
	}
	_, _, _, _, _, err = extractFields(&headers)
	if err == nil {
		t.Error("expected error when mixing aad and other headers")
	}
}

func TestMessage_UnmarshalPEM_BadBlock(t *testing.T) {
	msg := NewMessage(nil)
	// Invalid PEM data
	err := msg.UnmarshalPEM([]byte("-----BEGIN FOO"))
	if err == nil {
		t.Error("expected error on bad PEM")
	}
}