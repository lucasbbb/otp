package otp

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math"
)

type HOTP struct {
	Key []byte
}

func NewHOTP(key []byte) HOTP {
	return HOTP{Key: key}
}

// Generate
// https://datatracker.ietf.org/doc/html/rfc4226#section-5.3
func (otp HOTP) Generate(in interface{}, opts ...Option) string {
	options := NewOptions()
	for _, opt := range opts {
		opt(options)
	}

	// 8-byte counter value, the moving factor.
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, in.(uint64))

	h := hmac.New(options.HashFunc, otp.Key)
	_, _ = h.Write(counter)
	hmacRes := h.Sum(nil)

	offset := hmacRes[len(hmacRes)-1] & 0xf
	// The dynamic binary code is a 31-bit, unsigned, big-endian integer
	binCode := int(hmacRes[offset]&0x7f)<<24 |
		int(hmacRes[offset+1]&0xff)<<16 |
		int(hmacRes[offset+2]&0xff)<<8 |
		int(hmacRes[offset+3])&0xff

	remainder := int64(binCode) % int64(math.Pow10(options.Digit))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", options.Digit), remainder)
}

// Validate
// return true if the code matched the generated code
func (otp HOTP) Validate(in interface{}, code string, opts ...Option) bool {
	res := otp.Generate(in, opts...)
	return subtle.ConstantTimeCompare([]byte(code), []byte(res)) == 1
}
