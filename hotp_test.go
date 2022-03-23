package otp

import (
	"crypto/sha1"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
)

type hotpCase struct {
	Counter  uint64
	HashFunc func() hash.Hash
	Digit    int
	Code     string
	Secret   string
}

var (
	// https://datatracker.ietf.org/doc/html/rfc4226#appendix-B.3
	hotpCases = []hotpCase{
		{0, sha1.New, 6, "755224", "12345678901234567890"},
		{1, sha1.New, 6, "287082", "12345678901234567890"},
		{2, sha1.New, 6, "359152", "12345678901234567890"},
		{3, sha1.New, 6, "969429", "12345678901234567890"},
		{4, sha1.New, 6, "338314", "12345678901234567890"},
		{5, sha1.New, 6, "254676", "12345678901234567890"},
		{6, sha1.New, 6, "287922", "12345678901234567890"},
		{7, sha1.New, 6, "162583", "12345678901234567890"},
		{8, sha1.New, 6, "399871", "12345678901234567890"},
		{9, sha1.New, 6, "520489", "12345678901234567890"},
	}
)

func TestHOTP_Generate(t *testing.T) {
	for _, tt := range hotpCases {
		hotp := NewHOTP([]byte(tt.Secret))
		assert.Equal(t, tt.Code, hotp.Generate(
			tt.Counter,
			WithDigit(tt.Digit),
			WithHashFunc(tt.HashFunc),
		))
	}
}

func TestHOTP_Validate(t *testing.T) {
	for _, tt := range hotpCases {
		hotp := NewHOTP([]byte(tt.Secret))
		assert.True(t, hotp.Validate(
			tt.Counter,
			tt.Code,
			WithDigit(tt.Digit),
			WithHashFunc(tt.HashFunc),
		))
	}
}
