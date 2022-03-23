package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type totpCase struct {
	T        time.Time
	HashFunc func() hash.Hash
	Digit    int
	TimeStep int
	Code     string
	Secret   string
}

var (
	// https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
	totpCases = []totpCase{
		{time.Unix(59, 0), sha1.New, 8, 30, "94287082", "12345678901234567890"},
		{time.Unix(1111111109, 0), sha1.New, 8, 30, "07081804", "12345678901234567890"},
		{time.Unix(1111111111, 0), sha1.New, 8, 30, "14050471", "12345678901234567890"},
		{time.Unix(1234567890, 0), sha1.New, 8, 30, "89005924", "12345678901234567890"},
		{time.Unix(2000000000, 0), sha1.New, 8, 30, "69279037", "12345678901234567890"},
		{time.Unix(20000000000, 0), sha1.New, 8, 30, "65353130", "12345678901234567890"},
		{time.Unix(59, 0), sha256.New, 8, 30, "46119246", "12345678901234567890123456789012"},
		{time.Unix(1111111109, 0), sha256.New, 8, 30, "68084774", "12345678901234567890123456789012"},
		{time.Unix(1111111111, 0), sha256.New, 8, 30, "67062674", "12345678901234567890123456789012"},
		{time.Unix(1234567890, 0), sha256.New, 8, 30, "91819424", "12345678901234567890123456789012"},
		{time.Unix(2000000000, 0), sha256.New, 8, 30, "90698825", "12345678901234567890123456789012"},
		{time.Unix(20000000000, 0), sha256.New, 8, 30, "77737706", "12345678901234567890123456789012"},
		{time.Unix(59, 0), sha512.New, 8, 30, "90693936", "1234567890123456789012345678901234567890123456789012345678901234"},
		{time.Unix(1111111109, 0), sha512.New, 8, 30, "25091201", "1234567890123456789012345678901234567890123456789012345678901234"},
		{time.Unix(1111111111, 0), sha512.New, 8, 30, "99943326", "1234567890123456789012345678901234567890123456789012345678901234"},
		{time.Unix(1234567890, 0), sha512.New, 8, 30, "93441116", "1234567890123456789012345678901234567890123456789012345678901234"},
		{time.Unix(2000000000, 0), sha512.New, 8, 30, "38618901", "1234567890123456789012345678901234567890123456789012345678901234"},
		{time.Unix(20000000000, 0), sha512.New, 8, 30, "47863826", "1234567890123456789012345678901234567890123456789012345678901234"},
	}
)

func TestTOTP_Generate(t *testing.T) {
	for _, tt := range totpCases {
		totp := NewTOTP([]byte(tt.Secret))
		assert.Equal(t, tt.Code, totp.Generate(
			tt.T,
			WithDigit(tt.Digit),
			WithHashFunc(tt.HashFunc),
			WithTimeStep(tt.TimeStep),
		))
	}
}

func TestTOTP_Validate(t *testing.T) {
	for _, tt := range totpCases {
		totp := NewTOTP([]byte(tt.Secret))
		assert.True(t, totp.Validate(
			tt.T,
			tt.Code,
			WithDigit(tt.Digit),
			WithHashFunc(tt.HashFunc),
			WithTimeStep(tt.TimeStep),
		))
	}
}
