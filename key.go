package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"

	"github.com/lucasbbb/venus/condition"
	"github.com/pkg/errors"
	"github.com/skip2/go-qrcode"
)

var (
	ErrInvalidType     = fmt.Errorf("valid type must be hotp or totp")
	ErrSecretRequired  = fmt.Errorf("the secret is required")
	ErrInvalidSecret   = fmt.Errorf("the secret must be a base32 encoded string")
	ErrInvalidDigits   = fmt.Errorf("parse digits to int failed")
	ErrCounterRequired = fmt.Errorf("the counter is required for hotp")
	ErrInvalidCounter  = fmt.Errorf("parse counter to uint failed")
	ErrInvalidPeriod   = fmt.Errorf("parse period to uint failed")
)

type Key struct {
	rawURL    string
	Typ       string
	Issuer    string
	Account   string
	Secret    []byte
	Period    int
	Counter   uint64
	Digits    int
	Algorithm string
}

// ParseFromURL
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func ParseFromURL(rawURL string) (*Key, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	// Valid types are hotp and totp.
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format#types
	typ := u.Host
	if typ != "totp" && typ != "hotp" {
		return nil, ErrInvalidType
	}

	// The issuer and account are included in the path.
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format#label
	path := strings.TrimPrefix(u.Path, "/")
	index := strings.Index(path, ":")
	issuer := condition.StringIf(index != -1, path[:index], "")
	accountName := condition.StringIf(index != -1, path[index+1:], path)

	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters
	issuer = condition.StringIf(issuer == "", u.Query().Get("issuer"), issuer)

	secretStr := u.Query().Get("secret")
	secretStr = strings.ToUpper(secretStr)
	if secretStr == "" {
		return nil, ErrSecretRequired
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretStr)
	if err != nil {
		return nil, errors.Wrapf(ErrInvalidSecret, err.Error())
	}

	digits := 6
	if digitsStr := u.Query().Get("digits"); digitsStr != "" {
		digits, err = strconv.Atoi(digitsStr)
		if err != nil {
			return nil, errors.Wrapf(ErrInvalidDigits, err.Error())
		}
	}

	var alg string
	switch strings.ToUpper(u.Query().Get("algorithm")) {
	case "SHA512":
		alg = "SHA512"
	case "SHA256":
		alg = "SHA256"
	default:
		alg = "SHA1"
	}

	var counter uint64
	if typ == "hotp" {
		counterStr := u.Query().Get("counter")
		if counterStr == "" {
			return nil, errors.Wrapf(ErrCounterRequired, err.Error())
		}
		counter, err = strconv.ParseUint(counterStr, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(ErrInvalidCounter, err.Error())
		}
	}

	period := 30
	if typ == "totp" {
		if periodStr := u.Query().Get("period"); periodStr != "" {
			period, err = strconv.Atoi(periodStr)
			if err != nil {
				return nil, errors.Wrapf(ErrInvalidPeriod, err.Error())
			}
		}
	}

	return &Key{
		rawURL:    rawURL,
		Typ:       typ,
		Account:   accountName,
		Secret:    secret,
		Issuer:    issuer,
		Digits:    digits,
		Algorithm: alg,
		Counter:   counter,
		Period:    period,
	}, nil
}

func (k *Key) RawURL() string {
	if k.rawURL == "" {
		var u url.URL
		u.Scheme = "otpauth"
		u.Host = k.Typ
		u.Path = fmt.Sprintf("%s:%s", k.Issuer, k.Account)
		query := u.Query()
		query.Add("issuer", k.Issuer)
		query.Add("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(k.Secret))
		query.Add("digits", strconv.Itoa(k.Digits))
		query.Add("algorithm", k.Algorithm)
		if k.Typ == "hotp" {
			query.Add("counter", strconv.FormatUint(k.Counter, 10))
		}
		if k.Typ == "totp" {
			query.Add("period", strconv.Itoa(k.Period))
		}
		u.RawQuery = query.Encode()
		k.rawURL = u.String()
	}
	return k.rawURL
}

func (k *Key) Alg() func() hash.Hash {
	switch k.Algorithm {
	case "SHA512":
		return sha512.New
	case "SHA256":
		return sha256.New
	default:
		return sha1.New
	}
}

func (k *Key) QRImage(size int) ([]byte, error) {
	size = condition.IntIf(size > 0, size, 256)
	return qrcode.Encode(k.RawURL(), qrcode.Medium, size)
}
