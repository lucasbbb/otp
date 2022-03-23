package otp

import (
	"crypto/sha1"
	"hash"
)

type OTP interface {
	Generate(in interface{}, opts ...Option) string
	Validate(in interface{}, code string, opts ...Option) bool
}

type Options struct {
	Digit     int
	HashFunc  func() hash.Hash
	TimeStep  int
	Leeway    int
	StartTime int64
}

func NewOptions() *Options {
	return &Options{
		Digit:     6,
		HashFunc:  sha1.New,
		TimeStep:  30,
		StartTime: 0,
	}
}

type Option func(*Options)

// WithDigit
// The default digit = 6
func WithDigit(digit int) Option {
	return func(options *Options) {
		options.Digit = digit
	}
}

// WithHashFunc
// The default hash func is sha1.New
// You can use other hash func such as: sha256.New, sha512.New, md5.New
func WithHashFunc(f func() hash.Hash) Option {
	return func(options *Options) {
		options.HashFunc = f
	}
}

// WithTimeStep
// The default time step is 30s.
func WithTimeStep(step int) Option {
	return func(options *Options) {
		options.TimeStep = step
	}
}

// WithStartTime
// The default start time = 0
// The UNIX time to start counting time steps
func WithStartTime(start int64) Option {
	return func(options *Options) {
		options.StartTime = start
	}
}
