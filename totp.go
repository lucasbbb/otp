package otp

import "time"

type TOTP struct {
	Key []byte
}

func NewTOTP(key []byte) *TOTP {
	return &TOTP{Key: key}
}

func (otp TOTP) Generate(in interface{}, opts ...Option) string {
	options := NewOptions()
	for _, opt := range opts {
		opt(options)
	}

	t := in.(time.Time)
	counter := (t.Unix() - options.StartTime) / int64(options.TimeStep)
	return NewHOTP(otp.Key).Generate(uint64(counter), opts...)
}

func (otp TOTP) Validate(in interface{}, code string, opts ...Option) bool {
	options := NewOptions()
	for _, opt := range opts {
		opt(options)
	}
	t := in.(time.Time)
	counter := (t.Unix() - options.StartTime) / int64(options.TimeStep)
	counters := make([]int64, 0, 2*options.Leeway+1)
	counters = append(counters, counter)
	for i := 1; i <= options.Leeway; i++ {
		counters = append(counters, counter+int64(i))
		counters = append(counters, counter-int64(i))
	}

	hotp := NewHOTP(otp.Key)
	for _, counter := range counters {
		if hotp.Validate(uint64(counter), code, opts...) {
			return true
		}
	}
	return false
}
