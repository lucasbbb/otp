package otp

import (
	"reflect"
	"testing"
)

func TestParseFromURL(t *testing.T) {
	type args struct {
		rawURL string
	}
	tests := []struct {
		name    string
		args    args
		want    *Key
		wantErr bool
	}{
		{
			name:    "empty url",
			args:    args{rawURL: ""},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid type",
			args:    args{rawURL: "otpauth://otp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid secret",
			args:    args{rawURL: "otpauth://totp/Example:alice@google.com?secret=&issuer=Example"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid digits",
			args:    args{rawURL: "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=foo"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid counter",
			args:    args{rawURL: "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&counter=foo"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid counter",
			args:    args{rawURL: "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=foo"},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid totp",
			args: args{rawURL: "otpauth://hotp/Example:alice@google.com?counter=60&digits=6&issuer=Example&secret=JBSWY3DPEHPK3PXP"},
			want: &Key{
				rawURL:    "otpauth://hotp/Example:alice@google.com?counter=60&digits=6&issuer=Example&secret=JBSWY3DPEHPK3PXP",
				Typ:       "hotp",
				Issuer:    "Example",
				Account:   "alice@google.com",
				Secret:    []byte{'H', 'e', 'l', 'l', 'o', '!', 0xDE, 0xAD, 0xBE, 0xEF},
				Digits:    6,
				Period:    30,
				Counter:   60,
				Algorithm: "SHA1",
			},
			wantErr: false,
		},
		{
			name: "valid htop",
			args: args{rawURL: "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=60"},
			want: &Key{
				rawURL:    "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=60",
				Typ:       "totp",
				Issuer:    "Example",
				Account:   "alice@google.com",
				Secret:    []byte{'H', 'e', 'l', 'l', 'o', '!', 0xDE, 0xAD, 0xBE, 0xEF},
				Digits:    6,
				Period:    60,
				Algorithm: "SHA1",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFromURL(tt.args.rawURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFromURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseFromURL() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKey_RawURL(t *testing.T) {
	type fields struct {
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
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "valid hotp",
			fields: fields{
				rawURL:    "",
				Typ:       "hotp",
				Issuer:    "Example",
				Account:   "alice@google.com",
				Secret:    []byte{'H', 'e', 'l', 'l', 'o', '!', 0xDE, 0xAD, 0xBE, 0xEF},
				Digits:    6,
				Period:    30,
				Counter:   60,
				Algorithm: "SHA256",
			},
			want: "otpauth://hotp/Example:alice@google.com?algorithm=SHA256&counter=60&digits=6&issuer=Example&secret=JBSWY3DPEHPK3PXP",
		},
		{
			name: "valid totp",
			fields: fields{
				Typ:       "totp",
				Issuer:    "Example",
				Account:   "alice@google.com",
				Secret:    []byte{'H', 'e', 'l', 'l', 'o', '!', 0xDE, 0xAD, 0xBE, 0xEF},
				Digits:    6,
				Period:    60,
				Algorithm: "SHA256",
			},
			want: "otpauth://totp/Example:alice@google.com?algorithm=SHA256&digits=6&issuer=Example&period=60&secret=JBSWY3DPEHPK3PXP",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &Key{
				rawURL:    tt.fields.rawURL,
				Typ:       tt.fields.Typ,
				Issuer:    tt.fields.Issuer,
				Account:   tt.fields.Account,
				Secret:    tt.fields.Secret,
				Period:    tt.fields.Period,
				Counter:   tt.fields.Counter,
				Digits:    tt.fields.Digits,
				Algorithm: tt.fields.Algorithm,
			}
			if got := k.RawURL(); got != tt.want {
				t.Errorf("RawURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
