# otp
One Time Password package for Go/Golang developers

[中文文档](https://github.com/lucasbbb/otp/README_CN.md)

## Contents

- [Contents](#contents)
- [What is OTP](#What is OTP)
- [How to Use](#How to Use)

## What is OTP

A one-time password (OTP) is an automatically generated numeric string that authenticates a user for a single transaction or login session.

The most important advantage addressed by OTPs is that, in contrast to static passwords, they are not vulnerable to replay attacks. 

There are two kinds of OTP which are [HOTP](https://datatracker.ietf.org/doc/html/rfc4226) and [TOTP](https://datatracker.ietf.org/doc/html/rfc6238). The vast majority of OTP today is TOTP. Very few people still use HTOP.

By the way, the [TOTP](https://datatracker.ietf.org/doc/html/rfc6238) RFC document has a mistake. [More details](http://www.rfc-editor.org/errata_search.php?rfc=6238) can be found here if you are interested.

## How to Use

Before using this package, you need to install Go and set your Go workspace first.

1. Use the below Go command to install the package.

```sh
$ go get -u github.com/lucasbbb/otp
```

2. Import it in your code.

```go
import "github.com/lucasbbb/otp"
```

3. Generate a Key and show it's QR code.

```go
func main() {
    http.HandleFunc("/image", QRImage)
    _ = http.ListenAndServe(":6789", nil)
}

func QRImage(w http.ResponseWriter, req *http.Request) {
    secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("INEECT2TEBEVGICBEBGECRCEIVJA")
    key := otp.Key{
        Issuer:  "example",
        Account: "foo",
        Typ:     "totp",
        Secret:  secret,
    }
    image, _ := key.QRImage(256)
    _, _ = w.Write(image)
}
```

4. User scan the QR code with Google Authenticator or other apps.

![Google Authenticator](https://github.com/lucasbbb/otp/docs/google.PNG)

5. Compare the code with the sever generated code.

```go
func VerifyOTP(accountName, code string) {
	now := time.Now()
	// Get user's secret from DATABASE or other repository.
	// SELECT secret FORM user WHERE `account_name` = accountName
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("INEECT2TEBEVGICBEBGECRCEIVJA")
	res := otp.NewTOTP(secret).Validate(now, code)
	if res {
		// Continue your business logic.
	} else {
		// Abort.
	}
}
```