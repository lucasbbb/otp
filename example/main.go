package main

import (
	"encoding/base32"
	"net/http"

	"github.com/lucasbbb/otp"
)

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
