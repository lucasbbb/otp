# otp
OTP 工具包，实现了 HTOP 和 TOTP.

[English Document](https://github.com/lucasbbb/otp/blob/main/README.md)

## 目录

- [目录](#目录)
- [OTP 概念](#OTP概念)
- [如何使用](#如何使用)

## OTP概念

一次性密码（one-time password，简称OTP）又称为动态密码，是通过算法生成的只能使用一次的密码，可以用于需要用户做二次确认的场景，如输入完密码之后的二次认证。

相对于静态密码，OTP 最重要的优点是它们不容易受到重放攻击（replay attack）。

现在有两种 OTP 的实现方式：[基于计数器的 HOTP](https://datatracker.ietf.org/doc/html/rfc4226) 和 [基于时间的TOTP](https://datatracker.ietf.org/doc/html/rfc6238) 。 目前大部分场景都是在使用 TOTP，它避免了 HTOP 客户端和服务器计数不一致导致的同步问题。

注意， [TOTP的RFC文档](https://datatracker.ietf.org/doc/html/rfc6238) 有一个错误。 可以点击 [这里](http://www.rfc-editor.org/errata_search.php?rfc=6238) 了解更多上下文。

## 如何使用

在使用本工具包之前，你需要先安装 Go 并配置好工作环境。

1. 通过下边的命令安装此包

```sh
$ go get -u github.com/lucasbbb/otp
```

2. 引入包

```go
import "github.com/lucasbbb/otp"
```

3. 生成密钥的二维码并展示给用户

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

4. 用户可以通过 Google Authenticator 或者其他的 App 来扫码

![Google Authenticator](https://github.com/lucasbbb/otp/docs/google.PNG)

5. 对比用户输入的 Code 是否和服务端生成的一致

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