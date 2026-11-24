//go:build !reference_embedded

package fingerprint

import "errors"

func embeddedReference() (string, func(), error) {
	return "", nil, errors.New("此开发版未内嵌参考库，请设置 reference-dir 或使用 scripts/build.sh")
}
