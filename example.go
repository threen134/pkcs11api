package main

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/miekg/pkcs11"
)

var NORMAL_APIKEY = ""

// var iv = []byte("663F05F412028F81DA65D26EE56424B2")
var importAESKey = []byte("E5E9FA1BA31ECD1AE84F75CAAA474F3A")

func main() {
	p := pkcs11.New("./pkcs11-grep11-amd64.so")
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, NORMAL_APIKEY)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	fmt.Println("###############使用对成密钥作为临时KEK, 导入密钥###################")
	example1(p, session, "mytoken", "mytoken")

	fmt.Println("###############使用非成密钥作为临时KEK, 导入密钥###################")
	example2(p, session, "mytoken2", "mytoken2")

}

func example1(p *pkcs11.Ctx, session pkcs11.SessionHandle, token_lable, token_id string) {
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		// pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		// pkcs11.NewAttribute(pkcs11.CKA_ID, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 16),
	}

	fmt.Println("产生一个临时AES key")
	aesKeyHandle, err := p.GenerateKey(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		keyTemplate,
	)
	if err != nil {
		fmt.Print("generate temp aes key failed")
		panic(err)
	}
	fmt.Println("产生一个临时AES key 成功")

	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, make([]byte, 16))}, aesKeyHandle); err != nil {
		fmt.Printf("encrypt init failed")
		panic(err)
	}

	fmt.Println("加密导入密钥")
	encryptedAES, err := p.Encrypt(session, importAESKey)
	if err != nil {
		fmt.Println("encrypted AES key failed")
		panic(err)
	}
	fmt.Println("加密导入密钥成功")
	base64Output(encryptedAES)

	//Unwrap the AES key
	importedKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, token_lable),
		pkcs11.NewAttribute(pkcs11.CKA_ID, token_id),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 128/8),
	}

	fmt.Println("开始解包裹")
	keyImport, err := p.UnwrapKey(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, make([]byte, 16))},
		aesKeyHandle,
		encryptedAES,
		importedKeyTemplate,
	)
	if err != nil {
		fmt.Println("unwrap key failed")
		panic(err)
	}

	fmt.Println("开始解包裹成功")

	fmt.Println("开始测试加密")
	fmt.Println("使用导入的密钥加密")
	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, make([]byte, 16))}, keyImport); err != nil {
		fmt.Printf("encrypt init failed")
		panic(err)
	}

	plainText := []byte("the text need to encrypted to verify kay.")

	target1, err := p.Encrypt(session, plainText)
	if err != nil {
		fmt.Println("encrypted AES key failed")
		panic(err)
	}
	base64Output(target1)

	target2, err := AesEncrypt(plainText, importAESKey)
	if err != nil {
		panic(err)
	}
	base64Output(target2)
	if bytes.Equal(target1, target2) {
		fmt.Println(" 用导入后的密钥与明文密钥在本地加密同一段数据，他们的结果是一样的，说明导入的密钥是正确的。")
	} else {
		fmt.Println("导入失败")
	}
}

func example2(p *pkcs11.Ctx, session pkcs11.SessionHandle, token_lable, token_id string) {
	fmt.Println("产生一个临时rsa key")

	publicKeyTemplate := []*pkcs11.Attribute{
		//pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		// pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		//pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		//pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		//pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}
	pubKeyHandle, privateKeyHandle, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)

	if err != nil {
		fmt.Print("generate temp rsa key failed")
		panic(err)
	}
	fmt.Println("产生一个临时RSA key 成功")

	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, make([]byte, 16))}, pubKeyHandle); err != nil {
		fmt.Printf("encrypt init failed")
		panic(err)
	}

	fmt.Println("加密导入密钥")
	encryptedAES, err := p.Encrypt(session, importAESKey)
	if err != nil {
		fmt.Println("encrypted AES key failed")
		panic(err)
	}
	fmt.Println("加密导入密钥成功")
	base64Output(encryptedAES)

	//Unwrap the AES key
	importedKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, token_lable),
		pkcs11.NewAttribute(pkcs11.CKA_ID, token_id),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 128/8),
	}

	fmt.Println("开始解包裹")
	keyImport, err := p.UnwrapKey(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)},
		privateKeyHandle,
		encryptedAES,
		importedKeyTemplate,
	)
	if err != nil {
		fmt.Println("unwrap key failed")
		panic(err)
	}

	fmt.Println("开始解包裹成功")

	fmt.Println("开始测试加密")
	fmt.Println("使用导入的密钥加密")
	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, make([]byte, 16))}, keyImport); err != nil {
		fmt.Printf("encrypt init failed")
		panic(err)
	}

	plainText := []byte("the text need to encrypted to verify kay.")

	target1, err := p.Encrypt(session, plainText)
	if err != nil {
		fmt.Println("encrypted AES key failed")
		panic(err)
	}
	base64Output(target1)

	target2, err := AesEncrypt(plainText, importAESKey)
	if err != nil {
		panic(err)
	}
	base64Output(target2)
	if bytes.Equal(target1, target2) {
		fmt.Println(" 用导入后的密钥与明文密钥在本地加密同一段数据，他们的结果是一样的，说明导入的密钥是正确的。")
	} else {
		fmt.Println("导入失败")
	}
}

//AesEncrypt 加密
func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	//创建加密实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//判断加密快的大小
	blockSize := block.BlockSize()
	//填充
	encryptBytes := pkcs7Padding(data, blockSize)
	//初始化加密数据接收切片
	crypted := make([]byte, len(encryptBytes))
	//使用cbc加密模式
	blockMode := cipher.NewCBCEncrypter(block, make([]byte, 16))
	//执行加密
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

//pkcs7Padding 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	//判断缺少几位长度。最少1，最多 blockSize
	padding := blockSize - len(data)%blockSize
	//补足位数。把切片[]byte{byte(padding)}复制padding个
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// https://blog.csdn.net/qq_28058509/article/details/120997693
// https://www.systutorials.com/how-to-generate-rsa-private-and-public-key-pair-in-go-lang/
func generateRSAPairLocal() (privateKeyBytes, publicKeyBytes []byte) {
	//生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	//生成公钥
	publicKey := &privateKey.PublicKey
	privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyBytes = x509.MarshalPKCS1PublicKey(publicKey)
	return privateKeyBytes, publicKeyBytes
}

func base64Output(input []byte) {
	fmt.Println(base64.RawStdEncoding.EncodeToString(input))
}

func encryptAESUpdate(p *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle, plainOrigin []byte) (ciphertext []byte, err error) {
	plaintexts := chunkSlice(plainOrigin, 16)

	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)}, key); err != nil {
		return nil, err
	}
	fmt.Println("EncryptInit")

	var output, plaintext []byte
	for _, input := range plaintexts {
		plaintext = append(plaintext, input...)
		if output, err = p.EncryptUpdate(session, input); err != nil {
			fmt.Println(input)
			return nil, err
		}
		fmt.Println(input)
		fmt.Printf("output: %v", output)
		ciphertext = append(ciphertext, output...)
	}
	fmt.Println("start final")
	if output, err = p.EncryptFinal(session); err != nil {
		return nil, err
	}
	if bytes.Compare(plainOrigin, plaintext) != 0 {
		return nil, fmt.Errorf("here is a bug")
	}
	return ciphertext, nil
}

func chunkSlice(slice []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize

		// necessary check to avoid slicing beyond
		// slice capacity
		if end > len(slice) {
			end = len(slice)
		}

		chunks = append(chunks, slice[i:end])
	}

	return chunks
}
