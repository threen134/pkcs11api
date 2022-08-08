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

var NORMAL_APIKEY = "key"

// var iv = []byte("663F05F412028F81DA65D26EE56424B2")
var importAESKey = []byte("E5E9FA1BA31ECD1AE84F75CAAA474F3A")

func main() {
	fmt.Printf("%d", len(iv))
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

	tokenLabel := "tempKey"
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, tokenLabel),
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
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "finaletest"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, "finaletest"),
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

	testplan := []byte("the text need to encrypted to verify kay.")

	target1, err := p.Encrypt(session, testplan)
	if err != nil {
		fmt.Println("encrypted AES key failed")
		panic(err)
	}
	fmt.Println(target1)

	target2, err := AesEncrypt(testplan, importAESKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(target2)
	if bytes.Compare(target1,target2) == 0 {
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

func generateRSAKeyPair_tag1(p *pkcs11.Ctx, session pkcs11.SessionHandle, tokenPersistent bool, pubTokenLabel, privateTokenLabel string) (publicHandle, privateHandle pkcs11.ObjectHandle, err error) {
	// publicKeyTemplate := []*pkcs11.Attribute{
	// 	pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
	// 	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	// 	pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
	// 	pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
	// 	pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	// 	pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	// 	pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
	// 	pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
	// 	pkcs11.NewAttribute(pkcs11.CKA_LABEL, pubTokenLabel),
	// 	pkcs11.NewAttribute(pkcs11.CKA_ID, pubTokenLabel),
	// 	pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	// }
	// privateKeyTemplate := []*pkcs11.Attribute{
	// 	pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
	// 	pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	// 	pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	// 	pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
	// 	pkcs11.NewAttribute(pkcs11.CKA_LABEL, privateTokenLabel),
	// 	pkcs11.NewAttribute(pkcs11.CKA_ID, privateTokenLabel),
	// 	pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	// 	pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	// }

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, pubTokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, pubTokenLabel),

		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, privateTokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, privateTokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),

		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
	}
	publicHandle, privateHandle, err = p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	return
}

func generateRSAKeyPairForWrapUnwrap(p *pkcs11.Ctx, session pkcs11.SessionHandle) {

	publicKeyTemplate := []*pkcs11.Attribute{
		//pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, 17),
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
	pbkHandle, privateKeyHandle, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		fmt.Errorf("fail to create wrap and unwrap key pairs ", err)
	}

	// Generate a AES key
	keyLen := 128 // bits
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "newtest123"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, "newtest123"),
		// pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		// pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keyLen/8),
	}

	aesHandle, err := p.GenerateKey(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		keyTemplate,
	)
	fmt.Printf("aesHandle: %v\n", aesHandle)

	if err != nil {
		fmt.Errorf("fail to aes key", err)
	}

	// Wrap the AES key
	wrappedKey, err := p.WrapKey(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)},
		aesHandle,
		pbkHandle,
	)
	if err != nil {
		fmt.Errorf("fail to wrap aes key", err)
	}
	fmt.Println("111111")
	base64Output(wrappedKey)
	fmt.Printf("%d", len(wrappedKey))

	//Unwrap the AES key
	unwrapkeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		// pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		// pkcs11.NewAttribute(pkcs11.CKA_ID, tokenLabel),
		// pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		//pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keyLen/8),
	}
	result, err := p.UnwrapKey(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)},
		privateKeyHandle,
		wrappedKey,
		unwrapkeyTemplate,
	)
	if err != nil {
		fmt.Errorf("fail to unwrap aes key", err)
		fmt.Printf("result: %v\n", result)
	}

}

/*

// Example_wrapAndUnWrapKey wraps an AES key with a RSA public key and then unwraps it with the RSA private key
// Flow: connect, generate AES key, generate RSA key pair, wrap/unwrap AES key with RSA key pair
func Example_wrapAndUnwrapKey() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	// Generate a AES key
	aesKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   128 / 8,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // must be true to be wrapped
	}
	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(aesKeyTemplate),
	}
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generate AES key error: %s", err))
	} else {
		fmt.Println("Generated AES key")
	}

	// Generate RSA key pairs
	publicExponent := 17
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_WRAP:            true, // to wrap a key
		ep11.CKA_MODULUS_BITS:    2048,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
		ep11.CKA_EXTRACTABLE:     false,
	}
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:     true,
		ep11.CKA_SENSITIVE:   true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_UNWRAP:      true, // to unwrap a key
		ep11.CKA_EXTRACTABLE: false,
	}
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}
	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated RSA PKCS key pair")

	wrapKeyRequest := &pb.WrapKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:  generateKeyPairResponse.PubKeyBytes,
		Key:  generateKeyResponse.KeyBytes,
	}

	// Wrap the AES key
	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Wrap AES key error: %s", err))
	}
	fmt.Println("Wrapped AES key")

	aesUnwrapKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:       ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:    ep11.CKK_AES,
		ep11.CKA_VALUE_LEN:   128 / 8,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // must be true to be wrapped
	}
	unwrapRequest := &pb.UnwrapKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:      generateKeyPairResponse.PrivKeyBytes,
		Wrapped:  wrapKeyResponse.Wrapped,
		Template: util.AttributeMap(aesUnwrapKeyTemplate),
	}

	// Unwrap the AES key
	unwrappedResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapRequest)
	if err != nil {
		panic(fmt.Errorf("Unwrap AES key error: %s", err))
	}
	if !bytes.Equal(generateKeyResponse.GetCheckSum()[:3], unwrappedResponse.GetCheckSum()[:3]) {
		panic(fmt.Errorf("Unwrap AES key has a different checksum than the original key"))
	} else {
		fmt.Println("Unwrapped AES key")
	}


*/

/*
Purpose: Generate RSA keypair with a given name and persistence.
Inputs: test object
	context
	session handle
	tokenLabel: string to set as the token labels
	tokenPersistent: boolean. Whether or not the token should be
			session based or persistent. If false, the
			token will not be saved in the HSM and is
			destroyed upon termination of the session.
Outputs: creates persistent or ephemeral tokens within the HSM.
Returns: object handles for public and private keys. Fatal on error.
*/
func generateRSAKeyPair(p *pkcs11.Ctx, session pkcs11.SessionHandle, tokenLabel string, tokenPersistent bool) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	/*
		inputs: test object, context, session handle
			tokenLabel: string to set as the token labels
			tokenPersistent: boolean. Whether or not the token should be
					session based or persistent. If false, the
					token will not be saved in the HSM and is
					destroyed upon termination of the session.
		outputs: creates persistent or ephemeral tokens within the HSM.
		returns: object handles for public and private keys.
	*/

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, tokenLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	pbk, pvk, e := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)

	return pbk, pvk, e
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

func generateAESKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, token bool, CKA_ID, tokenLabel string) (pkcs11.ObjectHandle, error) {
	keyLen := 128 // bits
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, token),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keyLen/8),
	}

	return p.GenerateKey(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		keyTemplate,
	)
}

func encryptAES(p *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle, plaintext []byte) (ciphertext []byte, err error) {
	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, nil)}, key); err != nil {
		return nil, err
	}
	return p.Encrypt(session, plaintext)
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

// func encryptAES(p *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle, plaintext []byte) (ciphertext []byte, err error) {
// 	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)}, key); err != nil {
// 		return nil, err
// 	}
// 	return p.Encrypt(session, plaintext)
// }

func encryptAESUpdating(p *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle, plainOrigin, iv []byte) (ciphertext []byte, err error) {
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

func EncryptUpdate123(p *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle, plaint, iv []byte) []byte {
	var err error
	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}, key); err != nil {
		panic(err)
	}
	var ciphertexts []byte
	var output []byte
	plaintexts := chunkSlice(plaint, 16)

	for _, input := range plaintexts {
		if output, err = p.EncryptUpdate(session, input); err != nil {
			panic(err)
		}
		ciphertexts = append(ciphertexts, output...)
	}
	if output, err = p.EncryptFinal(session); err != nil {
		panic(err)
	}
	ciphertexts = append(ciphertexts, output...)
	return ciphertexts
}

func unwrapAES(p *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle, encryptedKey []byte, tokenLabel string) (pkcs11.ObjectHandle, error) {
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		//	pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		// pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	return p.UnwrapKey(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, make([]byte, 16))},
		key,
		encryptedKey,
		privateKeyTemplate,
	)
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
