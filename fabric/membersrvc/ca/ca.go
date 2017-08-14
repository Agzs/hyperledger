/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql" //sql包自动创建和释放连接;
	"encoding/json"
	"encoding/pem" //pem编码
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv" //字符串和基本数据类型之间转换
	"strings"
	"sync" //处理同步需求
	"time"

	gp "google/protobuf" //Google的数据交换格式

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/flogging"
	pb "github.com/hyperledger/fabric/membersrvc/protos"
	_ "github.com/mattn/go-sqlite3" // This blank import is required to load sqlite3 driver
	"github.com/op/go-logging"
	"github.com/spf13/viper" //满足不同的对配置文件的使用的要求，解决配置问题
)

var caLogger = logging.MustGetLogger("ca") //根据模块名称创建并返回ca的Logger对象。

// CA is the base certificate authority.
type CA struct { // CA结构体
	db *sql.DB // DB是表示零个或多个底层连接池的数据库句柄。

	path string //定义文件路径

	priv *ecdsa.PrivateKey //CA私钥
	cert *x509.Certificate //CA的X509证书
	raw  []byte            //CA的pem文件内容的解码字节
}

// CertificateSpec defines the parameter used to create a new certificate.
type CertificateSpec struct { //证书结构体
	id           string
	commonName   string
	serialNumber *big.Int
	pub          interface{}       //证书的注册公钥
	usage        x509.KeyUsage     //keyusage表示一个集合，该集合包含了对于一个给定key的有效操作
	NotBefore    *time.Time        //证书有效时间的起始时间，该程序中默认为当前时间的一分钟之前。
	NotAfter     *time.Time        //证书失效时间，该程序中默认为期90天
	ext          *[]pkix.Extension //可扩展字段
}

// AffiliationGroup struct
type AffiliationGroup struct { //隶属关系结构体
	name     string
	parentID int64
	parent   *AffiliationGroup
	preKey   []byte
}

var (
	mutex          = &sync.RWMutex{} //互斥
	caOrganization string            //pki.ca.subject.organization
	caCountry      string            //pki.ca.subject.country
	rootPath       string            //server.rootpath
	caDir          string            //server.cadir
)

// NewCertificateSpec creates a new certificate spec
func NewCertificateSpec(id string, commonName string, serialNumber *big.Int, pub interface{}, usage x509.KeyUsage, notBefore *time.Time, notAfter *time.Time, opt ...pkix.Extension) *CertificateSpec {
	spec := new(CertificateSpec)
	spec.id = id
	spec.commonName = commonName
	spec.serialNumber = serialNumber
	spec.pub = pub
	spec.usage = usage
	spec.NotBefore = notBefore
	spec.NotAfter = notAfter
	spec.ext = &opt
	return spec
}

// 3 >> 1 >> 2
// 4 >> 2

// NewDefaultPeriodCertificateSpec creates a new certificate spec with notBefore a minute ago and not after 90 days from notBefore.
// 1，新的默认期限证书
func NewDefaultPeriodCertificateSpec(id string, serialNumber *big.Int, pub interface{}, usage x509.KeyUsage, opt ...pkix.Extension) *CertificateSpec {
	return NewDefaultPeriodCertificateSpecWithCommonName(id, id, serialNumber, pub, usage, opt...)
}

// NewDefaultPeriodCertificateSpecWithCommonName creates a new certificate spec with notBefore a minute ago and not after 90 days from notBefore and a specifc commonName.
// 2，有通用名称的新的默认期限证书
func NewDefaultPeriodCertificateSpecWithCommonName(id string, commonName string, serialNumber *big.Int, pub interface{}, usage x509.KeyUsage, opt ...pkix.Extension) *CertificateSpec {
	notBefore := time.Now().Add(-1 * time.Minute)
	notAfter := notBefore.Add(time.Hour * 24 * 90)
	return NewCertificateSpec(id, commonName, serialNumber, pub, usage, &notBefore, &notAfter, opt...)
}

// NewDefaultCertificateSpec creates a new certificate spec with serialNumber = 1, notBefore a minute ago and not after 90 days from notBefore.
// 3，序列号为1的默认期限证书
func NewDefaultCertificateSpec(id string, pub interface{}, usage x509.KeyUsage, opt ...pkix.Extension) *CertificateSpec {
	serialNumber := big.NewInt(1)
	return NewDefaultPeriodCertificateSpec(id, serialNumber, pub, usage, opt...)
}

// NewDefaultCertificateSpecWithCommonName creates a new certificate spec with serialNumber = 1, notBefore a minute ago and not after 90 days from notBefore and a specific commonName.
// 4，有通用名称且序列号为1的默认期限证书
func NewDefaultCertificateSpecWithCommonName(id string, commonName string, pub interface{}, usage x509.KeyUsage, opt ...pkix.Extension) *CertificateSpec {
	serialNumber := big.NewInt(1)
	return NewDefaultPeriodCertificateSpecWithCommonName(id, commonName, serialNumber, pub, usage, opt...)
}

// CacheConfiguration caches the viper configuration，暂存配置文件
func CacheConfiguration() {
	caOrganization = viper.GetString("pki.ca.subject.organization")
	caCountry = viper.GetString("pki.ca.subject.country")
	rootPath = viper.GetString("server.rootpath")
	caDir = viper.GetString("server.cadir")
}

// GetID returns the spec's ID field/value
func (spec *CertificateSpec) GetID() string {
	return spec.id
}

// GetCommonName returns the spec's Common Name field/value
func (spec *CertificateSpec) GetCommonName() string {
	return spec.commonName
}

// GetSerialNumber returns the spec's Serial Number field/value
func (spec *CertificateSpec) GetSerialNumber() *big.Int {
	return spec.serialNumber
}

// GetPublicKey returns the spec's Public Key field/value
func (spec *CertificateSpec) GetPublicKey() interface{} {
	return spec.pub
}

// GetUsage returns the spec's usage (which is the x509.KeyUsage) field/value
func (spec *CertificateSpec) GetUsage() x509.KeyUsage {
	return spec.usage
}

// GetNotBefore returns the spec NotBefore (time.Time) field/value
func (spec *CertificateSpec) GetNotBefore() *time.Time {
	return spec.NotBefore
}

// GetNotAfter returns the spec NotAfter (time.Time) field/value
func (spec *CertificateSpec) GetNotAfter() *time.Time {
	return spec.NotAfter
}

// GetOrganization returns the spec's Organization field/value
func (spec *CertificateSpec) GetOrganization() string {
	return caOrganization
}

// GetCountry returns the spec's Country field/value
func (spec *CertificateSpec) GetCountry() string {
	return caCountry
}

// GetSubjectKeyID returns the spec's subject KeyID
func (spec *CertificateSpec) GetSubjectKeyID() *[]byte {
	return &[]byte{1, 2, 3, 4}
}

// GetSignatureAlgorithm returns the X509.SignatureAlgorithm field/value
func (spec *CertificateSpec) GetSignatureAlgorithm() x509.SignatureAlgorithm {
	return x509.ECDSAWithSHA384
}

// GetExtensions returns the sepc's extensions
func (spec *CertificateSpec) GetExtensions() *[]pkix.Extension {
	return spec.ext
}

// TableInitializer is a function type for table initialization
type TableInitializer func(*sql.DB) error

// 初始化公共表格：Certificates、Users、AffiliationGroups， 是上面类型的实例函数
func initializeCommonTables(db *sql.DB) error {
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS Certificates (row INTEGER PRIMARY KEY, id VARCHAR(64), timestamp INTEGER, usage INTEGER, cert BLOB, hash BLOB, kdfkey BLOB)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS Users (row INTEGER PRIMARY KEY, id VARCHAR(64), enrollmentId VARCHAR(100), role INTEGER, metadata VARCHAR(256), token BLOB, state INTEGER, key BLOB)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS AffiliationGroups (row INTEGER PRIMARY KEY, name VARCHAR(64), parent INTEGER, FOREIGN KEY(parent) REFERENCES AffiliationGroups(row))"); err != nil {
		return err
	}
	return nil
}

// NewCA sets up a new CA.
func NewCA(name string, initTables TableInitializer) *CA {
	ca := new(CA)
	flogging.LoggingInit("ca")
	ca.path = filepath.Join(rootPath, caDir) //将rootPath和caDir这两个路径元素连接到路径中

	if _, err := os.Stat(ca.path); err != nil { //Stat返回描述命名文件的文件信息
		caLogger.Info("Fresh start; creating databases, key pairs, and certificates.")

		if err := os.MkdirAll(ca.path, 0755); err != nil { //MkdirAll创建一个名为path的目录，以及任何必要的父项，第二个参数为八进制，表示文件的模式和权限。
			caLogger.Panic(err)
		}
	}

	// open or create certificate database
	db, err := sql.Open("sqlite3", ca.path+"/"+name+".db")
	if err != nil {
		caLogger.Panic(err)
	}

	// Ping验证数据库的连接是否仍然存在，如有必要建立连接。
	if err = db.Ping(); err != nil {
		caLogger.Panic(err)
	}

	// 初始化三大表格
	if err = initTables(db); err != nil {
		caLogger.Panic(err)
	}
	ca.db = db

	// read or create signing key pair，密钥对
	priv, err := ca.readCAPrivateKey(name)
	if err != nil {
		priv = ca.createCAKeyPair(name)
	}
	ca.priv = priv

	// read CA certificate, or create a self-signed CA certificate
	raw, err := ca.readCACertificate(name)
	if err != nil {
		raw = ca.createCACertificate(name, &ca.priv.PublicKey) // 创建CA的证书
	}
	cert, err := x509.ParseCertificate(raw) // ParseCertificate从给定的数据中解析单个证书。
	if err != nil {
		caLogger.Panic(err)
	}

	ca.raw = raw
	ca.cert = cert

	return ca
}

// Stop closes down the CA，关闭CA的数据库
func (ca *CA) Stop() error {
	err := ca.db.Close()
	if err == nil {
		caLogger.Debug("Shutting down CA - Successfully")
	} else {
		caLogger.Debug(fmt.Sprintf("Shutting down CA - Error closing DB [%s]", err))
	}
	return err
}

// 产生CA的密钥对，ECDSA算法
func (ca *CA) createCAKeyPair(name string) *ecdsa.PrivateKey {
	caLogger.Debug("Creating CA key pair.")

	curve := primitives.GetDefaultCurve() //curve表示a = -3的短格式Weierstrass曲线。

	priv, err := ecdsa.GenerateKey(curve, rand.Reader) // 产生密钥对，priv是个私钥结构体，里面包含公钥结构体
	if err == nil {
		raw, _ := x509.MarshalECPrivateKey(priv) // 私钥格式转换
		cooked := pem.EncodeToMemory(            // pem编码
			&pem.Block{
				Type:  "ECDSA PRIVATE KEY",
				Bytes: raw,
			})
		err = ioutil.WriteFile(ca.path+"/"+name+".priv", cooked, 0644)
		if err != nil {
			caLogger.Panic(err)
		}

		raw, _ = x509.MarshalPKIXPublicKey(&priv.PublicKey) //公钥格式转换
		cooked = pem.EncodeToMemory(
			&pem.Block{
				Type:  "ECDSA PUBLIC KEY",
				Bytes: raw,
			})
		err = ioutil.WriteFile(ca.path+"/"+name+".pub", cooked, 0644)
		if err != nil {
			caLogger.Panic(err)
		}
	}
	if err != nil {
		caLogger.Panic(err)
	}

	return priv
}

// 读取CA的私钥
func (ca *CA) readCAPrivateKey(name string) (*ecdsa.PrivateKey, error) {
	caLogger.Debug("Reading CA private key.")

	cooked, err := ioutil.ReadFile(ca.path + "/" + name + ".priv")
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(cooked)
	return x509.ParseECPrivateKey(block.Bytes)
}

// 创建CA的证书，（文件名，公钥）
func (ca *CA) createCACertificate(name string, pub *ecdsa.PublicKey) []byte {
	caLogger.Debug("Creating CA certificate.")

	raw, err := ca.newCertificate(name, pub, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign, nil) // 第三个参数？？？？？
	if err != nil {
		caLogger.Panic(err)
	}

	cooked := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: raw,
		})
	err = ioutil.WriteFile(ca.path+"/"+name+".cert", cooked, 0644)
	if err != nil {
		caLogger.Panic(err)
	}

	return raw
}

//通过CA的名称读取CA的证书
func (ca *CA) readCACertificate(name string) ([]byte, error) {
	caLogger.Debug("Reading CA certificate.")

	cooked, err := ioutil.ReadFile(ca.path + "/" + name + ".cert")
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(cooked)
	return block.Bytes, nil
}

// 通过调用3创建证书，然后加上时间戳
func (ca *CA) createCertificate(id string, pub interface{}, usage x509.KeyUsage, timestamp int64, kdfKey []byte, opt ...pkix.Extension) ([]byte, error) {
	spec := NewDefaultCertificateSpec(id, pub, usage, opt...)
	return ca.createCertificateFromSpec(spec, timestamp, kdfKey, true)
}

// 通过spec创建证书
func (ca *CA) createCertificateFromSpec(spec *CertificateSpec, timestamp int64, kdfKey []byte, persist bool) ([]byte, error) {
	caLogger.Debug("Creating certificate for " + spec.GetID() + ".")

	raw, err := ca.newCertificateFromSpec(spec)
	if err != nil {
		caLogger.Error(err)
		return nil, err
	}

	if persist {
		err = ca.persistCertificate(spec.GetID(), timestamp, spec.GetUsage(), raw, kdfKey)
	}

	return raw, err
}

// 保存证书，添加到数据库中
func (ca *CA) persistCertificate(id string, timestamp int64, usage x509.KeyUsage, certRaw []byte, kdfKey []byte) error {
	mutex.Lock()
	defer mutex.Unlock() //在defer后指定的函数会在函数退出前调用。

	hash := primitives.NewHash()
	hash.Write(certRaw)
	var err error

	if _, err = ca.db.Exec("INSERT INTO Certificates (id, timestamp, usage, cert, hash, kdfkey) VALUES (?, ?, ?, ?, ?, ?)", id, timestamp, usage, certRaw, hash.Sum(nil), kdfKey); err != nil {
		caLogger.Error(err)
	}
	return err
}

// 根据参数新建一个证书
func (ca *CA) newCertificate(id string, pub interface{}, usage x509.KeyUsage, ext []pkix.Extension) ([]byte, error) {
	spec := NewDefaultCertificateSpec(id, pub, usage, ext...)
	return ca.newCertificateFromSpec(spec)
}

// 通过certificateSpec创建一个证书
func (ca *CA) newCertificateFromSpec(spec *CertificateSpec) ([]byte, error) {
	notBefore := spec.GetNotBefore()
	notAfter := spec.GetNotAfter()

	parent := ca.cert // CA的证书
	isCA := parent == nil

	tmpl := x509.Certificate{ // X509证书
		SerialNumber: spec.GetSerialNumber(), // 序列号
		Subject: pkix.Name{ // 代表X.509的专有名称。
			CommonName:   spec.GetCommonName(),
			Organization: []string{spec.GetOrganization()},
			Country:      []string{spec.GetCountry()},
		},
		NotBefore: *notBefore,
		NotAfter:  *notAfter,

		SubjectKeyId:       *spec.GetSubjectKeyID(), // GetSubjectKeyID returns the spec's subject KeyID， {1,2,3,4}
		SignatureAlgorithm: spec.GetSignatureAlgorithm(),
		KeyUsage:           spec.GetUsage(),

		BasicConstraintsValid: true, //基本约束有效
		IsCA: isCA,
	}

	if len(*spec.GetExtensions()) > 0 { // 扩展字段有效
		tmpl.Extensions = *spec.GetExtensions()
		tmpl.ExtraExtensions = *spec.GetExtensions()
	}
	if isCA { // 当前证书为CA证书
		parent = &tmpl
	}

	raw, err := x509.CreateCertificate( //基于模板，创建证书。
		rand.Reader,
		&tmpl,               // 模板
		parent,              // 父证书
		spec.GetPublicKey(), // 注册公钥
		ca.priv,             // CA的私钥
	)
	if isCA && err != nil {
		caLogger.Panic(err)
	}

	return raw, err
}

// 通过使用关键字读取证书，KeyUsage表示为给定键有效的一组操作
func (ca *CA) readCertificateByKeyUsage(id string, usage x509.KeyUsage) ([]byte, error) {
	caLogger.Debugf("Reading certificate for %s and usage %v", id, usage)

	mutex.RLock()         // 互斥，上锁
	defer mutex.RUnlock() // 解锁，最后执行

	var raw []byte
	err := ca.db.QueryRow("SELECT cert FROM Certificates WHERE id=? AND usage=?", id, usage).Scan(&raw)
	// scan将查询结果中的匹配的条目拷贝到raw指向的值。

	if err != nil {
		caLogger.Debugf("readCertificateByKeyUsage() Error: %v", err)
	}

	return raw, err
}

// 通过时间戳读取证书
func (ca *CA) readCertificateByTimestamp(id string, ts int64) ([]byte, error) {
	caLogger.Debug("Reading certificate for " + id + ".")

	mutex.RLock()         // 互斥，上锁
	defer mutex.RUnlock() // 解锁，最后执行

	var raw []byte
	err := ca.db.QueryRow("SELECT cert FROM Certificates WHERE id=? AND timestamp=?", id, ts).Scan(&raw)
	// scan将查询结果中的匹配的条目拷贝到raw指向的值。

	return raw, err
}

// 读取证书， opt为可选参数，opt[0]代表时间戳
func (ca *CA) readCertificates(id string, opt ...int64) (*sql.Rows, error) {
	caLogger.Debug("Reading certificatess for " + id + ".")

	mutex.RLock()         // 互斥，上锁
	defer mutex.RUnlock() // 解锁，最后执行

	if len(opt) > 0 && opt[0] != 0 {
		return ca.db.Query("SELECT cert FROM Certificates WHERE id=? AND timestamp=? ORDER BY usage", id, opt[0])
	}

	return ca.db.Query("SELECT cert FROM Certificates WHERE id=?", id)
}

// 读取指定时间戳段(start,end)的证书集合
func (ca *CA) readCertificateSets(id string, start, end int64) (*sql.Rows, error) {
	caLogger.Debug("Reading certificate sets for " + id + ".")

	mutex.RLock()         // 互斥，上锁
	defer mutex.RUnlock() // 解锁，最后执行

	return ca.db.Query("SELECT cert, timestamp FROM Certificates WHERE id=? AND timestamp BETWEEN ? AND ? ORDER BY timestamp", id, start, end)
}

// 通过证书hash值读取证书
func (ca *CA) readCertificateByHash(hash []byte) ([]byte, error) {
	caLogger.Debug("Reading certificate for hash " + string(hash) + ".")

	mutex.RLock()
	defer mutex.RUnlock()

	var raw []byte
	row := ca.db.QueryRow("SELECT cert FROM Certificates WHERE hash=?", hash)
	err := row.Scan(&raw) // scan将row中匹配的条目复制到raw指向的值。

	return raw, err
}

// 判断隶属关系(affiliation)是否有效
func (ca *CA) isValidAffiliation(affiliation string) (bool, error) {
	caLogger.Debug("Validating affiliation: " + affiliation)

	mutex.RLock()
	defer mutex.RUnlock()

	var count int // AffiliationGroups中的数目
	var err error
	err = ca.db.QueryRow("SELECT count(row) FROM AffiliationGroups WHERE name=?", affiliation).Scan(&count) // 将查询结果中的匹配的条目拷贝到count
	if err != nil {
		caLogger.Debug("Affiliation <" + affiliation + "> is INVALID.")

		return false, err
	}
	caLogger.Debug("Affiliation <" + affiliation + "> is VALID.")

	return count == 1, nil
}

//
// Determine if affiliation is required for a given registration request.
//
// Affiliation is required if the role is client or peer.
// Affiliation is not required if the role is validator or auditor.
// 1: client, 2: peer, 4: validator, 8: auditor
// client、peer需要隶属关系，validator和auditor不需要隶属关系
//

// 请求隶属关系（affiliation），只有client和peer能调用
func (ca *CA) requireAffiliation(role pb.Role) bool {
	roleStr, _ := MemberRoleToString(role) // 将数字代表的实体转换成字符串
	caLogger.Debug("Assigned role is: " + roleStr + ".")

	return role != pb.Role_VALIDATOR && role != pb.Role_AUDITOR
}

// validateAndGenerateEnrollID validates the affiliation subject，验证subject的隶属关系，合法就返回生成的证书注册ID
func (ca *CA) validateAndGenerateEnrollID(id, affiliation string, role pb.Role) (string, error) {
	roleStr, _ := MemberRoleToString(role)
	caLogger.Debug("Validating and generating enrollID for user id: " + id + ", affiliation: " + affiliation + ", role: " + roleStr + ".")

	// Check whether the affiliation is required for the current user.
	//
	// Affiliation is required if the role is client or peer.
	// Affiliation is not required if the role is validator or auditor.
	if ca.requireAffiliation(role) {
		valid, err := ca.isValidAffiliation(affiliation)
		if err != nil {
			return "", err
		}

		if !valid {
			caLogger.Debug("Invalid affiliation group: ")
			return "", errors.New("Invalid affiliation group " + affiliation)
		}

		return ca.generateEnrollID(id, affiliation)
	}

	return "", nil
}

// registerUser registers a new member with the CA
// 使用CA注册一个新用户(client,peer,validator,auditor)
func (ca *CA) registerUser(id, affiliation string, role pb.Role, attrs []*pb.Attribute, aca *ACA, registrar, memberMetadata string, opt ...string) (string, error) {
	memberMetadata = removeQuotes(memberMetadata) //从字符串memberMetadata中删除外部引号。
	roleStr, _ := MemberRoleToString(role)
	caLogger.Debugf("Received request to register user with id: %s, affiliation: %s, role: %s, attrs: %+v, registrar: %s, memberMetadata: %s\n",
		id, affiliation, roleStr, attrs, registrar, memberMetadata)

	var enrollID, tok string
	var err error

	// There are two ways that registerUser can be called:
	// 1) At initialization time from eca.users in the YAML file
	//    In this case, 'registrar' may be nil but we still register the users from the YAML file
	// 2) At runtime via the GRPC ECA.RegisterUser handler (see RegisterUser in eca.go)
	//    In this case, 'registrar' must never be nil and furthermore the caller must have been authenticated
	//    to actually be the 'registrar' identity
	// This means we trust what is in the YAML file but not what comes over the network
	if registrar != "" {
		// Check the permission of member named 'registrar' to perform this registration
		err = ca.canRegister(registrar, role2String(int(role)), memberMetadata) // 检查该用户是否可注册
		if err != nil {
			return "", err
		}
	}

	enrollID, err = ca.validateAndGenerateEnrollID(id, affiliation, role) // 验证role的隶属关系
	if err != nil {
		return "", err
	}

	tok, err = ca.registerUserWithEnrollID(id, enrollID, role, memberMetadata, opt...) // 通过注册ID来注册用户
	if err != nil {
		return "", err
	}

	if attrs != nil && aca != nil {
		var pairs []*AttributePair
		pairs, err = toAttributePairs(id, affiliation, attrs) // 属性操作，格式转换
		if err == nil {
			err = aca.PopulateAttributes(pairs) // 属性填充
		}
	}

	return tok, err
}

// registerUserWithEnrollID registers a new user and its enrollmentID, role and state
// 通过注册ID，角色和状态等 注册一个新用户，
func (ca *CA) registerUserWithEnrollID(id string, enrollID string, role pb.Role, memberMetadata string, opt ...string) (string, error) {
	mutex.Lock()
	defer mutex.Unlock()

	roleStr, _ := MemberRoleToString(role)
	caLogger.Debugf("Registering user %s as %s with memberMetadata %s\n", id, roleStr, memberMetadata)

	var tok string // 若可选参数存在，tok=opt[0];若不存在，则随机生成12位的字符串
	if len(opt) > 0 && len(opt[0]) > 0 {
		tok = opt[0]
	} else {
		tok = randomString(12)
	}

	var row int
	err := ca.db.QueryRow("SELECT row FROM Users WHERE id=?", id).Scan(&row) // 将查询结果中匹配的条目复制到row中
	if err == nil {
		return "", errors.New("User is already registered")
	}

	_, err = ca.db.Exec("INSERT INTO Users (id, enrollmentId, token, role, metadata, state) VALUES (?, ?, ?, ?, ?, ?)", id, enrollID, tok, role, memberMetadata, 0)

	if err != nil {
		caLogger.Error(err)
	}

	return tok, err
}

// registerAffiliationGroup registers a new affiliation group
//  注册一个新的隶属关系
func (ca *CA) registerAffiliationGroup(name string, parentName string) error {
	mutex.Lock()
	defer mutex.Unlock()

	caLogger.Debug("Registering affiliation group " + name + " parent " + parentName + ".")

	var parentID int // 父证书的ID
	var err error
	var count int                                                                                    // 隶属关系名称为name的数目
	err = ca.db.QueryRow("SELECT count(row) FROM AffiliationGroups WHERE name=?", name).Scan(&count) // 将查询结果复制给count
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("Affiliation group is already registered")
	}

	if strings.Compare(parentName, "") != 0 {
		err = ca.db.QueryRow("SELECT row FROM AffiliationGroups WHERE name=?", parentName).Scan(&parentID)
		if err != nil {
			return err
		}
	}

	_, err = ca.db.Exec("INSERT INTO AffiliationGroups (name, parent) VALUES (?, ?)", name, parentID)

	if err != nil {
		caLogger.Error(err)
	}

	return err

}

// deleteUser deletes a user given a name
// 根据ID删除指定用户
func (ca *CA) deleteUser(id string) error {
	caLogger.Debug("Deleting user " + id + ".")

	mutex.Lock()
	defer mutex.Unlock()

	var row int
	err := ca.db.QueryRow("SELECT row FROM Users WHERE id=?", id).Scan(&row)
	if err == nil {
		_, err = ca.db.Exec("DELETE FROM Certificates Where id=?", id)
		if err != nil {
			caLogger.Error(err)
		}

		_, err = ca.db.Exec("DELETE FROM Users WHERE row=?", row)
		if err != nil {
			caLogger.Error(err)
		}
	}

	return err
}

// readUser reads a token given an id
// 读取指定ID的用户信息（role, token, state, key, enrollmentId）
func (ca *CA) readUser(id string) *sql.Row {
	caLogger.Debug("Reading token for " + id + ".")

	mutex.RLock()
	defer mutex.RUnlock()

	return ca.db.QueryRow("SELECT role, token, state, key, enrollmentId FROM Users WHERE id=?", id)
}

// readUsers reads users of a given Role
// 读取指定角色的所有用户
func (ca *CA) readUsers(role int) (*sql.Rows, error) {
	caLogger.Debug("Reading users matching role " + strconv.FormatInt(int64(role), 2) + ".")

	return ca.db.Query("SELECT id, role FROM Users WHERE role&?!=0", role)
}

// readRole returns the user Role given a user id
// 根据给定的用户ID读取用户的角色
func (ca *CA) readRole(id string) int {
	caLogger.Debug("Reading role for " + id + ".")

	mutex.RLock()
	defer mutex.RUnlock()

	var role int
	ca.db.QueryRow("SELECT role FROM Users WHERE id=?", id).Scan(&role)

	return role
}

// 读取CA中所有的隶属关系组
func (ca *CA) readAffiliationGroups() ([]*AffiliationGroup, error) {
	caLogger.Debug("Reading affilition groups.")

	rows, err := ca.db.Query("SELECT row, name, parent FROM AffiliationGroups")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := make(map[int64]*AffiliationGroup)

	for rows.Next() { // 将查询结果复制到group映射map中
		group := new(AffiliationGroup)
		var id int64
		if e := rows.Scan(&id, &group.name, &group.parentID); e != nil {
			return nil, err
		}
		groups[id] = group
	}

	groupList := make([]*AffiliationGroup, len(groups))
	idx := 0
	for _, eachGroup := range groups { // 将map映射group 分配下标并保存到groupList中
		eachGroup.parent = groups[eachGroup.parentID]
		groupList[idx] = eachGroup
		idx++
	}

	return groupList, nil
}

// 根据id和隶属关系（affiliation)生成注册ID
func (ca *CA) generateEnrollID(id string, affiliation string) (string, error) {
	if id == "" || affiliation == "" {
		return "", errors.New("Please provide all the input parameters, id and role")
	}

	if strings.Contains(id, "\\") || strings.Contains(affiliation, "\\") {
		return "", errors.New("Do not include the escape character \\ as part of the values") // escape character 转义字符
	}

	return id + "\\" + affiliation, nil
}

// 解析注册ID
func (ca *CA) parseEnrollID(enrollID string) (id string, affiliation string, err error) {

	if enrollID == "" {
		return "", "", errors.New("Input parameter missing")
	}

	enrollIDSections := strings.Split(enrollID, "\\") //根据"\\"将注册ID字符串切分成多个子串

	if len(enrollIDSections) != 2 {
		return "", "", errors.New("Either the userId or affiliation is missing from the enrollmentID. EnrollID was " + enrollID)
	}

	id = enrollIDSections[0]
	affiliation = enrollIDSections[1]
	err = nil
	return
}

// Check to see if member 'registrar' can register a new member of type 'newMemberRole'
// and with metadata associated with 'newMemberMetadataStr'
// Return nil if allowed, or an error if not allowed
// 检查成员'Registrar'是否可以注册一个'newMemberRole'类型的新成员，并如果允许，与'newMemberMetadataStr'关联的元数据返回为零;如果不允许，则返回一个错误
func (ca *CA) canRegister(registrar string, newMemberRole string, newMemberMetadataStr string) error {
	mutex.RLock()
	defer mutex.RUnlock()

	// Read the user metadata associated with 'registrar'
	var registrarMetadataStr string
	// 读取registrar的用户数据，并复制到registrarMetadataStr
	err := ca.db.QueryRow("SELECT metadata FROM Users WHERE id=?", registrar).Scan(&registrarMetadataStr)
	if err != nil {
		caLogger.Debugf("CA.canRegister: db error: %s\n", err.Error())
		return err
	}
	caLogger.Debugf("CA.canRegister: registrar=%s, registrarMD=%s, newMemberRole=%s, newMemberMD=%s",
		registrar, registrarMetadataStr, newMemberRole, newMemberMetadataStr)
	// If isn't a registrar at all, then error
	if registrarMetadataStr == "" {
		caLogger.Debug("canRegister: member " + registrar + " is not a registrar")
		return errors.New("member " + registrar + " is not a registrar")
	}
	// Get the registrar's metadata
	caLogger.Debug("CA.canRegister: parsing registrar's metadata")
	registrarMetadata, err := newMemberMetadata(registrarMetadataStr) // 将registrarMetadataStr字符串转换成MemberMetadata类型
	if err != nil {
		return err
	}
	// Convert the user's meta to an object
	caLogger.Debug("CA.canRegister: parsing new member's metadata")
	newMemberMetadata, err := newMemberMetadata(newMemberMetadataStr) // 将newMemberMetadataStr字符串转换成MemberMetadata类型
	if err != nil {
		return err
	}
	// See if the metadata to be registered is acceptable for the registrar
	return registrarMetadata.canRegister(registrar, newMemberRole, newMemberMetadata)
}

// Convert a string to a MemberMetadata
func newMemberMetadata(metadata string) (*MemberMetadata, error) {
	if metadata == "" {
		caLogger.Debug("newMemberMetadata: nil")
		return nil, nil
	}
	var mm MemberMetadata
	err := json.Unmarshal([]byte(metadata), &mm) // Unmarshal解析JSON编码的数据，并将结果存储在mm中。
	if err != nil {
		caLogger.Debugf("newMemberMetadata: error: %s, metadata: %s\n", err.Error(), metadata)
	}
	caLogger.Debugf("newMemberMetadata: metadata=%s, object=%+v\n", metadata, mm)
	return &mm, err
}

// MemberMetadata Additional member metadata,其他成员元数据
type MemberMetadata struct {
	Registrar Registrar `json:"registrar"`
}

// Registrar metadata
type Registrar struct {
	Roles         []string `json:"roles"`
	DelegateRoles []string `json:"delegateRoles"` //代理角色
}

// See if member 'registrar' can register a member of type 'newRole'
// with MemberMetadata of 'newMemberMetadata'
// registrar成员是否可注册为newRole类型并且拥有newMemberMetadata成员元数据的成员
func (mm *MemberMetadata) canRegister(registrar string, newRole string, newMemberMetadata *MemberMetadata) error {
	// Can register a member of this type?
	caLogger.Debugf("MM.canRegister registrar=%s, newRole=%s\n", registrar, newRole)
	if !strContained(newRole, mm.Registrar.Roles) { //子串判断
		caLogger.Debugf("MM.canRegister: role %s can't be registered by %s\n", newRole, registrar)
		return errors.New("member " + registrar + " may not register member of type " + newRole)
	}

	// The registrar privileges that are being registered must not be larger than the registrar's
	if newMemberMetadata == nil {
		// Not requesting registrar privileges for this member, so we are OK
		caLogger.Debug("MM.canRegister: not requesting registrar privileges")
		return nil
	}

	// Make sure this registrar is not delegating an invalid role，确定registrar代表的不是一个有效的角色
	err := checkDelegateRoles(newMemberMetadata.Registrar.Roles, mm.Registrar.DelegateRoles, registrar)
	if err != nil {
		caLogger.Debug("MM.canRegister: checkDelegateRoles failure")
		return err
	}

	// Can register OK
	caLogger.Debug("MM.canRegister: OK")
	return nil
}

// Return an error if all strings in 'strs1' are not contained in 'strs2'，str1包含于str2返回nil
func checkDelegateRoles(strs1 []string, strs2 []string, registrar string) error {
	caLogger.Debugf("CA.checkDelegateRoles: registrar=%s, strs1=%+v, strs2=%+v\n", registrar, strs1, strs2)
	for _, s := range strs1 {
		if !strContained(s, strs2) {
			caLogger.Debugf("CA.checkDelegateRoles: no: %s not in %+v\n", s, strs2)
			return errors.New("user " + registrar + " may not register delegateRoles " + s)
		}
	}
	caLogger.Debug("CA.checkDelegateRoles: ok")
	return nil
}

// Return true if 'str' is in 'strs'; otherwise return false，是否包含
func strContained(str string, strs []string) bool {
	for _, s := range strs {
		if s == str {
			return true
		}
	}
	return false
}

// Return true if 'str' is prefixed by any string in 'strs'; otherwise return false，是否是前缀
func isPrefixed(str string, strs []string) bool {
	for _, s := range strs {
		if strings.HasPrefix(str, s) {
			return true
		}
	}
	return false
}

// convert a role to a string， role => string
func role2String(role int) string {
	if role == int(pb.Role_CLIENT) {
		return "client"
	} else if role == int(pb.Role_PEER) {
		return "peer"
	} else if role == int(pb.Role_VALIDATOR) {
		return "validator"
	} else if role == int(pb.Role_AUDITOR) {
		return "auditor"
	}
	return ""
}

// Remove outer quotes from a string if necessary, 去掉外部引号
func removeQuotes(str string) string {
	if str == "" {
		return str
	}
	if (strings.HasPrefix(str, "'") && strings.HasSuffix(str, "'")) ||
		(strings.HasPrefix(str, "\"") && strings.HasSuffix(str, "\"")) { //str前后均有单引号或双引号
		str = str[1 : len(str)-1] // 去掉str[0]和str[len(str)-1]
	}
	caLogger.Debugf("removeQuotes: %s\n", str)
	return str
}

// Convert the protobuf array of attributes to the AttributePair array format
// as required by the ACA code to populate the table
// 将属性的protobuf数组按照ACA代码的要求将AttributePair数组格式转换为表格填充。
func toAttributePairs(id, affiliation string, attrs []*pb.Attribute) ([]*AttributePair, error) {
	var pairs = make([]*AttributePair, 0) // 初始化属性对 表
	for _, attr := range attrs {
		vals := []string{id, affiliation, attr.Name, attr.Value, attr.NotBefore, attr.NotAfter}
		pair, err := NewAttributePair(vals, nil) //NewAttributePair创建关联的新属性对。
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, pair) // 添加pair到pairs数组中
	}
	caLogger.Debugf("toAttributePairs: id=%s, affiliation=%s, attrs=%v, pairs=%v\n",
		id, affiliation, attrs, pairs)
	return pairs, nil
}

// 时间转换
func convertTime(ts *gp.Timestamp) time.Time {
	var t time.Time
	if ts == nil {
		t = time.Unix(0, 0).UTC() // Unix返回与给定的Unix时间相对应的本地时间，秒和毫秒都是自1970年1月1日UTC以来。
	} else {
		t = time.Unix(ts.Seconds, int64(ts.Nanos)).UTC() // Unix返回与给定的Unix时间相对应的本地时间，秒和毫秒都是自1970年1月1日UTC以来。
	}
	return t
}
