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
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io/ioutil"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/flogging"
	pb "github.com/hyperledger/fabric/membersrvc/protos"
	"github.com/op/go-logging"
	"google.golang.org/grpc"
)

var tcaLogger = logging.MustGetLogger("tca")

var (
	// TCertEncTCertIndex is the ASN1 object identifier of the TCert index.
	TCertEncTCertIndex = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}

	// TCertEncEnrollmentID is the ASN1 object identifier of the enrollment id.
	TCertEncEnrollmentID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 8}

	// TCertAttributesHeaders is the ASN1 object identifier of attributes header.
	TCertAttributesHeaders = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 9}

	// Padding for encryption.
	Padding = []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}

	// RootPreKeySize for attribute encryption keys derivation
	RootPreKeySize = 48 // 用于属性加密密钥派生
)

// TCA is the transaction certificate authority.
type TCA struct {
	*CA                          // CA
	eca        *ECA              // ECA (enrollment)
	hmacKey    []byte            // 用于hmac(消息摘要)的密钥
	rootPreKey []byte            // 根密钥，用于属性加密密钥的派生？？？
	preKeys    map[string][]byte // 属性加密密钥？？？
	gRPCServer *grpc.Server      // gRPC服务器
}

// TCertSet contains relevant information of a set of tcerts
type TCertSet struct {
	Ts           int64  // 时间戳
	EnrollmentID string // 注册ID
	Nonce        []byte // 随机值
	Key          []byte // 密钥，用于 ？？？
}

// 初始化TCA表格:TCertificateSets (row, enrollmentID, timestamp, nonce, kdfKey)
func initializeTCATables(db *sql.DB) error {
	var err error

	err = initializeCommonTables(db) // 调用ca.go中的函数，初始化公共表格
	if err != nil {
		return err
	}

	if _, err = db.Exec("CREATE TABLE IF NOT EXISTS TCertificateSets (row INTEGER PRIMARY KEY, enrollmentID VARCHAR(64), timestamp INTEGER, nonce BLOB, kdfkey BLOB)"); err != nil {
		return err
	}

	return err
}

// NewTCA sets up a new TCA. 设置新TCA
func NewTCA(eca *ECA) *TCA {
	tca := &TCA{NewCA("tca", initializeTCATables), eca, nil, nil, nil, nil} // 初始化含有CA、eca的tca实例
	flogging.LoggingInit("tca")

	err := tca.readHmacKey() // 从文件系统读取hmac密钥。
	if err != nil {
		tcaLogger.Panic(err)
	}

	err = tca.readRootPreKey() // 从文件系统中读取
	if err != nil {
		tcaLogger.Panic(err)
	}

	err = tca.initializePreKeyTree() // 初始化用于属性加密的密钥树
	if err != nil {
		tcaLogger.Panic(err)
	}
	return tca
}

// Read the hcmac key from the file system.
func (tca *TCA) readHmacKey() error {
	var cooked string
	raw, err := ioutil.ReadFile(tca.path + "/tca.hmac") // 读取tca.hmac文件内容
	if err != nil {
		key := make([]byte, 49)
		rand.Reader.Read(key)                           // 读取最多len(key)个字节到key中
		cooked = base64.StdEncoding.EncodeToString(key) // cooked是key的base64编码

		err = ioutil.WriteFile(tca.path+"/tca.hmac", []byte(cooked), 0644) // 写入文件，文件有相应的权限
		if err != nil {
			tcaLogger.Panic(err)
		}
	} else {
		cooked = string(raw) // 强制类型转换
	}

	tca.hmacKey, err = base64.StdEncoding.DecodeString(cooked) // base64解码
	return err
}

// Read the root pre key from the file system.
func (tca *TCA) readRootPreKey() error {
	var cooked string
	raw, err := ioutil.ReadFile(tca.path + "/root_pk.hmac") // 读取root_pk.hmac文件内容
	if err != nil {
		key := make([]byte, RootPreKeySize)             // key 应该是之前的rootPreKey
		rand.Reader.Read(key)                           // 读取最多len(key)个字节到key中
		cooked = base64.StdEncoding.EncodeToString(key) // cooked是key的base64编码

		err = ioutil.WriteFile(tca.path+"/root_pk.hmac", []byte(cooked), 0644) // 写入文件，文件有相应的权限
		if err != nil {
			tcaLogger.Panic(err)
		}
	} else {
		cooked = string(raw)
	}

	tca.rootPreKey, err = base64.StdEncoding.DecodeString(cooked) // base64解码
	return err
}

// 计算密钥
func (tca *TCA) calculatePreKey(variant []byte, preKey []byte) ([]byte, error) {
	mac := hmac.New(primitives.GetDefaultHash(), preKey) // 使用给定的参数返回一个新的HMAC散列。
	_, err := mac.Write(variant)                         // 从variant写入len(variant)个字节到底层数据流。
	if err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil // Sum追加当前哈希并返回所生成的切片。
}

// 初始化非根组的PreKey
func (tca *TCA) initializePreKeyNonRootGroup(group *AffiliationGroup) error {
	if group.parent.preKey == nil {
		//Initialize parent if it is not initialized yet.
		tca.initializePreKeyGroup(group.parent) // 初始化父隶属关系
	}
	var err error
	group.preKey, err = tca.calculatePreKey([]byte(group.name), group.parent.preKey) // 使用父组的密钥生成本组密钥
	return err
}

// 初始化根组preKey
func (tca *TCA) initializePreKeyGroup(group *AffiliationGroup) error {
	if group.parentID == 0 {
		//This group is root
		group.preKey = tca.rootPreKey // 根密钥
		return nil
	}
	return tca.initializePreKeyNonRootGroup(group) // 初始化非根组的PreKey
}

// 初始化密钥树
func (tca *TCA) initializePreKeyTree() error {
	tcaLogger.Debug("Initializing PreKeys.")
	groups, err := tca.eca.readAffiliationGroups() // 读取隶属关系组， 等价于tca.eca.CA.readAffiliationGroups()
	if err != nil {
		return err
	}
	tca.preKeys = make(map[string][]byte)
	for _, group := range groups { // 依次读取隶属关系
		if group.preKey == nil { // 初始化组密钥
			err = tca.initializePreKeyGroup(group)
			if err != nil {
				return err
			}
		}
		tcaLogger.Debug("Initializing PK group ", group.name)
		tca.preKeys[group.name] = group.preKey
	}

	return nil
}

// 获取当前隶属关系密钥
func (tca *TCA) getPreKFrom(enrollmentCertificate *x509.Certificate) ([]byte, error) {
	_, affiliation, err := tca.eca.parseEnrollID(enrollmentCertificate.Subject.CommonName) // 解析注册ID
	if err != nil {
		return nil, err
	}
	preK := tca.preKeys[affiliation] // 获取当前组的密钥
	if preK == nil {
		return nil, errors.New("Could not be found a pre-k to the affiliation group " + affiliation + ".")
	}
	return preK, nil
}

// Start starts the TCA. 启动TCA服务
func (tca *TCA) Start(srv *grpc.Server) {
	tcaLogger.Info("Staring TCA services...")
	tca.startTCAP(srv) // 启动TCAP服务
	tca.startTCAA(srv) // 启动TCAA服务
	tca.gRPCServer = srv
	tcaLogger.Info("TCA started.")
}

// Stop stops the TCA services. 停止TCA服务
func (tca *TCA) Stop() error {
	tcaLogger.Info("Stopping the TCA services...")
	if tca.gRPCServer != nil {
		tca.gRPCServer.Stop() // 停止gRPC服务器
	}
	err := tca.CA.Stop() // 停止CA服务
	if err != nil {
		tcaLogger.Errorf("Error stopping TCA services: %s", err)
	} else {
		tcaLogger.Info("TCA services stopped")
	}
	return err
}

// 启动TCAP(为TCA的公共gRPC接口服务) 服务
func (tca *TCA) startTCAP(srv *grpc.Server) {
	pb.RegisterTCAPServer(srv, &TCAP{tca}) // 注册tcap服务器
	tcaLogger.Info("TCA PUBLIC gRPC API server started")
}

// 启动TCAA(为TCA的管理员gRPC接口提供服务) 服务
func (tca *TCA) startTCAA(srv *grpc.Server) {
	pb.RegisterTCAAServer(srv, &TCAA{tca}) // 注册TCAA服务器
	tcaLogger.Info("TCA ADMIN gRPC API server started")
}

// 获取Tcert证书集
func (tca *TCA) getCertificateSets(enrollmentID string) ([]*TCertSet, error) {
	mutex.RLock() // 互斥
	defer mutex.RUnlock()

	var sets = []*TCertSet{}
	var err error

	var rows *sql.Rows
	rows, err = tca.retrieveCertificateSets(enrollmentID) // 检索证书集
	if err != nil {
		return nil, err
	}
	defer rows.Close() // 最后执行，关闭结果集

	var enrollID string
	var timestamp int64
	var nonce []byte
	var kdfKey []byte

	for rows.Next() { // 依次读取每条结果
		if err = rows.Scan(&enrollID, &timestamp, &nonce, &kdfKey); err != nil { // 将每条结果的内容，复制到相匹配的变量中
			return nil, err
		}
		sets = append(sets, &TCertSet{Ts: timestamp, EnrollmentID: enrollID, Key: kdfKey}) // 追加到数组中
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return sets, nil
}

// 存储证书
func (tca *TCA) persistCertificateSet(enrollmentID string, timestamp int64, nonce []byte, kdfKey []byte) error {
	mutex.Lock() // 互斥
	defer mutex.Unlock()

	var err error

	if _, err = tca.db.Exec("INSERT INTO TCertificateSets (enrollmentID, timestamp, nonce, kdfkey) VALUES (?, ?, ?, ?)", enrollmentID, timestamp, nonce, kdfKey); err != nil {
		tcaLogger.Error(err)
	}
	return err
}

// 根据注册ID检索证书集
func (tca *TCA) retrieveCertificateSets(enrollmentID string) (*sql.Rows, error) {
	return tca.db.Query("SELECT enrollmentID, timestamp, nonce, kdfkey FROM TCertificateSets WHERE enrollmentID=?", enrollmentID)
}
