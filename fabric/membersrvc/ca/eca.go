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
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/flogging"
	pb "github.com/hyperledger/fabric/membersrvc/protos"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

var ecaLogger = logging.MustGetLogger("eca")

var (
	// ECertSubjectRole is the ASN1 object identifier of the subject's role.
	//
	ECertSubjectRole = asn1.ObjectIdentifier{2, 1, 3, 4, 5, 6, 7}
)

// ECA is the enrollment certificate authority.
//
type ECA struct { // 注册CA
	*CA                          // CA
	aca             *ACA         // ACA
	obcKey          []byte       // 对称密钥
	obcPriv, obcPub []byte       // 私钥， 公钥
	gRPCServer      *grpc.Server // gRPC服务器
}

// 初始化ECA的表格，调用ca.go中的函数，初始化公共表格：Certificates、Users、AffiliationGroups
func initializeECATables(db *sql.DB) error {
	return initializeCommonTables(db)
}

// NewECA sets up a new ECA.
// 设置一个新的ECA
func NewECA(aca *ACA) *ECA {
	eca := &ECA{CA: NewCA("eca", initializeECATables), aca: aca} // 初始化eca中的CA和aca
	flogging.LoggingInit("eca")

	{
		// read or create global symmetric encryption key,读取或创建全局对称加密密钥，使用了AES加密算法
		var cooked string
		var l = logging.MustGetLogger("ECA") // 这个对称密码算法中使用，以区别于公钥密码中使用的ecaLogger

		raw, err := ioutil.ReadFile(eca.path + "/obc.aes") // 根据路径读取文件内容
		if err != nil {
			rand := rand.Reader                             // Reader是一个全局共享的、加密强大的伪随机生成器的实例。
			key := make([]byte, 32)                         // AES-256
			rand.Read(key)                                  // 读取至多len(key)个字节到key。
			cooked = base64.StdEncoding.EncodeToString(key) // 返回key的base64编码

			err = ioutil.WriteFile(eca.path+"/obc.aes", []byte(cooked), 0644) // 把数据写入到文件中，文件权限为0644
			if err != nil {
				l.Panic(err) // 日志记录
			}
		} else {
			cooked = string(raw) //强制类型转换
		}

		eca.obcKey, err = base64.StdEncoding.DecodeString(cooked) // 返回字符串cooked的base64解码
		if err != nil {
			l.Panic(err)
		}
	}

	{
		// read or create global ECDSA key pair for ECIES,读取或创建全局ECDSA密钥对
		var priv *ecdsa.PrivateKey
		cooked, err := ioutil.ReadFile(eca.path + "/obc.ecies") // 根据路径读取文件内容
		if err == nil {
			block, _ := pem.Decode(cooked)                  // 将在输入中找到下一个PEM格式的块（证书，私钥等），返回该块和输入的其余部分。
			priv, err = x509.ParseECPrivateKey(block.Bytes) // 解析找到的PEM块
			if err != nil {
				ecaLogger.Panic(err)
			}
		} else {
			priv, err = ecdsa.GenerateKey(primitives.GetDefaultCurve(), rand.Reader) // 生成公私钥对
			if err != nil {
				ecaLogger.Panic(err)
			}

			raw, _ := x509.MarshalECPrivateKey(priv) // MarshalECPrivateKey将 EC私钥 编组为ASN.1，DER格式。
			cooked = pem.EncodeToMemory(             // 编码私钥
				&pem.Block{
					Type:  "ECDSA PRIVATE KEY",
					Bytes: raw,
				})
			err := ioutil.WriteFile(eca.path+"/obc.ecies", cooked, 0644) // 把数据写入到文件中，文件权限为0644
			if err != nil {
				ecaLogger.Panic(err)
			}
		}

		eca.obcPriv = cooked                                 // ECA私钥
		raw, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey) // MarshalPKIXPublicKey将公钥序列化为DER编码的PKIX格式。
		eca.obcPub = pem.EncodeToMemory(                     // 编码公钥
			&pem.Block{
				Type:  "ECDSA PUBLIC KEY",
				Bytes: raw,
			})
	}

	eca.populateAffiliationGroupsTable() // 填充隶属关系组织表格
	eca.populateUsersTable()             // 填充用户表格
	return eca
}

// populateUsersTable populates the users table.
// 填充用户表格
func (eca *ECA) populateUsersTable() {
	// populate user table
	users := viper.GetStringMapString("eca.users") //返回与“eca.users”关联的值作为字符串的映射
	for id, flds := range users {
		vals := strings.Fields(flds)       // 以一个或多个空格符将flds划分为多个子串
		role, err := strconv.Atoi(vals[0]) // 解析字符串
		if err != nil {
			ecaLogger.Panic(err)
		}
		var affiliation, memberMetadata, registrar string
		if len(vals) >= 3 {
			affiliation = vals[2]
			if len(vals) >= 4 {
				memberMetadata = vals[3]
				if len(vals) >= 5 {
					registrar = vals[4]
				}
			}
		}
		// 注册一个新用户(client,peer,validator,auditor)，等价于eca.CA.registerUser()
		eca.registerUser(id, affiliation, pb.Role(role), nil, eca.aca, registrar, memberMetadata, vals[1])
	}
}

// populateAffiliationGroup populates the affiliation groups table.
// 填充隶属关系组织，类似于域名树
func (eca *ECA) populateAffiliationGroup(name, parent, key string, level int) {
	eca.registerAffiliationGroup(name, parent) // 注册一个新的隶属关系，等价于eca.CA.registerAffiliationGroup()
	newKey := key + "." + name

	if level == 0 { // 递归函数出口
		affiliationGroups := viper.GetStringSlice(newKey) // 返回与“newkey”关联的值作为一个字符串
		for ci := range affiliationGroups {
			eca.registerAffiliationGroup(affiliationGroups[ci], name) // 注册一个新的隶属关系
		}
	} else {
		affiliationGroups := viper.GetStringMapString(newKey)
		for childName := range affiliationGroups {
			eca.populateAffiliationGroup(childName, name, newKey, level-1) // 递归调用自身
		}
	}
}

// populateAffiliationGroupsTable populates affiliation groups table.
// 填充隶属关系组织的表格
func (eca *ECA) populateAffiliationGroupsTable() {
	key := "eca.affiliations"
	affiliationGroups := viper.GetStringMapString(key) // 返回与“newkey”关联的值作为一个字符串
	for name := range affiliationGroups {
		eca.populateAffiliationGroup(name, "", key, 1)
	}
}

// Start starts the ECA.
// 启动ECA
func (eca *ECA) Start(srv *grpc.Server) {
	ecaLogger.Info("Starting ECA...")

	eca.startECAP(srv)   // 启动ECAP
	eca.startECAA(srv)   // 启动ECAA
	eca.gRPCServer = srv // gRPC服务器赋值

	ecaLogger.Info("ECA started.")
}

// Stop stops the ECA services. 停止ECA服务
func (eca *ECA) Stop() {
	ecaLogger.Info("Stopping ECA services...")
	if eca.gRPCServer != nil {
		eca.gRPCServer.Stop() // 停止gRPC服务器
	}
	err := eca.CA.Stop() // 停止CA
	if err != nil {
		ecaLogger.Errorf("ECA Error stopping services: %s", err)
	} else {
		ecaLogger.Info("ECA stopped")
	}
}

// 启动ECAP服务
func (eca *ECA) startECAP(srv *grpc.Server) {
	pb.RegisterECAPServer(srv, &ECAP{eca}) // 注册一个ECA服务
	ecaLogger.Info("ECA PUBLIC gRPC API server started")
}

// 启动ECAA
func (eca *ECA) startECAA(srv *grpc.Server) {
	pb.RegisterECAAServer(srv, &ECAA{eca}) // 注册一个ECAA服务
	ecaLogger.Info("ECA ADMIN gRPC API server started")
}
