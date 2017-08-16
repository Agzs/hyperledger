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
	"bytes"
	"crypto/ecdsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/ioutil"
	"math/big"
	"strconv"
	"time"

	"github.com/hyperledger/fabric/core/crypto/primitives/ecies"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	pb "github.com/hyperledger/fabric/membersrvc/protos"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
)

var ecapLogger = logging.MustGetLogger("ecap")

// ECAP serves the public GRPC interface of the ECA.
//
type ECAP struct {
	eca *ECA
}

// ReadCACertificate reads the certificate of the ECA.
// 读取ECA的证书
func (ecap *ECAP) ReadCACertificate(ctx context.Context, in *pb.Empty) (*pb.Cert, error) {
	ecapLogger.Debug("gRPC ECAP:ReadCACertificate")

	return &pb.Cert{Cert: ecap.eca.raw}, nil
}

// 获取属性
func (ecap *ECAP) fetchAttributes(cert *pb.Cert) error {
	//TODO we are creating a new client connection per each ecert request. We should implement a connections pool.
	sock, acaP, err := GetACAClient() // 获取ACAClient，返回值类型为(*grpc.ClientConn, pb.ACAPClient, error)
	if err != nil {
		return err
	}
	defer sock.Close() // 最后执行，关闭客户端连接

	req := &pb.ACAFetchAttrReq{ // 构建请求（Request）结构体
		Ts:        &timestamp.Timestamp{Seconds: time.Now().Unix(), Nanos: 0}, // 时间戳
		ECert:     cert,                                                       // Ecert，注册证书
		Signature: nil}                                                        // 签名

	var rawReq []byte
	rawReq, err = proto.Marshal(req) // 编码，格式转换
	if err != nil {
		return err
	}

	var r, s *big.Int

	r, s, err = primitives.ECDSASignDirect(ecap.eca.priv, rawReq) // 使用ECA私钥进行签名

	if err != nil {
		return err
	}

	R, _ := r.MarshalText()
	S, _ := s.MarshalText() // 编码，转换格式

	req.Signature = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S} // 构建签名结构体

	resp, err := acaP.FetchAttributes(context.Background(), req) // 获取属性，构建响应（Response）结构体
	if err != nil {
		return err
	}

	if resp.Status != pb.ACAFetchAttrResp_FAILURE {
		return nil
	}
	return errors.New("Error fetching attributes.")
}

// CreateCertificatePair requests the creation of a new enrollment certificate pair by the ECA.
// 请求由ECA创建新的注册证书对。
func (ecap *ECAP) CreateCertificatePair(ctx context.Context, in *pb.ECertCreateReq) (*pb.ECertCreateResp, error) {
	ecapLogger.Debug("gRPC ECAP:CreateCertificate")

	// validate token
	var tok, prev []byte
	var role, state int
	var enrollID string

	id := in.Id.Id                                                           // 用户id
	err := ecap.eca.readUser(id).Scan(&role, &tok, &state, &prev, &enrollID) // 根据id读取用户，并返回用户角色、token、状态、key、注册ID

	if err != nil {
		errMsg := "Identity lookup error: " + err.Error()
		ecapLogger.Debug(errMsg)
		return nil, errors.New(errMsg)
	}
	if !bytes.Equal(tok, in.Tok.Tok) {
		ecapLogger.Debugf("id or token mismatch: id=%s", id)
		return nil, errors.New("Identity or token does not match.")
	}

	ekey, err := x509.ParsePKIXPublicKey(in.Enc.Key) // 解析DER编码的PKIX公钥
	if err != nil {
		return nil, err
	}

	// fetchResult指示在注册期间调用的获取属性的结果。
	fetchResult := pb.FetchAttrsResult{Status: pb.FetchAttrsResult_SUCCESS, Msg: ""}
	switch {
	case state == 0: // 初始化请求
		// initial request, create encryption challenge
		tok = []byte(randomString(12)) //随机生成12位字符串

		mutex.Lock()                                                                                             // 互斥，上锁
		_, err = ecap.eca.db.Exec("UPDATE Users SET token=?, state=?, key=? WHERE id=?", tok, 1, in.Enc.Key, id) // 更新数据库
		mutex.Unlock()                                                                                           // 解锁

		if err != nil {
			ecapLogger.Error(err)
			return nil, err
		}

		spi := ecies.NewSPI()                                           // 新建一个SPI实例
		eciesKey, err := spi.NewPublicKey(nil, ekey.(*ecdsa.PublicKey)) // 生成一个新的公钥
		if err != nil {
			return nil, err
		}

		ecies, err := spi.NewAsymmetricCipherFromPublicKey(eciesKey) // 从eciesKey创建一个新的ecies加密
		if err != nil {
			return nil, err
		}

		out, err := ecies.Process(tok) // 处理输入中给定的字节数组tok

		return &pb.ECertCreateResp{Certs: nil, Chain: nil, Pkchain: nil, Tok: &pb.Token{Tok: out}}, err // Ecert创建的响应构建

	case state == 1: // 确保用于challenge的相同加密密钥已被签名
		// ensure that the same encryption key is signed that has been used for the challenge
		if subtle.ConstantTimeCompare(in.Enc.Key, prev) != 1 { // 当且仅当两个参数具有相同的内容时，ConstantTimeCompare返回1。
			return nil, errors.New("Encryption keys do not match.")
		}

		// validate request signature
		sig := in.Sig
		in.Sig = nil // 删除签名

		r, s := big.NewInt(0), big.NewInt(0)
		r.UnmarshalText(sig.R)
		s.UnmarshalText(sig.S) // 获取签名

		if in.Sign.Type != pb.CryptoType_ECDSA { // 签名类型判断
			return nil, errors.New("Unsupported (signing) key type.")
		}
		skey, err := x509.ParsePKIXPublicKey(in.Sign.Key) //解析PKIX公钥
		if err != nil {
			return nil, err
		}

		// 验证签名
		hash := primitives.NewHash()
		raw, _ := proto.Marshal(in)
		hash.Write(raw)
		if ecdsa.Verify(skey.(*ecdsa.PublicKey), hash.Sum(nil), r, s) == false {
			return nil, errors.New("Signature verification failed.")
		}

		// create new certificate pair，创建一个新的证书对
		ts := time.Now().Add(-1 * time.Minute).UnixNano() // 时间戳

		// 创建skey的证书
		spec := NewDefaultCertificateSpecWithCommonName(id, enrollID, skey.(*ecdsa.PublicKey), x509.KeyUsageDigitalSignature, pkix.Extension{Id: ECertSubjectRole, Critical: true, Value: []byte(strconv.Itoa(ecap.eca.readRole(id)))})
		sraw, err := ecap.eca.createCertificateFromSpec(spec, ts, nil, true) // 使用spec(证书规格)新建一个证书
		if err != nil {
			ecapLogger.Error(err)
			return nil, err
		}

		_ = ioutil.WriteFile("/tmp/ecert_"+id, sraw, 0644) // 写入文件，且文件拥有权限

		// 创建ekey的证书
		spec = NewDefaultCertificateSpecWithCommonName(id, enrollID, ekey.(*ecdsa.PublicKey), x509.KeyUsageDataEncipherment, pkix.Extension{Id: ECertSubjectRole, Critical: true, Value: []byte(strconv.Itoa(ecap.eca.readRole(id)))})
		eraw, err := ecap.eca.createCertificateFromSpec(spec, ts, nil, true)
		if err != nil { // 起到回滚作用
			mutex.Lock()
			ecap.eca.db.Exec("DELETE FROM Certificates Where id=?", id)
			mutex.Unlock()
			ecapLogger.Error(err)
			return nil, err
		}

		mutex.Lock()
		_, err = ecap.eca.db.Exec("UPDATE Users SET state=? WHERE id=?", 2, id)
		mutex.Unlock()
		if err != nil { // 起到回滚作用
			mutex.Lock()
			ecap.eca.db.Exec("DELETE FROM Certificates Where id=?", id)
			mutex.Unlock()
			ecapLogger.Error(err)
			return nil, err
		}

		var obcECKey []byte
		if role == int(pb.Role_VALIDATOR) { // validator
			obcECKey = ecap.eca.obcPriv // 私钥
		} else {
			obcECKey = ecap.eca.obcPub // 公钥
		}
		if role == int(pb.Role_CLIENT) { // client
			//Only client have to fetch attributes.
			if viper.GetBool("aca.enabled") { // 获取相关联的bool值
				err = ecap.fetchAttributes(&pb.Cert{Cert: sraw}) // 获取属性
				if err != nil {
					fetchResult = pb.FetchAttrsResult{Status: pb.FetchAttrsResult_FAILURE, Msg: err.Error()}
					// 指示在注册期间调用的获取属性的结果。
				}
			}
		}

		return &pb.ECertCreateResp{Certs: &pb.CertPair{Sign: sraw, Enc: eraw}, Chain: &pb.Token{Tok: ecap.eca.obcKey}, Pkchain: obcECKey, Tok: nil, FetchResult: &fetchResult}, nil
	}

	return nil, errors.New("Invalid (=expired) certificate creation token provided.")
}

// ReadCertificatePair reads an enrollment certificate pair from the ECA.
// 从ECA读取证书对
func (ecap *ECAP) ReadCertificatePair(ctx context.Context, in *pb.ECertReadReq) (*pb.CertPair, error) {
	ecapLogger.Debug("gRPC ECAP:ReadCertificate")

	rows, err := ecap.eca.readCertificates(in.Id.Id) // 读取证书，等价于ecap.eca.CA.readCertificates()
	defer rows.Close()                               // 最后执行，关闭结果集

	hasResults := false
	var certs [][]byte
	if err == nil {
		for rows.Next() { // 依次读取，追加到certs数组中
			hasResults = true
			var raw []byte
			err = rows.Scan(&raw)
			certs = append(certs, raw)
		}
		err = rows.Err()
	}

	if !hasResults {
		return nil, errors.New("No certificates for the given identity were found.")
	}
	return &pb.CertPair{Sign: certs[0], Enc: certs[1]}, err // 返回构建的证书对
}

// ReadCertificateByHash reads a single enrollment certificate by hash from the ECA.
// 通过hash值向ECA读取证书
func (ecap *ECAP) ReadCertificateByHash(ctx context.Context, hash *pb.Hash) (*pb.Cert, error) {
	ecapLogger.Debug("gRPC ECAP:ReadCertificateByHash")

	raw, err := ecap.eca.readCertificateByHash(hash.Hash) // 通过hash值读取证书，等价于ecap.eca.CA.readCertificateByHash()
	return &pb.Cert{Cert: raw}, err
}

// RevokeCertificatePair revokes a certificate pair from the ECA.  Not yet implemented.
// 撤销证书对，未实现
func (ecap *ECAP) RevokeCertificatePair(context.Context, *pb.ECertRevokeReq) (*pb.CAStatus, error) {
	ecapLogger.Debug("gRPC ECAP:RevokeCertificate")

	return nil, errors.New("ECAP:RevokeCertificate method not (yet) implemented")
}
