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
	"crypto/x509"
	"database/sql"
	"errors"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/flogging"
	pb "github.com/hyperledger/fabric/membersrvc/protos"
	"github.com/op/go-logging"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var tlscaLogger = logging.MustGetLogger("tlsca")

// TLSCA is the tls certificate authority.
//
type TLSCA struct {
	*CA
	eca        *ECA
	gRPCServer *grpc.Server
}

// TLSCAP serves the public GRPC interface of the TLSCA.
//
type TLSCAP struct {
	tlsca *TLSCA
}

// TLSCAA serves the administrator GRPC interface of the TLS.
//
type TLSCAA struct {
	tlsca *TLSCA
}

// 初始化TLSCA的表格，调用ca.go中的函数，初始化公共表格：Certificates、Users、AffiliationGroups
func initializeTLSCATables(db *sql.DB) error {
	return initializeCommonTables(db)
}

// NewTLSCA sets up a new TLSCA.
// 设置新的TLSCA
func NewTLSCA(eca *ECA) *TLSCA {
	tlsca := &TLSCA{NewCA("tlsca", initializeTLSCATables), eca, nil}
	flogging.LoggingInit("tlsca")

	return tlsca
}

// Start starts the TLSCA.
// 启动TLSCA服务
func (tlsca *TLSCA) Start(srv *grpc.Server) {
	tlsca.startTLSCAP(srv) // 启动TLSCAP服务
	tlsca.startTLSCAA(srv) // 启动TLSCAA服务

	tlscaLogger.Info("TLSCA started.")
}

// 启动TLSCAP服务
func (tlsca *TLSCA) startTLSCAP(srv *grpc.Server) {
	pb.RegisterTLSCAPServer(srv, &TLSCAP{tlsca})
}

// 启动TLSCAA服务
func (tlsca *TLSCA) startTLSCAA(srv *grpc.Server) {
	pb.RegisterTLSCAAServer(srv, &TLSCAA{tlsca})
}

// Stop stops the TCA services. 停止TCA服务
func (tlsca *TLSCA) Stop() error {
	tlscaLogger.Info("Stopping the TLSCA services...")
	if tlsca.gRPCServer != nil {
		tlsca.gRPCServer.Stop()
	}
	err := tlsca.CA.Stop()
	if err != nil {
		tlscaLogger.Errorf("Error stopping the TLSCA services: %s", err)
	} else {
		tlscaLogger.Info("TLSCA services stopped")
	}
	return err
}

// ReadCACertificate reads the certificate of the TLSCA.
// 读取TLSCA的证书
func (tlscap *TLSCAP) ReadCACertificate(ctx context.Context, in *pb.Empty) (*pb.Cert, error) {
	tlscaLogger.Debug("grpc TLSCAP:ReadCACertificate")

	return &pb.Cert{Cert: tlscap.tlsca.raw}, nil
}

// CreateCertificate requests the creation of a new enrollment certificate by the TLSCA.
// 请求TLSCA创建新的注册证书。
func (tlscap *TLSCAP) CreateCertificate(ctx context.Context, in *pb.TLSCertCreateReq) (*pb.TLSCertCreateResp, error) {
	tlscaLogger.Debug("grpc TLSCAP:CreateCertificate")

	id := in.Id.Id

	sig := in.Sig
	in.Sig = nil // 清除签名

	r, s := big.NewInt(0), big.NewInt(0)
	r.UnmarshalText(sig.R)
	s.UnmarshalText(sig.S) // 获取签名

	raw := in.Pub.Key                       // 获取公钥
	if in.Pub.Type != pb.CryptoType_ECDSA { // 判断加密类型
		return nil, errors.New("unsupported key type")
	}
	pub, err := x509.ParsePKIXPublicKey(in.Pub.Key) // 解析公钥
	if err != nil {
		return nil, err
	}

	// 验证签名
	hash := primitives.NewHash()
	raw, _ = proto.Marshal(in)
	hash.Write(raw)
	if ecdsa.Verify(pub.(*ecdsa.PublicKey), hash.Sum(nil), r, s) == false {
		return nil, errors.New("signature does not verify")
	}

	// 创建证书
	if raw, err = tlscap.tlsca.createCertificate(id, pub.(*ecdsa.PublicKey), x509.KeyUsageDigitalSignature, in.Ts.Seconds, nil); err != nil {
		tlscaLogger.Error(err)
		return nil, err
	}

	return &pb.TLSCertCreateResp{Cert: &pb.Cert{Cert: raw}, RootCert: &pb.Cert{Cert: tlscap.tlsca.raw}}, nil
}

// ReadCertificate reads an enrollment certificate from the TLSCA.
// 从TLSCA读取注册证书
func (tlscap *TLSCAP) ReadCertificate(ctx context.Context, in *pb.TLSCertReadReq) (*pb.Cert, error) {
	tlscaLogger.Debug("grpc TLSCAP:ReadCertificate")

	raw, err := tlscap.tlsca.readCertificateByKeyUsage(in.Id.Id, x509.KeyUsageKeyAgreement) // 读取证书
	if err != nil {
		return nil, err
	}

	return &pb.Cert{Cert: raw}, nil
}

// RevokeCertificate revokes a certificate from the TLSCA.  Not yet implemented.
// 未实现
func (tlscap *TLSCAP) RevokeCertificate(context.Context, *pb.TLSCertRevokeReq) (*pb.CAStatus, error) {
	tlscaLogger.Debug("grpc TLSCAP:RevokeCertificate")

	return nil, errors.New("not yet implemented")
}

// RevokeCertificate revokes a certificate from the TLSCA.  Not yet implemented.
// 未实现
func (tlscaa *TLSCAA) RevokeCertificate(context.Context, *pb.TLSCertRevokeReq) (*pb.CAStatus, error) {
	tlscaLogger.Debug("grpc TLSCAA:RevokeCertificate")

	return nil, errors.New("not yet implemented")
}
