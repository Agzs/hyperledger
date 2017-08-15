package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"time"

	pb "github.com/hyperledger/fabric/membersrvc/protos"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

/** Performs Certificate type validation **/
/*
*  Checks for valid Cert format type，检查有效证书的格式类型
*  Cert expiration，验证证书是否过期
*
 */
func isValidCertFormatted(certLocation string) bool {

	var isvalidCert = false
	certificate, err := ioutil.ReadFile(certLocation) // 读取certLocation文件，返回文件内容
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certificate) // 将在输入中找到下一个PEM格式的块（证书，私钥等），返回该块和输入的其余部分。
	if block == nil {
		certificates, err := x509.ParseCertificates(certificate) // 没有找到PEM数据，block为nil，解析证书内容
		if err != nil {
			caLogger.Error("Not a valid Certificate")
		} else {
			validCert := validateCert(certificates[0]) // 验证证书是否过期
			if !validCert {
				caLogger.Error("Certificate has expired")
			}
			return validCert
		}
	} else {
		certificates, err := x509.ParseCertificates(block.Bytes) // 解析找到的PEM块
		if err != nil {
			caLogger.Error("Not a valid Certificate")
		} else {
			validCert := validateCert(certificates[0]) // 验证证书是否过期
			if !validCert {
				caLogger.Error("Certificate has expired")
			}
			return validCert
		}
	}

	return isvalidCert

}

/** Given the cert , it checks for expiry， 检查是否过期
*  Does not check for revocation， 过期 不等于 撤销
 */
func validateCert(cert *x509.Certificate) bool {

	notBefore := cert.NotBefore // 证书生效时间
	notAfter := cert.NotAfter   // 证书失效时间

	currentTime := time.Now()                   // 当前时间
	diffFromExpiry := notAfter.Sub(currentTime) // notAfater - currentTime，剩余有效时间
	diffFromStart := currentTime.Sub(notBefore) // currentTime - notBefore，已使用时间

	return ((diffFromExpiry > 0) && (diffFromStart > 0)) // 必须在有效期内，有的证书可能还没生效也算过期。

}

/** NewClientTLSFromFile creates Client TLS connection credentials，创建客户端TLS连接凭据
*   @certFile : TLS Server Certificate in PEM format
*   @serverNameOverride : Common Name (CN) of the TLS Server Certificate
*   returns Secure Transport Credentials
 */
func NewClientTLSFromFile(certFile, serverNameOverride string) (credentials.TransportCredentials, error) {
	caLogger.Debug("upgrading to TLS1.2")
	b, err := ioutil.ReadFile(certFile) // 读取证书文件

	if err != nil {
		caLogger.Errorf("Certificate could not be found in the [%s] path", certFile)
		return nil, err
	}

	if !isValidCertFormatted(certFile) { //验证证书是否有效
		return nil, nil
	}

	cp := x509.NewCertPool() // 返回一个新的、空的证书集合

	ok := cp.AppendCertsFromPEM(b) // 尝试解析PEM编码证书b。返回值表示证书是否已成功解析。
	if !ok {
		caLogger.Error("credentials: failed to append certificates: ")
		return nil, nil
	}
	return credentials.NewTLS(&tls.Config{ServerName: serverNameOverride, RootCAs: cp, MinVersion: 0, MaxVersion: 0}), nil //NewTLS使用c构建基于TLS的TransportCredentials。
}

//GetClientConn returns a connection to the server located on *address*. 返回到位于“address”上的服务器的连接。
func GetClientConn(address string, serverName string) (*grpc.ClientConn, error) {

	caLogger.Debug("GetACAClient: using the given gRPC client connection to return a new ACA client")
	var opts []grpc.DialOption // 配置如何建立连接。

	if viper.GetBool("security.tls_enabled") { //返回与security.tls_enabled相关联的布尔值
		caLogger.Debug("TLS was enabled [security.tls_enabled == true]")

		creds, err := NewClientTLSFromFile(viper.GetString("security.client.cert.file"), viper.GetString("security.serverhostoverride")) // 创建客户端TLS连接凭据

		if err != nil {
			caLogger.Error("Could not establish TLS client connection in GetClientConn while getting creds:")
			caLogger.Error(err)
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		caLogger.Debug("TLS was not enabled [security.tls_enabled == false]")
		opts = append(opts, grpc.WithInsecure())
	}
	opts = append(opts, grpc.WithTimeout(time.Second*3))
	return grpc.Dial(address, opts...) // 创建给定address的客户端连接。
}

//GetACAClient returns a client to Attribute Certificate Authority. 获取ACAClient
func GetACAClient() (*grpc.ClientConn, pb.ACAPClient, error) {
	caLogger.Debug("GetACAClient: Trying to create a new ACA Client from the connection provided")
	conn, err := GetClientConn(viper.GetString("aca.address"), viper.GetString("aca.server-name")) // 返回到位于“address”上的服务器的连接。
	if err != nil {
		return nil, nil, err
	}

	client := pb.NewACAPClient(conn) // 根据服务器连接，新建一个ACA客户端

	return conn, client, nil
}
