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

package main

import (
	"net"
	"os"
	"path/filepath"
	"runtime"

	"strings"

	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/flogging"
	"github.com/hyperledger/fabric/membersrvc/ca"
	"github.com/hyperledger/fabric/metadata"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const envPrefix = "MEMBERSRVC_CA"

var logger = logging.MustGetLogger("server")

func main() {

	viper.SetEnvPrefix(envPrefix)             // 设置环境变量前缀
	viper.AutomaticEnv()                      // 检查设置在config，default，flags中的所有键的ENV变量
	replacer := strings.NewReplacer(".", "_") // 字符串中字符替换
	viper.SetEnvKeyReplacer(replacer)         // 设置viper对象上的strings.Replacer用于将环境变量映射到与其不匹配的键。
	viper.SetConfigName("membersrvc")         // 为配置文件命名
	viper.SetConfigType("yaml")               // 为配置文件设置类型
	viper.AddConfigPath("./")                 // 设置路径

	// Path to look for the config file based on GOPATH
	gopath := os.Getenv("GOPATH")                  // 系统GOPATH
	for _, p := range filepath.SplitList(gopath) { //SplitList分割由特定操作系统的ListSeparator连接的路径列表，通常位于PATH或GOPATH环境变量中。
		cfgpath := filepath.Join(p, "src/github.com/hyperledger/fabric/membersrvc")
		viper.AddConfigPath(cfgpath)
	}
	err := viper.ReadInConfig() // 检索并加载配置文件爱呢
	if err != nil {
		logger.Panicf("Fatal error when reading %s config file: %s", "membersrvc", err)
	}

	flogging.LoggingInit("server")

	// Init the crypto layer
	if err := crypto.Init(); err != nil { // Init初始化加密层。 从viper加载安全级别和日志记录设置。
		logger.Panicf("Failed initializing the crypto layer [%s]", err)
	}

	// cache configure
	ca.CacheConfiguration() // ca包中的函数，暂存配置文件

	logger.Infof("CA Server (" + metadata.Version + ")") // 版本号，从Makefile中获取

	aca := ca.NewACA() // ca包中的函数，创建一个ACA实例
	defer aca.Stop()   // 最后执行，停止ACA服务

	eca := ca.NewECA(aca) // ca包中的函数，创建一个ECA实例
	defer eca.Stop()      // 最后执行，停止ECA服务

	tca := ca.NewTCA(eca) // ca包中的函数，创建一个TCA实例
	defer tca.Stop()      // 最后执行，停止TCA服务

	tlsca := ca.NewTLSCA(eca) // ca包中的函数，创建一个TLSCA实例
	defer tlsca.Stop()        // 最后执行，停止TLSCA服务

	runtime.GOMAXPROCS(viper.GetInt("server.gomaxprocs")) // GOMAXPROCS设置可以同时执行的最大CPU数，并返回上一个设置。

	var opts []grpc.ServerOption // 服务选项设置

	if viper.GetBool("security.tls_enabled") {
		logger.Debug("TLS was enabled [security.tls_enabled == true]")
		// NewServerTLSFromFile从输入的证书文件和服务器的密钥文件构造一个TLS。
		creds, err := credentials.NewServerTLSFromFile(viper.GetString("server.tls.cert.file"), viper.GetString("server.tls.key.file"))
		if err != nil {
			logger.Panic(err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)} // Creds返回一个为服务器连设置证书的ServerOption，
	} else {
		logger.Debug("TLS was not enabled [security.tls_enabled == false]")
	}

	srv := grpc.NewServer(opts...) // 新建一个gRPC服务器

	if viper.GetBool("aca.enabled") { // 与参数相关联的值的bool值
		logger.Debug("ACA was enabled [aca.enabled == true]")
		aca.Start(srv) // 启动ACA
	}
	eca.Start(srv)   // 启动ECA
	tca.Start(srv)   // 启动TCA
	tlsca.Start(srv) // 启动TLSCA

	// GetString将与参数相关联的值作为字符串laddr返回； Listen监听本地网络地址上laddr的通报
	if sock, err := net.Listen("tcp", viper.GetString("server.port")); err != nil {
		logger.Errorf("Fail to start CA Server: %s", err)
		os.Exit(1) //程序退出
	} else {
		// Serve接受监听器sock上的传入连接，为每个服务器创建一个新的服务传输和服务程序(goroutine)。
		// 服务程序读取gRPC请求，然后调用注册的处理程序来处理它们。 sock.Accept失败时返回服务。 当此方法返回时，sock将被关闭。
		srv.Serve(sock)
		sock.Close() // 关闭监听程序
	}
}
