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
	"net"
	"os"
	"testing"

	"github.com/spf13/viper"

	"fmt"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"google.golang.org/grpc"

	"time"
)

var (
	aca    *ACA
	eca    *ECA
	tca    *TCA
	server *grpc.Server
)

func TestMain(m *testing.M) {
	setupTestConfig()                     // 配置设置
	curve := primitives.GetDefaultCurve() // 获取用于加密的椭圆曲线
	fmt.Printf("Default Curve %v \n", curve)
	// Init PKI
	initPKI()                    // 初始化PKI
	go startPKI()                // 启动PKI
	defer cleanup()              // 最后执行，收尾工作
	time.Sleep(time.Second * 10) // 线程Sleep的10秒
	fmt.Println("Running tests....")
	ret := m.Run() // 运行测试程序
	fmt.Println("End running tests....")
	cleanupFiles() // 文件收尾处理
	os.Exit(ret)   // 退出测试程序

}

// 设置测试配置
func setupTestConfig() {
	primitives.SetSecurityLevel("SHA3", 256) // 设置安全配置文件算法采用SHA3，hash长度为256
	viper.AutomaticEnv()                     // 检查设置在config，default，flags中的所有键的ENV变量
	viper.SetConfigName("ca_test")           // name of config file (without extension)
	viper.AddConfigPath("./")                // path to look for the config file in
	viper.AddConfigPath("./..")              // path to look for the config file in
	err := viper.ReadInConfig()              // Find and read the config file
	if err != nil {                          // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
}

// 初始化PKI
func initPKI() {
	CacheConfiguration() // Cache configuration
	aca = NewACA()       // 创建实例
	eca = NewECA(aca)
	tca = NewTCA(eca)
}

// 启动PKI
func startPKI() {
	var opts []grpc.ServerOption
	fmt.Printf("open socket...\n")
	// GetString将与参数相关联的值作为字符串laddr返回； Listen监听本地网络地址上laddr的通报
	sockp, err := net.Listen("tcp", viper.GetString("server.port"))
	if err != nil {
		panic("Cannot open port: " + err.Error())
	}
	fmt.Printf("open socket...done\n")

	server = grpc.NewServer(opts...) // 新建服务
	aca.Start(server)                // 启动服务
	eca.Start(server)
	tca.Start(server)
	fmt.Printf("start serving...\n")
	server.Serve(sockp) // Serve接受监听器sockp上的传入连接，为每个服务器创建一个新的服务传输和服务程序(goroutine)。
	// 服务程序读取gRPC请求，然后调用注册的处理程序来处理它们。 sockp.Accept失败时返回服务。 当此方法返回时，sock将被关闭。
}

// 收尾工作
func cleanup() {
	fmt.Println("Cleanup...")
	stopPKI()
	fmt.Println("Cleanup...done!")
}

// 清理文件
func cleanupFiles() {
	//cleanup files
	path := viper.GetString("server.cadir") // 获取路径
	err := os.RemoveAll("./" + path)        // 删除文件爱呢
	if err != nil {
		fmt.Printf("Failed removing [%s] [%s]\n", path, err)
	}
}

// 停止PKI服务
func stopPKI() {
	aca.Stop()
	eca.Stop()
	tca.Stop()
	server.Stop()
}
