fabric-ca：即原先fabric v0.6中的 membersrvc，现独立成一个新的项目。
## 1. api包
* client.go <br>
定义了一些请求和相应的结构体，包括RegistrationRequest、RegistrationResponse、EnrollmentRequest、ReenrollmentRequest、RevocationRequest、GetTCertBatchRequest、GetTCertBatchResponse、GetCAInfoRequest、CSRInfo(Certificate Signing Request information)、Attribute。
* net.go <br>
包含一些结构体定义，这些结构体作用：在Fabric-ca客户端和fabric-ca服务器之间通过网络进行请求和响应。

## 2. cmd包
### fabric-ca-client包
定义了一些client指令和指令配置文件，client指令主要有enroll、reenroll、register、revoke、getcacert；指令配置文件主要是定义了一些指令的用法及指令介绍。另外，该包含有main.go文件：
* 定义了rootCmd变量，rootCmd是Hyperledger Fabric CA客户端的基本命令；
* init初始化函数，进行client配置
* RunMain函数，fabric-ca-client主函数
* checkAndEnableProfiling函数，检查FABRIC_CA_CLIENT_PROFILE_MODE环境变量，如果设置为“cpu”，则启用cpu分析; 如果将其设置为“heap”，则会启用堆分析<br>
* `Fabric CA Client`功能
   1. `Enrolling the bootstrap identity`<br>
   2. `Registering a new identity`<br>
   3. `Enrolling a peer identity`<br>
   4. `Reenrolling an identity`<br>
   5. `Revoking a certificate or identity`<br>
   6. `Enabling TLS`<br>
   7. `Contact specific CA instance`<br>
### fabric-ca-server包
定义了server端的指令，含有server的config.go、init.go、main.go、start.go，还有个Apache v2.0 的license文件，Apache 2 许可文件。
* config.go <br>
定义了一些server端使用的变量、配置信息说明、初始化配置文件的函数configInit()和createDefaultConfigFile()、获取CA的函数getCAName（）。
* init.go <br>
server端初始化配置、初始化指令、执行指令。
* main.go <br>
基本上同client的main.go功能相同，只不过操作对象是server，此外该文件还含有一个getServer()函数，为init和start命令获取服务器。
* start.go <br>
初始化并启动server。<br>
* `Fabric CA Server`功能
   1. `Initializing the server`<br>
   2. `Starting the server`<br>
   3. `Configuring the database`<br>
   4. `Configuring LDAP`<br>
   5. `Setting up a cluster`<br>
   6. `Setting up multiple CAs`<br>
   7. `Enrolling an intermediate CA`<br>

## 3. docker包
含有两个docker-compose.yml文件，一个是样例，一个用来运行服务器。另外含有README.md文件，介绍使用方法。
* examples/client-server-flow下docker-compose.yml，此示例通用客户端和服务器流。
* 服务器目录包含一个docker-compose.yml文件来运行fabric-ca-server。

## 4. docs包
含有一些css、html文件，以及一些说明文档。
* users-guide.rst <br>
这个文档很重要，详细的介绍了fabric-ca的安装配置、使用。

## 5. images包
含有fabric-ca、openldap、fabric-ca-fvt目录，一些跟 Docker 镜像生成相关的配置和脚本。主要包括各个镜像的 Dockerfile.in 文件。这些文件是生成 Dockerfile 的模板。

## 6. lib包，特别重要
含有项目的大多数代码，包含了dbutil、ldap、spi、tcert、tls包，以及一些ca、client、server的配置、链接、处理异常的文件。
* dbutil包 <br>
数据库相关操作，数据库包括SQLite、postgres、MySQL三种数据库。<br>
* ldap包 <br>
ldap，轻量目录访问协议。配置、创建LDAP客户端，提供对用户及附属组(affiliation group)的增删改查功能。<br>
* spi包 <br>
**_affiliation.go_:** 定义了Affiliation接口，包括组名称Name及其父项Prekey这两个变量、及获取它们的方法。<br>
**_userregistry.go_:** 定义了fabric-ca服务器使用的用户注册接口。<br>
* tcert包 <br>
**_api.go_:** 包含对TCert库API的输入和输出的定义。<br>
**_keytree.go_:** KeyTree是派生密钥的树，该树是具有单个根密钥的派生密钥的层次结构。该树中的每个节点都有一个key和name，key是一些secret，name可能是公共的。 如果与节点相关联的secret是已知的，则如果节点的name已知，则可以导出其子树中每个节点的secret; 然而，无法导出不属于该子树的其他节点相关联的key。该数据结构有助于向审核员公布与任何节点相关联的secret，而不会让审核员访问树中的所有节点。<br>
**_tcert.go_:** 获取TCert，生成要包含在TCert中的加密扩展等。<br>
**_util.go_:** 一些加密算法和一些标准的加解密操作（密钥的获取、解析等）；X509证书的获取、信息处理等。<br>
* tls包 <br>
包含服务器和客户端的TLS相关代码; TLS相关的一些操作。
* ca <br>
包括 _ca.go_ 、 _caconfig.go_ 文件。定义了ca的结构体；创建、初始化ca，获取ca证书（证书链），初始化用户注册表接口、注册签名者，加载用户列表等功能。
* client <br>
包括 _client.go_ 、 _clientconfig.go_ 、 _identity.go_ 文件。定义了client结构体；初始化；含由clientconfig.go配置的主Client对象。
* server <br>
包括 _server.go_ 、 _serverauth.go_ 、 _serverconfig.go_ 、 _serverenroll.go_ 、 _servererrors.go_ 、 _serverregister.go_ 、
 _serverrevoke.go_ 、 _servercert.go_ 文件。含由serverconfig.go配置的主服务器对象。
* database <br>
包括 _certdbaccessor.go_ 、 _dbaccessor.go_ 文件。
* 其他 <br>
**_signer.go：_**  <br>
**_util.go：_**  <br>
## 7. release_notes包
一些日志记录，包括错误修复，文档和测试覆盖改进，基于用户反馈和更改UX改进，以解决各种静态扫描发现（未使用的代码，静态安全扫描，拼写，linting等），这个包基本没啥用？

## 8. scripts包
一些辅助脚本，多数为外部 Makefile 调用。

## 9. swagger包
仅包含 _swagger-fabric-ca.json_ 文件，提供fabric-ca-server API，自动生成同步的在线文档;与 Fabric CA 服务端的所有通信，都是通过 REST API 进行的。
* swagger <br>
Swagger 文档提供了一个方法，使我们可以用指定的 JSON 或者 YAML 摘要来描述你的 API，包括了比如 names、order 等 API 信息。<br>
官方介绍：Swagger是一个规范且完整的框架，提供描述、生产、消费和可视化RESTful Web Service。<br>
专业角度：Swagger是由庞大工具集合支撑的形式化规范。这个集合涵盖了从终端用户接口、底层代码库到商业API管理的方方面面。<br>

## 10. testdata包
包含ca、rootca的配置信息，以及各种位数的加密算法的所需的参数、密钥等其他相关数据。

## 11. util包
提供一些
* mocks目录 <br>
该目录下只有bccsp.go文件，模仿fabric/bccsp，区块链加密服务提供者（Blockchain Crypto Service Provider），提供一些密码学相关操作的实现，包括 Hash、签名、校验、加解密等。
* 其他文件 <br>
**_args.go：_** 参数处理转换。<br>
**_csp.go：_** 处理一些和BCCSP相关的操作：初始化、配置、获取BCCSP;获取签名、请求密钥（对）、加载密钥等。<br>
**_flag.go：_** 设置并处理一些字段标志，这些标志有：<br>
&nbsp;&nbsp;&nbsp;&nbsp; “def” - 字段的默认值;<br>
&nbsp;&nbsp;&nbsp;&nbsp; “opt” - 在命令行中使用的可选的一个字符短名称;<br>
&nbsp;&nbsp;&nbsp;&nbsp; “help” - 在命令行上显示的帮助信息;<br>
&nbsp;&nbsp;&nbsp;&nbsp; “skip” - skip字段。<br>
**_struct.go：_** 定义了filed结构体，filed是一个任意结构的filed。定义了ParseObj()函数，解析对象结构，回调每个字段的字段信息。
定义了CopyMissingValues()函数，检查dst接口的缺失值。<br>
**_util.go：_** 读写文件；获取一些加密算法（ECDSA、RSA）的密钥，签名；编解码处理；http请求；证书字段处理；<br>

## 12. vendor包
管理包依赖<br>
查找依赖包路径的解决方案如下：<br>
* 当前包下的vendor目录。 <br>
* 向上级目录查找，直到找到src下的vendor目录。 <br>
* 在GOPATH下面查找依赖包。 <br>
* 在GOROOT目录下查找 <br>

## 13. 其他文件
根目录下的一些文件，包括一些说明文档、安装需求说明、License 信息文件等
* Makefile文件 <br>
builds all targets and runs all tests/checks，执行测试、格式检查、安装依赖、生成镜像等操作。
* README.md文件 <br>
开发者帮助文档，项目的说明文件，包括一些有用的链接等。
* docker-env.mk <br>
被 Makefile 引用，生成 Docker 镜像时的环境变量。
* git 相关文件 <br>
**_.gitignore：_** git 代码管理时候忽略的文件和目录，包括 build 和 bin 等中间生成路径。<br>
**_.gitreview：_** 使用 git review 时候的配置，带有项目的仓库地址信息。<br>
