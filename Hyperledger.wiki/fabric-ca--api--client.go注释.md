# 1、api/client.go
引用cloudflare/cfssl/csr包，这个包是CloudFlare's PKI toolkit；
引用fabric-ca/lib/tcert，这个包是Transaction Certificate (TCert), 当在hyperledger fabric区块链上进行交易时，保证匿名性和不可追踪性。
定义以下结构体：
## 1）RegistrationRequest，注册一个新的身份的请求
### 成员变量：
    Name：身份标识
    Type：身份类型
    Secret：注册时提供的身份信息，该字段可省略
    MaxEnrollments：用户可重复登记次数的最大登记个数，该字段可省略
    Affiliation：身份的从属关系，该字段可省略
    Attributes：属性，该字段可省略 结构体数组，定义参考：10
    CAName：CA的名称，该字段可省略
## 2） RegistrationResponse，注册响应
### 成员变量：
    Secret：身份信息 //注册成功后会反馈该信息
## 3）EnrollmentRequest，登记一个身份的请求
### 成员变量：
    Name：要注册的标识名
    Secret：注册返回的secret，该字段可省略
    Profile：配置文件是在颁发证书时使用的签名配置文件的名称，该字段可省略
    Label：使用HSM操作的标签，该字段可省略  HSM 高速存储器？
    CSR：Certificate Signing Request info，证书签名请求信息，该字段可省略，结构体指针，定义参考(9)
    CAName：想要连接的CA的名称，该字段可省略
## 4）ReenrollmentRequest，重新注册一个身份的请求，用于在证书即将过期时更新证书
### 成员变量：
    Profile：配置文件是在颁发证书时使用的签名配置文件的名称，该字段可省略
    Label：使用HSM操作的标签，该字段可省略  HSM 高速存储器？
    CSR：Certificate Signing Request info，证书签名请求信息，该字段可省略
    CAName：想要连接的CA的名称，该字段可省略	
## 5）RevocationRequest，单一的证书或身份相关的所有证书撤销请求。
要撤销单个证书，必须设置Serial和AKI字段; 否则，要撤消所有证书和与注册ID相关联的身份，Name字段必须设置为现有的注册ID。RevocationRequest只能由具有“hf.Revoker”属性的用户执行。
### 成员变量：
    Name：想要撤销证书的用户名称，该字段可省略
    Serial：要撤销的证书的序列号，该字段可省略
    AKI：将要被撤销证书的AKI(Authority Key Identifier)，该字段可省略
    Reason：撤销证书的原因，该字段可省略默认值为0，其他有效值参考[文档](https://godoc.org/golang.org/x/crypto/ocsp)
    CAName：想要连接的CA的名称，该字段可省略	
## 6）GetTCertBatchRequest，为identity.GetTCertBatch提供输入。
identity.GetTCertBatch在fabric-ca/lib/identity.go中，为当前identity返回一批Tcerts。
### 成员变量：
	Count ：整型，批处理中的Tcert数目。
	AttrNames ：string数组类型，将名称和值封装在发出的TCerts中的属性名称。该字段可省略。
	EncryptAttrs ：bool类型，表示是否加密属性值。当设置为true时，批处理中每个发出的TCert将包含加密的属性值。该字段可省略。
	ValidityPeriod ：time.Duration类型，证书有效期。如果指定，所使用的值是TCert管理器的最小值和配置的有效期。该字段可省略。
	PreKey ：string类型，用于密钥派生。
	DisableKeyDerivation ：bool类型，标识是否使用密钥派生。如果设置为true，则禁用密钥派生，以使TCert与ECert不具有密码相关性。 当使用不支持TCert密钥导出功能的HSM时，这可能是必需的，该字段可省略。
	CAName ：string类型，想要链接的CA的名称，该字段可省略。
## 7）GetTCertBatchResponse，identity.GetTCertBatch的返回值
### 成员变量：
tcert.GetBatchResponse：fabric-ca/lib/Tcert/api.go中，响应GetBatch API。
## 8）GetCAInfoRequest，获取通用CA信息的请求
### 成员变量：
	CAName ：string类型，想要链接的CA的名称，该字段可省略。
## 9）CSRInfo，CSRInfo is Certificate Signing Request information，证书签名请求信息
### 成员变量：
	CN           string               `json:"CN"`
	Names        []csr.Name           `json:"names,omitempty"`
	Hosts        []string             `json:"hosts,omitempty"`
	KeyRequest   *csr.BasicKeyRequest `json:"key,omitempty"`
	CA           *csr.CAConfig        `json:"ca,omitempty"`
	SerialNumber string               `json:"serial_number,omitempty"`
## 10）Attribute，一个键值对（name，value）
### 成员变量：
	Name  string `json:"name"`
	Value string `json:"value"`


	
	
