## 1、JSON 介绍
JSON(JavaScript Object Notation, JS 对象标记) 是一种轻量级的数据交换格式。具体介绍可参考https://zh.wikipedia.org/wiki/JSON
## 2、JSON 与 Go 
Go语言自带的JSON转换库为 encoding/json。
这是官方的一篇博客，介绍的挺详细，不过是英文版的：http://golang.org/doc/articles/json_and_go.html。
## 3、用处

```
//引用 hyperledger fabric-ca 的go语言代码
type RegistrationRequest struct {
    // Name is the unique name of the identity
    Name string `json:"id" help:"Unique name of the identity"`
    // Type of identity being registered (e.g. "peer, app, user")
    Type string `json:"type" help:"Type of identity being registered (e.g. 'peer, app, user')"`
    // Secret is an optional password.  If not specified,
    // a random secret is generated.  In both cases, the secret
    // is returned in the RegistrationResponse.
    Secret string `json:"secret,omitempty" help:"The enrollment secret for the identity being registered"`
    // MaxEnrollments is the maximum number of times the secret can
    // be reused to enroll.
    MaxEnrollments int `json:"max_enrollments,omitempty" help:"The maximum number of times the secret can be reused to enroll."`
    // is returned in the response.
    // The identity's affiliation.
    // For example, an affiliation of "org1.department1" associates the identity with "department1" in "org1".
    Affiliation string `json:"affiliation" help:"The identity's affiliation"`
    // Attr is used to support a single attribute provided through the fabric-ca-client CLI
    Attr string `help:"Attributes associated with this identity (e.g. hf.Revoker=true)"`
    // Attributes associated with this identity
    Attributes []Attribute `json:"attrs,omitempty"`
}
```

结构体成员变量 'xxxx' 里面的 json字符串是Go语言的structTag。
structTag：如果希望手动配置结构体的成员和JSON字段的对应关系，可以在定义结构体的时候给成员打标签：
使用omitempty熟悉，如果该字段为nil或0值（数字0,字符串"",空数组[]等），则打包的JSON结果不会有这个字段。
样例：点击打开链接
## 4、其他用法
可参考博客：http://blog.csdn.net/tiaotiaoyly/article/details/38942311

## 转自：http://blog.csdn.net/code_segment/article/details/76795317











