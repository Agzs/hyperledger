##fabric v0.6 介绍

## 1. bddtests包
测试包，含有大量 bdd 测试用例；

## 2. consensus包

## 3. core包
大部分核心实现代码都在本包下。其它包的代码封装上层接口，最终调用本包内代码；

## 4. devenv包
配置开发环境；

## 5. docs包
含有一些css、html文件，以及一些说明文档。
* users-guide.rst <br>
这个文档很重要，详细的介绍了fabric-ca的安装配置、使用。

## 6. events包
支持 event 框架

## 7. examples包
包括一些示例的 chaincode 代码；

## 8. flogging包
封装 go-logging，提供日志支持；

## 9. gotools包
golang 开发相关工具安装；

## 10. images包
含有一个fabric-ca-fvt目录，一些跟 Docker 镜像生成相关的配置和脚本。主要包括各个镜像的 Dockerfile.in 文件。这些文件是生成 Dockerfile 的模板。**不过还没看懂是干嘛用的？**

## 11. membersrvc包

## 12. metadata包
版本信息等；

## 13. peer包
peer 的入口和框架代码；

## 14. proposals包

## 15. protos包
包括各种协议和消息的 protobuf 定义文件；

## 16. pub包

## 17. scripts包
一些辅助脚本，多数为外部 Makefile 调用。

## 18. sdk包

## 19. tools包

## 20. vendor包
管理包依赖<br>
查找依赖包路径的解决方案如下：<br>
* 当前包下的vendor目录。 <br>
* 向上级目录查找，直到找到src下的vendor目录。 <br>
* 在GOPATH下面查找依赖包。 <br>
* 在GOROOT目录下查找 <br>

## 21. 其他文件
根目录下的一些文件，包括一些说明文档、安装需求说明、License 信息文件等
* Makefile文件 <br>
builds all targets and runs all tests/checks，执行测试、格式检查、安装依赖、生成镜像等操作。
* README.md文件 <br>
开发者帮助文档，项目的说明文件，包括一些有用的链接等。
* Docker 相关文件 <br>
**_.dockerignore：_** 生成 Docker 镜像时忽略一些目录，包括 .git 目录。
* git 相关文件 <br>
**_.gitattributes：_** git 代码管理时候的属性文件，带有不同类型文件中换行符的规则，默认都为 linux 格式，即 \n。
**_.gitignore：_** git 代码管理时候忽略的文件和目录，包括 build 和 bin 等中间生成路径。<br>
**_.gitreview：_** 使用 git review 时候的配置，带有项目的仓库地址信息。<br>
* travis 相关文件 <br>
**_.travis.yml：_** travis 配置文件，目前是使用 golang 1.6 编辑，运行了三种测试：unit-test、behave、node-sdk-unit-tests。
