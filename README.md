# EasyOpenSSL

EasyOpenSSL 库封装了常用的 OpenSSL 代码，使基于 OpenSSL 开发更加方便。

AES-CBC 加密后的字符串可能出现 null char(char* 的终止符)，使用十六进制
编码时，加密没问题，解密因为终止符的问题，会导致解密错误。
所以，AES-CBC 使用 Base64 编码。

## 生成文档
运行命令 `doxygen Doxyfile` ，生成的文档 `html` 目录中。