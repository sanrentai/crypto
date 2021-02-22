# crypto  
go 加密封装  
简单易用高效  
----------   
# 非对称加密
ed25519 完成   
ecdsa todo  
rsa 完成 
----------  
# 对称加密
des 完成   
aes 完成  
tea 完成
xtea 完成
---------- 
# 摘要算法
md5 完成   
hmac todo    
sha1 完成   
sha256 完成   
sha512  完成   
----------
# 组合加密算法，自定义
rsa+des 完成  
算法概要  
加密：用des加密原文，用rsa公钥加密des密钥，用rsa私钥对原文签名  
解密：用rsa私钥解密得到des密钥，用des密钥解密得到原文，用rsa公钥对原文验签  
