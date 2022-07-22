#pragma once
#include <string>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/opensslconf.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
 
#define string std::string

using namespace std;

class SM2 {
private:
	/// <summary>
/// 通过公钥/私钥返回EVP_PKEY
/// </summary>
/// <param name="key">pem格式</param>
/// <param name="is_public"></param>
/// <param name="out_ecKey"></param>
/// <returns></returns>
	static bool CreateEVP_PKEY(unsigned char* key, int is_public, EVP_PKEY** out_ecKey);
public:	
	/// <summary>
	/// 根据私钥计算出公钥
	/// </summary>
	/// <param name="in_priKey"></param>
	/// <param name="out_pubKey"></param>
	/// <returns></returns>
	static bool PriKey2PubKey(string in_priKey, string& out_pubKey);
	/// <summary>
	/// 生成EC秘钥对 
	/// </summary>
	/// <param name="privKey">pem格式的私钥</param>
	/// <param name="pubKey">pem格式的公钥</param>
	/// <returns></returns>
	static int GenEcPairKey(string& out_priKey, string& out_pubKey);
 
	/// <summary>
	/// 签名 私钥加密 0成功
	/// </summary>
	/// <param name="in_buf">待签名数据</param>
	/// <param name="in_buflen">长度</param>
	/// <param name="out_sig">签名后数据</param>
	/// <param name="len_sig">签名数据长度</param>
	/// <param name="priKey">私钥pem格式</param>
	/// <returns></returns>
	static int Sign(string in_buf, int in_buflen, string& out_sig, int& len_sig, string priKey);
 
	/// <summary>
	/// 验签 公钥解密 0成功
	/// </summary>
	/// <param name="in_buf">待验签数据 明文</param>
	/// <param name="buflen">数据长度</param>
	/// <param name="sig">签名数据</param>
	/// <param name="siglen">签名数据长度</param>
	/// <param name="pubkey">公钥</param>
	/// <param name="keylen">公钥长度</param>
	/// <returns></returns>
	static int Verify(string in_buf, const int buflen, string sig, const int siglen, 
		string pubkey, const int keylen);
 
	/// <summary>
	/// 加密 公钥加密 0成功
	/// </summary>
	/// <param name="in_buf"></param>
	/// <param name="in_buflen"></param>
	/// <param name="out_encrypted"></param>
	/// <param name="len_encrypted"></param>
	/// <param name="pubKey">pem格式公钥</param>
	/// <returns></returns>
	static int Encrypt(string in_buf, int in_buflen, string& out_encrypted, int& len_encrypted, string pubKey);
 
	/// <summary>
	/// 解密 私钥解密 0成功
	/// </summary>
	/// <param name="in_buf"></param>
	/// <param name="in_buflen"></param>
	/// <param name="out_plaint"></param>
	/// <param name="len_plaint"></param>
	/// <param name="prikey">pem格式私钥</param>
	/// <returns></returns>
	static int Decrypt(string in_buf, int in_buflen, string& out_plaint, int& len_plaint, string prikey);
};
 

