#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sms4.h>
#include "e_os.h"


int main(int argc, char **argv)
{
	int i;
	sms4_key_t key_en, key_de;
	unsigned char buf[16], key_iv[16] = {0};
	
	if (argc < 2)
	{
		printf("Input Paramter Error...eg: %s [sms4_encry/sms4_cbc_encry]\n", argv[0]);
		return 0;
	}

	unsigned char user_key[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
//--------encry
	unsigned char basetext1[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
//--------cbc_encry	
	unsigned char iv[16] = {
		0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
		0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
	};
	unsigned char basetext2[16] = {
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	};


/*
	const unsigned char *in：	输入数据
	unsigned char *out：		输出数据
	const sms4_key_t *key：		加密秘钥
	void sms4_encrypt(const unsigned char *in, unsigned char *out, const sms4_key_t *key)
*/
	if (!strcmp(argv[1], "sms4_encry"))
	{
		/* test key scheduling */
		sms4_set_encrypt_key(&key_en, user_key);
		sms4_set_decrypt_key(&key_de, user_key);

		/* test encrypt once */
		sms4_encrypt(basetext1, buf, &key_en);
		printf("encrypt: \nin\t--->\tout\n");
		for (i = 0; i < 16; i++)
		{
			printf("%x\t--->\t", basetext1[i]);
			printf("%x", buf[i]);
			printf("\n");
		}

		printf("\n");
		
		sms4_encrypt(buf, basetext1, &key_de);
		printf("decrypt: \nin\t--->\tout\n");
		for (i = 0; i < 16; i++)
		{
			printf("%x\t--->\t", buf[i]);
			printf("%x", basetext1[i]);
			printf("\n");
		}
	}
/*
	const unsigned char *in：	输入数据
	unsigned char *out：		输出数据
	size_t len：				数据总长度
	const sms4_key_t *key：		加密秘钥
	unsigned char *iv：			初始向量	16 byte, 不可重入
	int enc：					加密或解密，1：加密   0：解密
	void sms4_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const sms4_key_t *key, unsigned char *iv, int enc)
*/
	else if (!strcmp(argv[1], "sms4_cbc_encry"))
	{
		/* test key scheduling */
		sms4_set_encrypt_key(&key_en, user_key);
		sms4_set_decrypt_key(&key_de, user_key);
		
		memcpy(key_iv, iv, 16);
		/* test encrypt once */
		sms4_cbc_encrypt(basetext2, buf, 16, &key_en, key_iv, 1);
		printf("cbc encrypt: \nin\t--->\tout\n");
		for (i = 0; i < 16; i++)
		{
			printf("%x\t--->\t", basetext2[i]);
			printf("%x", buf[i]);
			printf("\n");
		}

		printf("\n");
		
		memcpy(key_iv, iv, 16);
		sms4_cbc_encrypt(buf, basetext2, 16, &key_de, key_iv, 0);
		printf("cbc decrypt: \nin\t--->\tout\n");
		for (i = 0; i < 16; i++)
		{
			printf("%x\t--->\t", buf[i]);
			printf("%x", basetext2[i]);
			printf("\n");
		}
	}
	
	else
	{
		printf("Input Paramter Error...eg: %s [sms4_encry/sms4_cbc_encry]\n", argv[0]);
	}
	

	return 0;
}










































