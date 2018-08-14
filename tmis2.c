#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "tmis_enc_denc.h"
#include "/usr/local/include/pbc/pbc.h"  //必须包含头文件pbc.h
#include "/usr/local/include/pbc/pbc_test.h"


#if 0  // 注册事件

char secret_key[1024] = "[1431701601476568613993916354570581999234296492200903722689435064403093647543786410908775082711468637043556899660242354405958838182001143332963964057164995, 2090155367049341967001403718508984758041491186470976194749112114432660174858545929700501744055058603817941671083836419094294404012587185432039026958345540]";
char public_key[1024] = "[8779246804865256595845410635551148521227644044548861627285453536743878386166265446937141101008408588690674901331738586548621281816777149434943936565852561, 5462710688655103662240594520449922001027729122965123487994410536107298056563228514615559984791707466524546778752823276552092115399599325705605166751646997]";
char str_id[100] = "123";
char str_pw[100] = "456";
unsigned char bytes_HPWi[100]={0};


void register_client_do1();
void register_server_do();


// 注册阶段
void tmis_register()
{
	register_client_do1();
	register_server_do();

}

void register_server_do()
{
////  1. 生成随机数m，这里要生成一个随机数种子，否则的话，每一次的随机数都是相同的	
	mpz_t m;
	mpz_init(m);
// void mpz_urandomb (mpz_t rop, gmp_randstate_t state, mp_bitcnt_t n)
//****** Generate a uniformly distributed random integer in the range 0 to 2n − 1, inclusive
// void gmp_randinit_mt (gmp randstate t state)
//***** Initialize state
// void gmp_randseed_ui (gmp randstate t state, unsigned long int seed)
	unsigned long int seed = (unsigned long int)time(NULL);
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	gmp_randseed_ui(state,seed);
	mpz_urandomb(m,state,100); 	// 产生小于2^100的随机数

	char str_m[1024]={0};  
// char * mpz_get_str (char *str, int base, mpz_t op)	
	mpz_get_str (str_m, -16,m);  	// 将随机数m转化为16进制字符串，保存
	printf("m = %s\n",str_m);
	printf("m_len = %ld\n",strlen(str_m));

//// 2. 计算Ai
	int len1 = strlen(str_id); 			
	int len2 = strlen(secret_key); 		
	char *CONSTR1 =(char *)malloc(sizeof(char) * (len1+len2)+1); // ID || KS
	memset(CONSTR1,0,len1+len2+1);
	strncpy(CONSTR1,str_id,len1);
	strncpy(CONSTR1+len1,secret_key,len2);
	printf("CONSTR1 = %s\n",CONSTR1);
	unsigned char bytes_Ai[100]={0};
	sha1((unsigned char *)CONSTR1,bytes_Ai);

//// 3. 计算	Bi
// 	IDi || HPWi
	len1 = strlen(str_id);
	len2 = strlen((char *)bytes_HPWi);
	char *CONSTR2 =(char *)malloc(sizeof(char) * (len1+len2)+1); 
	memset(CONSTR2,0,len1+len2+1);
	memcpy(CONSTR2,str_id,len1);
	memcpy(CONSTR2+len1,bytes_HPWi,len2);

	unsigned char bytes_temp1[1024]={0};
	sha1((unsigned char*)CONSTR2,bytes_temp1);   // h( IDi || HPWi  )
	// 转化成mpz_t类型，然后mod
	char str_temp1[1024]={0};
	bytes2hex(bytes_temp1,strlen((char *)bytes_temp1),str_temp1);
	printf("str_temp1 = %s\n",str_temp1);
	mpz_t mpz_temp1;
	mpz_init_set_str(mpz_temp1,str_temp1,16);
	gmp_printf("mpz_temp1 = %Zd\n",mpz_temp1);

	mpz_t mpz_res;
	mpz_init(mpz_res);
//	void mpz_mod (mpz t r, mpz t n, mpz t d) [Function]
//**** Set r to n mod d.
	mpz_mod(mpz_res,mpz_temp1,m);
	gmp_printf("mpz_res = %Zd\n",mpz_res);  // h( IDi || HPWi  ) mod m
	// 将mpz_res转化为字符串
//  char * mpz_get_str (char *str, int base, mpz t op);	
	char str_res[1024]={0};
	mpz_get_str(str_res,-16,mpz_res);
	printf("str_res = %s\n",str_res);
	unsigned char bytes_Bi[100]={0};
	sha1((unsigned char *)str_res,bytes_Bi);   //  h ( h( IDi || HPWi  ) mod m )
	
//// 4. 计算Ci
//  unsigned char bytes_Ai[100]={0};    unsigned char bytes_HPWi[100]={0};  unsigned char bytes_Bi[100]={0};
/// 先将字节流数组转化为mpz_t,然后异或操作
	mpz_t mpz_Ai,mpz_HPWi,mpz_Bi;
	char str_temp2[1024]={0};
	bytes2hex(bytes_Ai,strlen((char *)bytes_Ai),str_temp2);
	mpz_init_set_str(mpz_Ai,str_temp2,16);  // mpz_Ai
	memset(str_temp2,0,sizeof(str_temp2));
	bytes2hex(bytes_HPWi,strlen((char *)bytes_HPWi),str_temp2);
	mpz_init_set_str(mpz_HPWi,str_temp2,16);  // mpz_HPWi
	memset(str_temp2,0,sizeof(str_temp2));
	bytes2hex(bytes_Bi,strlen((char *)bytes_Bi),str_temp2);
	printf("str_Bi = %s\n",str_temp2);
	mpz_init_set_str(mpz_Bi,str_temp2,16);  // mpz_Bi
//	void mpz_xor (mpz t rop, mpz t op1, mpz t op2)
//**** Set rop to op1 bitwise exclusive-or op2.
	mpz_t mpz_Ci;
	mpz_init(mpz_Ci);
	mpz_xor(mpz_Ci,mpz_Ai,mpz_HPWi);
	mpz_xor(mpz_Ci,mpz_Ci,mpz_Bi);
	char str_Ci[1024]={0};
	mpz_get_str(str_Ci,-16,mpz_Ci);
	printf("str_Ci = %s\n",str_Ci);

	



//// 清理使用到的变量
	mpz_clear(m);
	mpz_clear(mpz_temp1);
	mpz_clear(mpz_res);
	mpz_clear(mpz_Ai);
	mpz_clear(mpz_Bi);
	mpz_clear(mpz_HPWi);
	mpz_clear(mpz_Ci);
	free(CONSTR1);
	free(CONSTR2);

}


void register_client_do1()
{
////  1. 生成随机数b，这里要生成一个随机数种子，否则的话，每一次的随机数都是相同的	
	mpz_t b;
	mpz_init(b);
// void mpz_urandomb (mpz_t rop, gmp_randstate_t state, mp_bitcnt_t n)
//****** Generate a uniformly distributed random integer in the range 0 to 2n − 1, inclusive
// void gmp_randinit_mt (gmp randstate t state)
//***** Initialize state
// void gmp_randseed_ui (gmp randstate t state, unsigned long int seed)
	unsigned long int seed = (unsigned long int)time(NULL);
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	gmp_randseed_ui(state,seed);
	mpz_urandomb(b,state,100); // 产生小于2^100的随机数

	char str_b[1024]={0};  
// char * mpz_get_str (char *str, int base, mpz_t op)	
	mpz_get_str (str_b, -16, b);  // 将随机数b转化为16进制字符串，保存
	printf("B = %s\n",str_b);
	printf("B_len = %ld\n",strlen(str_b));
	

//// 2.计算HPWi
	// 连接字符串 PWi || b
	int len1 = strlen(str_pw);
	int len2 = strlen(str_b);
	char *CONSTR =(char *)malloc(sizeof(char) * (len1+len2)+1);
	memset(CONSTR,0,len1+len2+1);
	strncpy(CONSTR,str_pw,len1);
	strncpy(CONSTR+len1,str_b,len2);
	printf("CONSTR = %s\n",CONSTR);

//	unsigned char bytes_HPWi[100]={0};
	sha1((unsigned char *)CONSTR, bytes_HPWi); 


//// final：清理使用到的变量，mpz内部使用指针实现的，避免内存泄露
	mpz_clear(b);
	free(CONSTR);


	// ===== 发送信息给注册服务器(使用全区变量代替发送过来)
	printf("注册服务：客户端生成参数完成。。。\n");


}

void client_do2()
{
	// 存储相关的信息到文件中，这里先保存字符流试试
}


int main()
{
	tmis_register();

	return 0;
}



#endif




