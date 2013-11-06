#include <new>
#include <stdexcept>
#include <cstring>//for memset

#include "ntstatus.h"
#include "AES_ECB.h"

AES_ECB::AES_ECB():m_pbExpDecKey(nullptr), m_pbExpEncKey(nullptr),m_szbKey(NULL),m_pfuncDecBlock(nullptr),m_pfuncEncBlock(nullptr),m_pfuncExpKey(nullptr)
{
	
}
AES_ECB::~AES_ECB()
{
	if(destroyKey())
	{
		//throw expection
	}
}
AES_ECB::AES_ECB(const unsigned char *pbKey, const size_t &szbKey):m_pbExpDecKey(nullptr), m_pbExpEncKey(nullptr),m_szbKey(NULL),m_pfuncDecBlock(nullptr),m_pfuncEncBlock(nullptr),m_pfuncExpKey(nullptr)
{
	if(setKey(pbKey,szbKey));//throw exception
}
unsigned int AES_ECB::destroyKey()
{
	if(m_pbExpEncKey && m_pbExpDecKey && m_szbKey)
	{
		switch(m_szbKey)
		{
		case(16):
			::memset(m_pbExpEncKey,0,11*16);
			::memset(m_pbExpDecKey,0,11*16);
			break;
		case(24):
		case(32):
		default:
			//RETURN expection
			break;
		}
		delete[] m_pbExpEncKey;
		delete[] m_pbExpDecKey;
	}
	m_szbKey=0;
	m_pfuncDecBlock=nullptr;
	m_pfuncEncBlock=nullptr;
	m_pfuncExpKey=nullptr;
	m_pbExpEncKey=nullptr;
	m_pbExpDecKey=nullptr;
	return 0;
}
unsigned int AES_ECB::setKey(const unsigned char *pbKey, const size_t &szbKey)
{
	
	if(this->destroyKey()){return 1;/*throw exception*/}
	switch(szbKey)
	{
	case(16):
		{
			//if 128 bit AES
		m_pbExpEncKey = new (std::nothrow) unsigned char[11*16];
		m_pbExpDecKey = new (std::nothrow) unsigned char[11*16];
		m_szbKey=szbKey;
	
		//Set functions
		m_pfuncExpKey=&AES_ECB::expKey128;
		m_pfuncDecBlock=&AES_ECB::decryptBlock128;
		m_pfuncEncBlock=&AES_ECB::encryptBlock128;
			break;
		}
	case(24):
		{
			//if 192 bit AES
		m_pbExpEncKey = new (std::nothrow) unsigned char[13*16];
		m_pbExpDecKey = new (std::nothrow) unsigned char[13*16];
		m_szbKey=szbKey;
			
		//Set functions
		m_pfuncExpKey=&AES_ECB::expKey192;
		m_pfuncDecBlock=&AES_ECB::decryptBlock192;
		 m_pfuncEncBlock=&AES_ECB::encryptBlock192;
		break;
		}
	case(32):
		{
			break;
		}
	default:
		return 1;//return exception!!!
		break;
	}
	if(!m_pbExpDecKey && !m_pbExpEncKey)
	{//no memmory
		m_szbKey=0;
		return 1;//return exception!!!
	}
	if((this->*m_pfuncExpKey)(pbKey))
	{
		m_szbKey=0;
		return 1;//return exception(can exp key)!!!
	}
	return 0;
}
unsigned int AES_ECB::expKey128(const unsigned char *pbKey)
{
	if(m_szbKey!=16)
	{
		return 1;
	}
	__asm{
		mov ebx, pbKey;
		movups xmm1,[ebx];
		movups xmm4,xmm1;

		mov eax,[this] ;
       	mov ebx,[eax+m_pbExpDecKey];
		add ebx,160;		
		mov eax,[eax+m_pbExpEncKey];
		
		movups [eax], xmm1;                  ;cipher Key
		add eax,0x00000010;
		movups [ebx], xmm1;
		sub ebx,0x00000010;

		aeskeygenassist xmm2, xmm1, 0x1     ;  1 
		call L_key_expansion_128;
		
		aeskeygenassist xmm2, xmm1, 0x2     ;  2 
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x4     ;  3 
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x8     ;  4 
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x10     ;  5 
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x20     ; 6 
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x40     // 7
		call L_key_expansion_128;
		
		aeskeygenassist xmm2, xmm1, 0x80     // 8
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x1b;	  //9
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x36;     //  10 
		call L_key_expansion_128; 
		add ebx,0x00000010;
		movups [ebx], xmm1;
		
		jmp end;
L_key_expansion_128: 
	   
	   pshufd xmm2, xmm2, 0xff;
	   movups xmm3, xmm1;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x00;

	   pshufd xmm3, xmm3, 0x39;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x14;

	   pshufd xmm3, xmm3, 0x38;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0xA4;

	   pshufd xmm3, xmm3, 0x34;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   movups [eax], xmm2;
	   movups xmm1, xmm2;
	   add eax,0x00000010;
	   
	   aesimc xmm3, xmm1;
	   movups [ebx], xmm3;
	   sub ebx,0x00000010;	   
	   ret ;
end:
	}
	return 0;
}
unsigned int AES_ECB::expKey192(const unsigned char *pbKey)
{
	if(m_szbKey!=24)
	{
		return 1;
	}
	__asm{
		mov edx, pbKey;
		movups xmm1,[edx];
		
		mov eax,[this] ;
       	mov eax,[eax+m_pbExpEncKey];
		//lea eax,k;


		movups [eax], xmm1;                  ;cipher Key
		movups xmm4, xmm1;

		add eax,0x00000008;
		add edx,0x00000008;
		
		movups xmm1,[edx];
		movups [eax], xmm1;
		add eax,0x00000010;

		
		aeskeygenassist xmm2, xmm1, 0x1     ;  1 
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x2     ;  2 
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x4     ;  3
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x8     ;  4
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x10     ;  5
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x20     ;  6
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x40     ;  7
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x80     ;  8
		call L_key_expansion_192_last;

		call L_key_expansion_192_for_decrypt;


		jmp end;
	
L_key_expansion_192:

	   pshufd xmm2, xmm2, 0xff; 
	   movups xmm3, xmm4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x00;
	  

	   pshufd xmm3, xmm3, 0x39;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x14;

	   pshufd xmm3, xmm3, 0x38;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0xA4;

	   pshufd xmm3, xmm3, 0x34;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   movups [eax], xmm2;
	   add eax,0x00000010;

	   pshufd xmm2, xmm2, 0xff;
	   pshufd xmm1, xmm1, 0xfe;
	   pxor xmm2,xmm1;

	   pshufd xmm2, xmm2, 0x00;
	   pslldq xmm1,0x4;
	   pshufd xmm1, xmm1, 0x08;
	   pxor xmm2,xmm1;

	   movups [eax], xmm2;
	   add eax,0x00000008;
	   movups xmm1,[eax-16];
	   movups xmm4,[eax-24];

	   ret;
L_key_expansion_192_last:

	   pshufd xmm2, xmm2, 0xff; 
	   movups xmm3, xmm4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x00;
	  

	   pshufd xmm3, xmm3, 0x39;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x14;

	   pshufd xmm3, xmm3, 0x38;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0xA4;

	   pshufd xmm3, xmm3, 0x34;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   movups [eax], xmm2;
	   ret;
L_key_expansion_192_for_decrypt:
	   	mov eax,[this] ;
       	mov ebx,[eax+m_pbExpDecKey];
		add ebx,192;
		mov eax,[eax+m_pbExpEncKey];

		movups xmm1,[eax];
		movups [ebx],xmm1;

		add eax,16;                  //1
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //2
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //3
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //4
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //5
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //6
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //7
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //8
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //9
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //10
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //11
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //12
		sub ebx,16;

		movups xmm1,[eax];
		//aesimc xmm1, xmm1;
		movups [ebx],xmm1;
		ret;

		
end:
		}
		return 0;
	
}

unsigned int AES_ECB::encryptBlock128(const unsigned char *pbInput,unsigned char *pbOutput)
{
	if(!m_pbExpEncKey){return 1;/*exception*/}
	__asm
	{
		mov ebx,pbInput;
		movups xmm1,[ebx];

		mov eax,[this] ;
		mov eax,[eax+m_pbExpEncKey];
		movups xmm2,[eax];

		pxor xmm1,xmm2;
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 1 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 2 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 3 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 4 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 5
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 6 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 7 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 8 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 9
        add eax,0x00000010;
		movups xmm2,[eax];
		aesenclast xmm1, xmm2 ; Round 10 
		mov ebx,pbOutput;
		movups [ebx],xmm1;
}
	return 0;
}
unsigned int AES_ECB::encryptBlock192(const unsigned char *pbInput,unsigned char *pbOutput)
{

	if(!m_pbExpEncKey){return 1;/*exception*/}
	__asm
	{
		mov ebx,pbInput;
		movups xmm1,[ebx];

		mov eax,[this] ;
		mov eax,[eax+m_pbExpEncKey];
		movups xmm2,[eax];

		pxor xmm1,xmm2;
		add eax,0x00000010;
		movups xmm2,[eax];
		
		aesenc xmm1, xmm2 ; Round 1 
		add eax,0x00000010;
		movups xmm2,[eax];
		

		aesenc xmm1, xmm2 ; Round 2 
		add eax,0x00000010;
		movups xmm2,[eax];
		
		aesenc xmm1, xmm2 ; Round 3 
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 4 
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 5
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 6 
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 7 
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 8 
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 9
        add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 10 
	    add eax,0x00000010;
		movups xmm2,[eax];


		aesenc xmm1, xmm2 ; Round 11 
	    add eax,0x00000010;
		movups xmm2,[eax];
		
		
		aesenclast xmm1, xmm2 ; Round 12 
	    add eax,0x00000010;
	
		mov ebx,pbOutput;
		movups [ebx],xmm1;
}
	return 0;
}
unsigned int AES_ECB::encrypt(const unsigned char *pbInput, const size_t szbInput, unsigned char *pbOutput, const size_t szbOutput, size_t *szbResult)
{
	if(!m_szbKey){ return 1;/*exception*/}
	unsigned char bPadBlock[16];
	unsigned int iPadind=16-(szbInput%16);
	size_t cBlock=szbInput/16;
	*szbResult=0;
	if((szbResult && !szbOutput))*szbResult=(cBlock+(iPadind/16))*16;//если запршивается тьребуемый размер
	
	if(!szbOutput)return 0;//если запршивается тьребуемый размер

	if(szbOutput<((iPadind/16)+cBlock)*16)//если нету памяти для расшифровки
	{
		*szbResult=0;
		return 1;
	}

	for(unsigned int i=0;i<szbInput%16;++i)
	{
		bPadBlock[i]=pbInput[(cBlock*16)+i];
	}
	
	for(unsigned int i=szbInput%16;i<16;++i)
	{
		bPadBlock[i]=iPadind;
	}
	
	for(unsigned int i=0;i<cBlock;++i)
	{
		(this->*m_pfuncEncBlock)(pbInput+(i*16),pbOutput+(i*16));
		(*szbResult)+=16;
	}
	(this->*m_pfuncEncBlock)(bPadBlock,pbOutput+(cBlock*16));
	(*szbResult)+=16;
	::memset(bPadBlock,0,16);
	return 0;
}
unsigned int AES_ECB::decrypt(const unsigned char *pbInput, const size_t szbInput, unsigned char *pbOutput, const size_t szbOutput, size_t *szbResult)
{
	*szbResult=0;
	if(!m_szbKey){ return 1;/*exception*/}
	if(szbInput%16)return 1;
	unsigned char bPadBlock[16];
	(this->*m_pfuncDecBlock)(pbInput+(((szbInput/16)-1)*16),bPadBlock);
	if(bPadBlock[15]>16){return 1;::memset(bPadBlock,0,16);}
	if(szbResult && !szbOutput) *szbResult=szbInput-bPadBlock[15];
	
	if(szbOutput<szbInput-bPadBlock[15]){return 1;::memset(bPadBlock,0,16);}

	for(unsigned int i=0; i< (szbInput/16)-1;++i)
	{
		(this->*m_pfuncDecBlock)(pbInput+(i*16),pbOutput+(i*16));
		(*szbResult)+=16;
	}
	for(unsigned int i=0;i<16-bPadBlock[15];++i)
	{
		*(pbOutput+(((szbInput/16)-1)*16)+i)=bPadBlock[i];
		(*szbResult)++;
	}
	::memset(bPadBlock,0,16);
	return 0;
}
unsigned int AES_ECB::decryptBlock128(const unsigned char *pbInput,unsigned char *pbOutput)
{
	__asm{
		mov eax,[this] ;
		mov eax,[eax+m_pbExpDecKey];
		
		movups xmm2,[eax];

		mov ebx,pbInput;
		movups xmm1,[ebx];
		pxor xmm1, xmm2 ; First xor


		add eax,0x00000010;
		movups xmm2,[eax]; 
		aesdec xmm1, xmm2 ; Round 1 


		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 2 
		

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 3

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 4 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 5

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 6

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 7

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 8 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 9 


		add eax,0x00000010;
		movups xmm2,[eax];
		aesdeclast xmm1, xmm2 ; Round 10 
	    mov ebx,pbOutput;
		movups [ebx],xmm1;

	}
	return 0;
}
unsigned int AES_ECB::decryptBlock192(const unsigned char *pbInput,unsigned char *pbOutput)
{
			unsigned char m[16];
	__asm{
		mov eax,[this] ;
		mov eax,[eax+m_pbExpDecKey];
		
		movups xmm2,[eax];

		mov ebx,pbInput;
		movups xmm1,[ebx];
		pxor xmm1, xmm2 ; First xor

		lea ebx,m;
		movups [ebx],xmm1;


		add eax,0x00000010;
		movups xmm2,[eax]; 
		aesdec xmm1, xmm2 ; Round 1 


		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 2 
		

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 3

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 4 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 5

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 6

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 7

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 8 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 9 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 10 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 11 
        
		add eax,0x00000010;
		movups xmm2,[eax];
		aesdeclast xmm1, xmm2 ; Round 12 
	    mov ebx,pbOutput;
//		lea ebx,m;
		movups [ebx],xmm1;

	}
	return 0;
}
int main()
{
	    unsigned char key[16]={0x2b, 0x7e,  0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
		 0xab, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3c};

   unsigned char key1[32]={0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   //unsigned char m[16]={0x32, 0x43,  0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
  unsigned char key24[24]={0x00, 0x01,  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 , 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
  unsigned char m[16]={0x00, 0x11,  0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  //8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b
  /* unsigned char key24[]={0x8e, 0x73, 0xb0, 0xf7, 
							0xda, 0x0e, 0x64, 0x52, 
							0xc8, 0x10, 0xf3, 0x2b, 
							0x80, 0x90, 0x79, 0xe5, 
							0x62, 0xf8, 0xea, 0xd2,
							0x52, 0x2c, 0x6b, 0x7b };*/
	AES_ECB aes;
	size_t res;
	aes.setKey(key24,24);
	aes.encrypt(m,16,key1,32,&res);
	aes.decrypt(key1,res,key1,16,&res);
	
}