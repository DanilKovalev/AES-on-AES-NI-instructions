#ifndef AES_ECB_H_INCLUDED
#define AES_ECB_H_INCLUDED
/**
 * \file AES.h
 * @brief file contains the declaration of the class AES_ECB  
 * \author ostikawm
 * \date      2013
 *  
 */
/**
 * @defgroup group_AES_ECB   AES ECB mode
 * 
 * @brief ???
 *
 * @full ???
 * @todo do:)
 * @todo translate
*/










/**
* \class AES_ECB AES_ECB.h "AES_ECB.h"
* @brief implements AES in ECB mode 
* \author  ostikawm
* \date 2013
* \ingroup group_AES_ECB
* \version 0.1
*
* @todo translate
* 
*/
class AES_ECB
{
public:
	/// @name constructors/
	/// @{

	/**
	* @brief Default constructor
	* @warning no set the Key. Must be call AES_ECB::setKey function
	*/
	AES_ECB();

	/**
	* @brief constructor
	* @param[in] pbKey
	* Pointer to a buffer that contains the key
	* @param[in] szbKey
	* The size, in bytes, of the pbKey buffer.
	* @throw std::bad_alloc if no memmory
	* @throw std::invalid_argument if key size is not 16, 24 or 32
	*/
	AES_ECB(const unsigned char *pbKey, const size_t &szbKey) throw(std::bad_alloc, std::invalid_argument);
	
	/**
	* @brief destructor
	* @throw std::bad_exception 
	* @pre call AES_ECB::destroyKey()
	*/
	~AES_ECB();
	///@}
	
	/**
	* @brief set Key for encrypt and decrypt
	* @param[in] pbKey
	* Pointer to a buffer that contains the key
	* @param[in] szbKey
	* The size, in bytes, of the pbKey buffer.
	* @return error code(ntstatus)
	*/
	unsigned int setKey(const unsigned char *pbKey, const size_t &szbKey);

	/**
	* @brief destroy key and free memmore
	* @return error code(ntstatus)
	*/
	unsigned int destroyKey();

	/**
	* @brief encrypt data
	* @full ???
	* @param[in] pbInput
	* The address of a buffer that contains the plaintext to be encrypted. 
	* @param[in] szbInput
	* The number of bytes in the pbInput buffer to encrypt.
	* @param[out] pbOutput
	* The address of the buffer that receives the ciphertext produced by this function.
	* @param[in] szbOutput
	* The size, in bytes, of the pbOutput buffer. This parameter is ignored if the pbOutput parameter is \b NULL.
	* @param[out] szbResult
	* A pointer to variable that receives the number of bytes copied to the pbOutput buffer. If pbOutput is \b NULL, this receives the size, in bytes, required for the ciphertext.
	* @return error code(ntstatus)
	* @todo full description
	* @bug  not change szbResult
	* @bug  no result if szbOutput=0
	*/
	unsigned int encrypt(const unsigned char *pbInput, const size_t szbInput, unsigned char *pbOutput, const size_t szbOutput, size_t *szbResult);
	
		/**
	* @brief decrypt data
	* @full ???
	* @param[in] pbInput
	* The address of a buffer that contains the ciphertext to be decrypted. 
	* @param[in] szbInput
	* The number of bytes in the pbInput buffer to decrypt.
	* @param[out] pbOutput
	* The address of the buffer that receives the plaintext produced by this function.
	* @param[in] szbOutput
	* The size, in bytes, of the pbOutput buffer. This parameter is ignored if the pbOutput parameter is \b NULL.
	* @param[out] szbResult
	* A pointer to variable that receives the number of bytes copied to the pbOutput buffer. If pbOutput is \b NULL, this receives the size, in bytes, required for the plaintext.
	* @return error code(ntstatus)
	* @todo full description
	* @bug  not change szbResult
	* @bug  no result if szbOutput=0
	*/
	unsigned int decrypt(const unsigned char *pbInput, const size_t szbInput, unsigned char *pbOutput, const size_t szbOutput, size_t *szbResult);


protected:


private:
	AES_ECB(const AES_ECB&);
	const AES_ECB & operator= (const AES_ECB&);
	unsigned int expKey128(const unsigned char *pbKey);
	unsigned int expKey192(const unsigned char *pbKey);
	unsigned int expKey256();
	unsigned int encryptBlock128(const unsigned char *pbInput,unsigned char *pbOutput);
	unsigned int encryptBlock192(const unsigned char *pbInput,unsigned char *pbOutput);
	unsigned int encryptBlock256();



	unsigned int decryptBlock128(const unsigned char *pbInput,unsigned char *pbOutput);
	unsigned int decryptBlock192(const unsigned char *pbInput,unsigned char *pbOutput);
	unsigned int decryptBlock256();

	unsigned char *m_pbExpEncKey;
	unsigned char *m_pbExpDecKey;
	unsigned int (__thiscall AES_ECB::*m_pfuncExpKey)(const unsigned char *);
	unsigned int (__thiscall AES_ECB::*m_pfuncEncBlock)(const unsigned char *,unsigned char *);
	unsigned int (__thiscall AES_ECB::*m_pfuncDecBlock)(const unsigned char *,unsigned char *);
	size_t m_szbKey;

};
#endif//AES_ECB_H_INCLUDED