/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
//#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[100] = {0,};
	char ciphertext[100] = {0,};
	int len = 100;
	char encryptedkey[1] = {0};
	char decryptedkey[1] = {0};
   
   	FILE *file;

   	res = TEEC_InitializeContext(NULL, &ctx);
   
   	res = TEEC_OpenSession(&ctx, &sess, &uuid,
                TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
   
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;    

	if(!strcmp(argv[1], "-e")){
	printf("========================Encryption========================\n");
	file = fopen(argv[2], "r");

	if(file == NULL){

		perror("File not found");

		return 0;

	}

	fgets(plaintext, sizeof(plaintext), file);
	fclose(file);
	printf("plaintext: %s\n", plaintext);  

	//generate randomkey
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);
      
	//encrypt plaintext using randomkey
	memcpy(op.params[0].tmpref.buffer, plaintext, len);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
      
	//save ciphertext
	memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	printf("ciphertext: %s\n", ciphertext);
      
	//make ciphertext.txt, save ciphertext to txt
	file = fopen("ciphertext.txt", "w");
	fputs(ciphertext, file);
	fclose(file);

	//encrypt randomkey using root key (randomkey -> encryptedkey)
	memcpy(op.params[0].tmpref.buffer, encryptedkey, 1);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);

	//save encryptedkey to txt
	memcpy(encryptedkey, op.params[0].tmpref.buffer, 1);
	printf("encryptedkey : %d\n", encryptedkey[0]);
	file = fopen("encryptedKey.txt", "w");
	fputc(encryptedkey[0], file);
 	fclose(file);

	}
	else if(!strcmp(argv[1], "-d")){ 
	printf("========================Decryption========================\n");

	file = fopen(argv[2], "r");

	if(file == NULL){

		perror("File not found");

		return 0;

	}

	fgets(ciphertext, sizeof(ciphertext), file);
	fclose(file);

	file = fopen(argv[3], "r");
	if(file == NULL){

		perror("File not found");

		return 0;

	}
	decryptedkey[0] = fgetc(file);      
 	printf("ciphertext: %s\n", ciphertext);
	fclose(file);
      
	//decrypt encryptedkey using root key (encryptedkey > randomkey)
	memcpy(op.params[0].tmpref.buffer, decryptedkey, 1);        
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op, &err_origin);

	//decrypt ciphertext
	memcpy(op.params[0].tmpref.buffer, ciphertext, len);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

	//save plaintext
	memcpy(plaintext, op.params[0].tmpref.buffer, len);
	printf("plaintext: %s\n", plaintext);
      
	//make decrypttext.txt
	file = fopen("decrypttext.txt", "w");
	fputs(plaintext, file);
	fclose(file);


	}
	else{

		perror("retry\n");
   
		return 0;
	}

 
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;

}
