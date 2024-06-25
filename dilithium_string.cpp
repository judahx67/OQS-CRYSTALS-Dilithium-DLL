#define _CRT_SECURE_NO_WARNINGS

#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <string>

#ifndef DLL_EXPORT
#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif
#endif

extern "C"
{
    DLL_EXPORT const char* keygen(const char* private_key_file);
    DLL_EXPORT const char* sign(const char* message, const char* private_key_file);
    DLL_EXPORT bool verify(const char* message, const char* signature_hex, const char* public_key_hex);
}

const char* keygen(const char* private_key_file);
const char* sign(const char* message, const char* private_key_file);
bool verify(const char* message, const char* signature_hex, const char* public_key_hex);

const char* keygen(const char* private_key_file)
{
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL)
    {
        printf("Failed to initialize Dilithium algorithm.\n");
        exit(1);
    }

    uint8_t* public_key = (uint8_t*)malloc(sig->length_public_key);
    uint8_t* private_key = (uint8_t*)malloc(sig->length_secret_key);
    if (public_key == NULL || private_key == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for keys\n");
        exit(1);
    }

    OQS_STATUS status = OQS_SIG_keypair(sig, public_key, private_key);
    if (status != OQS_SUCCESS)
    {
        fprintf(stderr, "OQS_SIG_keypair failed\n");
        exit(1);
    }

    // Save private key to file
    FILE* file = fopen(private_key_file, "wb");
    if (file == NULL)
    {
        fprintf(stderr, "Failed to open file: %s\n", private_key_file);
        exit(1);
    }
    fwrite(private_key, 1, sig->length_secret_key, file);
    fclose(file);

    // Convert public key to hexadecimal string
    char* public_key_hex = (char*)malloc(sig->length_public_key * 2 + 1);
    for (size_t i = 0; i < sig->length_public_key; i++)
    {
        sprintf(public_key_hex + 2 * i, "%02x", public_key[i]);
    }
    public_key_hex[sig->length_public_key * 2] = '\0';

    OQS_MEM_cleanse(private_key, sig->length_secret_key);
    printf("Keys generated and saved successfully.\n");
    free(public_key);
    free(private_key);
    OQS_SIG_free(sig);

    return public_key_hex;
}

const char* sign(const char* message, const char* private_key_file)
{
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL)
    {
        fprintf(stderr, "Failed to initialize Dilithium algorithm\n");
        exit(1);
    }

    // Read private key from file
    FILE* file = fopen(private_key_file, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Failed to open file: %s\n", private_key_file);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    size_t private_key_len = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t* private_key = (uint8_t*)malloc(private_key_len);
    if (private_key == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for private key\n");
        exit(1);
    }
    fread(private_key, 1, private_key_len, file);
    fclose(file);

    // Convert message to binary
    size_t message_len = strlen(message);
    uint8_t* message_bin = (uint8_t*)message;

    uint8_t* signature = (uint8_t*)malloc(sig->length_signature);
    size_t signature_len;

    OQS_STATUS status = OQS_SIG_sign(sig, signature, &signature_len, message_bin, message_len, private_key);
    if (status != OQS_SUCCESS)
    {
        fprintf(stderr, "OQS_SIG_sign failed\n");
        exit(1);
    }

    // Convert signature to hexadecimal string
    char* signature_hex = (char*)malloc(signature_len * 2 + 1);
    for (size_t i = 0; i < signature_len; i++)
    {
        sprintf(signature_hex + 2 * i, "%02x", signature[i]);
    }
    signature_hex[signature_len * 2] = '\0';

    OQS_MEM_cleanse(private_key, private_key_len);
    OQS_MEM_cleanse(signature, sig->length_signature);
    printf("Signature generated successfully.\n");
    free(private_key);
    free(signature);
    OQS_SIG_free(sig);

    return signature_hex;
}

bool verify(const char* message, const char* signature_hex, const char* public_key_hex)
{
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL)
    {
        fprintf(stderr, "Failed to initialize Dilithium algorithm\n");
        return false;
    }

    // Convert public key hex to binary
    size_t public_key_len = strlen(public_key_hex) / 2;
    uint8_t* public_key = (uint8_t*)malloc(public_key_len);
    for (size_t i = 0; i < public_key_len; i++)
    {
        sscanf(public_key_hex + 2 * i, "%2hhx", &public_key[i]);
    }

    // Convert signature hex to binary
    size_t signature_len = strlen(signature_hex) / 2;
    uint8_t* signature = (uint8_t*)malloc(signature_len);
    for (size_t i = 0; i < signature_len; i++)
    {
        sscanf(signature_hex + 2 * i, "%2hhx", &signature[i]);
    }

    // Convert message to binary
    size_t message_len = strlen(message);
    uint8_t* message_bin = (uint8_t*)message;

    OQS_STATUS status = OQS_SIG_verify(sig, message_bin, message_len, signature, signature_len, public_key);
    if (status == OQS_SUCCESS)
    {
        printf("Signature is valid.\n");
        OQS_MEM_cleanse(public_key, public_key_len);
        OQS_MEM_cleanse(signature, signature_len);
        free(public_key);
        free(signature);
        OQS_SIG_free(sig);
        return true;
    }
    else
    {
        printf("Signature is NOT valid.\n");
        OQS_MEM_cleanse(public_key, public_key_len);
        OQS_MEM_cleanse(signature, signature_len);
        free(public_key);
        free(signature);
        OQS_SIG_free(sig);
        return false;
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <mode> [options]\n", argv[0]);
        printf("Modes:\n");
        printf("  keygen <private_key_file>\n");
        printf("  sign <message> <private_key_file>\n");
        printf("  verify <message> <signature_hex> <public_key_hex>\n");
        return 1;
    }

    const char* mode = argv[1];

    if (strcmp(mode, "keygen") == 0)
    {
        if (argc != 3)
        {
            printf("Usage: %s keygen <private_key_file>\n", argv[0]);
            return 1;
        }
        const char* public_key_hex = keygen(argv[2]);
        printf("Public Key: %s\n", public_key_hex);
        free((void*)public_key_hex);  // Free the allocated public key hex string
    }
    else if (strcmp(mode, "sign") == 0)
    {
        if (argc != 4)
        {
            printf("Usage: %s sign <message> <private_key_file>\n", argv[0]);
            return 1;
        }
        const char* signature = sign(argv[2], argv[3]);
        printf("Signature: %s\n", signature);
        free((void*)signature);  // Free the allocated signature string
    }
    else if (strcmp(mode, "verify") == 0)
    {
        if (argc != 5)
        {
            printf("Usage: %s verify <message> <signature_hex> <public_key_hex>\n", argv[0]);
            return 1;
        }
        bool result = verify(argv[2], argv[3], argv[4]);
        printf("Verification result: %s\n", result ? "valid" : "invalid");
    }
    else
    {
        printf("Invalid mode\n");
        return 1;
    }

    return 0;
}
