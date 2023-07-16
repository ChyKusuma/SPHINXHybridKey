/*
 *  Copyright (c) (2023) SPHINX_ORG
 *  Authors:
 *    - (C kusuma) <thekoesoemo@gmail.com>
 *      GitHub: (https://github.com/chykusuma)
 *  Contributors:
 *    - (Contributor 1) <email1@example.com>
 *      Github: (https://github.com/yourgit)
 *    - (Contributor 2) <email2@example.com>
 *      Github: (https://github.com/yourgit)
 */


/////////////////////////////////////////////////////////////////////////////////////////////////////////
// The provided code is implementation of a hybrid key exchange scheme using the SPHINX cryptographic library.

// performX25519KeyExchange:
  // This function performs the X25519 key exchange algorithm.
  // It takes a private key, public key, and shared key as input.
  // The X25519 key exchange algorithm calculates a shared secret using the private key and the other party's public key.

// HybridKeypair structure:
  // This structure holds the keypairs used in the hybrid encryption scheme.
  // It contains:
     // merged_key field: It holds the keypair for the Kyber768 key encapsulation mechanism (KEM).
     // kyber_public_key: The public key for Kyber768 KEM.
     // kyber_private_key: The private key for Kyber768 KEM.
     // x25519_key field: It holds the keypair for the X25519 key exchange algorithm.
     // first: The private key for X25519.    
     // second: The public key for X25519.
     // public_key_pke field: It is a vector to store the public key used in public key encryption (PKE).
     // secret_key_pke field: It is a vector to store the secret key used in PKE.
     // prng field: It represents a pseudorandom number generator used for key generation.

// generate_hybrid_keypair:
  // This function generates a hybrid keypair.
  // It creates an instance of HybridKeypair.
  // It generates a Kyber768 keypair for the KEM.
  // It generates an X25519 keypair.
  // It resizes the PKE keypair vectors.
  // It generates a PKE keypair.
  // Finally, it returns the generated hybrid keypair.

// deriveMasterKeyAndChainCode:
  // This function derives the master private key and chain code from a given seed.
  // It takes a seed string as input.
  // It derives the master private key using HMAC-SHA512 with "Sphinx seed" as the key.
  // It derives the chain code using HMAC-SHA512 with "Sphinx chain code" as the key.
  // It returns a pair of strings containing the master private key and chain code.

// deriveKeyHMAC:
  // This function derives a key using HMAC-SHA512.
  // It takes a key and data string as input.
  // It calculates the HMAC-SHA512 hash of the data using the provided key.
  // It returns the derived key as a string.

// performX25519KeyExchange (repeated declaration):
  // This function performs the X25519 key exchange algorithm (same as explained earlier).

// generateRandomNonce:
  // This function generates a random nonce.
  // It calls a function in the "UTILS.HPP" file to generate the random nonce.
  // It returns the generated nonce as a string.

// deriveKeyHKDF:
  // This function derives a key using HKDF (HMAC-based Key Derivation Function).
  // It takes input key material, salt, info, and key length as input.
  // It derives the key using HKDF with the provided parameters.
  // It compresses the derived key using the "SPHINXHash" or "SPHINX_256" hash function.
  // It returns the compressed derived key as a string.

// hash:
  // This function calculates the SWIFFTX-256 hash of a string.
  // It takes an input string and calls the SPHINXHash::SPHINX_256 function to calculate the hash.
  // It returns the calculated hash as a string.

// generateKeyPair:
  // This function generates a key pair.
  // It generates a private key by generating a random nonce.
  // It calculates the hash of the private key to obtain the public key.
  // It returns a pair of strings containing the private and public keys.

// generateAddress:
  // This function generates an address from a public key.
  // It takes a public key as input.
  // It calculates the hash of the public key.
  // It returns the first 20 characters of the hash as the address.

// requestDigitalSignature:
  // This function requests a digital signature for the given data using the provided hybrid keypair.
  // It calls the verify_data function from the "sign.hpp" file, passing the data and secret key from the hybrid keypair.
  // It returns the generated signature as a string.

// encryptMessage:
  // This function encrypts a message using the Kyber768 KEM.
  // It takes a message and a public key for PKE as input.
  // It generates a random nonce.
  // It encrypts the message using Kyber768 KEM and the provided public key.
  // It returns the encrypted message as a string.

// decryptMessage:
  // This function decrypts a message encrypted with the Kyber768 KEM.
  // It takes an encrypted message and a secret key for PKE as input.
  // It decrypts the message using Kyber768 KEM and the provided secret key.
  // It returns the decrypted message as a string.

// encapsulateHybridSharedSecret:
  // This function encapsulates a shared secret using the hybrid KEM.
  // It takes a hybrid keypair and an encapsulated key vector as input.
  // It generates a random X25519 private key.
  // It derives the X25519 public key from the private key.
  // It performs the X25519 key exchange with the Kyber768 public key to obtain the shared secret.
  // It encapsulates the shared secret using Kyber768 KEM.
  // It returns the shared secret as a string.

// decapsulateHybridSharedSecret:
  // This function decapsulates a shared secret using the hybrid KEM.
  // It takes a hybrid keypair and an encapsulated key as input.
  // It performs the Kyber768 KEM decapsulation to obtain the X25519 public key and the shared secret.
  // It performs the X25519 key exchange to obtain the shared secret.
  // It compares the derived shared secret with the original shared secret and throws an error if they don't match.
  // It returns the shared secret as a string.
/////////////////////////////////////////////////////////////////////////////////////////////////////////


#ifndef SPHINX_HYBRID_KEY_HPP
#define SPHINX_HYBRID_KEY_HPP

#pragma once

#include <utility>
#include <array>
#include <iostream>
#include <algorithm>
#include <random>
#include <string>
#include <vector>
#include <cstdint>

#include "lib/Openssl/evp.h"
#include "lib/Openssl/hkdf.h" 
#include "lib/Openssl/hmac.h"
#include "Lib/Openssl/curve25519.h"
#include "lib/Openssl/sha.h"
#include "lib/Swifftx/SHA3.h"
#include "lib/Kyber/include/kyber768_kem.hpp"
#include "lib/Kyber/include/kyber768_pke.hpp"
#include "lib/Kyber/include/encapsulation.hpp"
#include "lib/Kyber/include/decapsulation.hpp"
#include "lib/Kyber/include/encryption.hpp"
#include "lib/Kyber/include/compression.hpp"

#include "Hash.hpp"
#include "Key.hpp"


namespace SPHINXHybridKey {

    // Function to perform the X25519 key exchange
    void performX25519KeyExchange(unsigned char shared_key[32], const unsigned char private_key[32], const unsigned char public_key[32]) {
        X25519(shared_key, private_key, public_key);
    }

    // Structure to hold the merged keypair
    struct HybridKeypair {
        struct {
            // Kyber768 keypair
            kyber768_kem::PublicKey kyber_public_key;
            kyber768_kem::PrivateKey kyber_private_key;
        } merged_key;

        // X25519 keypair
        std::pair<unsigned char[32], unsigned char[32]> x25519_key;

        // PKE keypair
        std::vector<uint8_t> public_key_pke;
        std::vector<uint8_t> secret_key_pke;

        // PRNG for key generation
        kyber768_pke::RandomNumberGenerator prng;
    };

    // Function to generate the hybrid keypair
    HybridKeypair generate_hybrid_keypair() {
        HybridKeypair hybrid_keypair;

        // Generate Kyber768 keypair for KEM
        hybrid_keypair.merged_key.kyber_public_key = kyber768_kem::keygen(hybrid_keypair.merged_key.kyber_private_key);

        // Generate X25519 keypair
        curve25519_generate_keypair(hybrid_keypair.x25519_key.first, hybrid_keypair.x25519_key.second);

        // Resize PKE keypair vectors
        hybrid_keypair.public_key_pke.resize(kyber768_pke::pub_key_len());
        hybrid_keypair.secret_key_pke.resize(kyber768_pke::sec_key_len());

        // Generate PKE keypair
        kyber768_pke::keygen(hybrid_keypair.prng, hybrid_keypair.public_key_pke.data(), hybrid_keypair.secret_key_pke.data());

        return hybrid_keypair;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////
    // Function to derive the master private key and chain code 
    // These functions are essential in blockchain systems for key generation, derivation, and 
    // securing data.
    // The deriveMasterKeyAndChainCode function is typically used to derive 
    // hierarchical deterministic (HD) wallet keys, where the master private key is derived from a 
    // seed and serves as the starting point for generating child keys. The HMAC-SHA512 function
    // (deriveKeyHMAC_SHA512) is commonly used in cryptographic protocols for key derivation, message
    // authentication, and integrity checking.
    /////////////////////////////////////////////////////////////////////////////////////////////////////
    std::pair<std::string, std::string> deriveMasterKeyAndChainCode(const std::string& seed) {
        std::string masterPrivateKey = deriveKeyHMAC_SWIFFTX("Sphinx seed", seed);
        std::string chainCode = deriveKeyHMAC_SWIFFTX("Sphinx chain code", seed);

        return std::make_pair(masterPrivateKey, chainCode);
    }

    // Function to derive a key using HMAC-SHA512
    std::string deriveKeyHMAC_SHA512(const std::string& key, const std::string& data) {
        // Convert the key and data to unsigned char arrays
        unsigned char keyBytes[key.length()];
        unsigned char dataBytes[data.length()];
        memcpy(keyBytes, key.data(), key.length());
        memcpy(dataBytes, data.data(), data.length());

        // Create a hash object for HMAC-SHA512
        HMAC_SHA512_CTX ctx;
        HMAC_SHA512_Init(&ctx);
        HMAC_SHA512_Update(&ctx, keyBytes, key.length());
        HMAC_SHA512_Update(&ctx, dataBytes, data.length());

        // Finalize the HMAC-SHA512 hash and get the result
        unsigned char hmacResult[HMAC_SHA512_DIGEST_LENGTH];
        HMAC_SHA512_Final(hmacResult, &ctx);

        // Convert the HMAC-SHA512 result to a string
        std::string derivedKey;
        for (size_t i = 0; i < HMAC_SHA512_DIGEST_LENGTH; i++) {
            derivedKey += static_cast<char>(hmacResult[i]);
        }

        return derivedKey;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////
    // Function to finalized HMAC-SHA512 the data using SWIFFTX-512
    // The SWIFFTX-512 hash function (hashSWIFFTX512) may be used for cryptographic operations requiring 
    // secure hashing, such as verifying data integrity and generating digital signatures.
    /////////////////////////////////////////////////////////////////////////////////////////////////////
    std::string hashSWIFFTX512(const std::string& data) {
        // Convert the data to BitSequence array
        BitSequence dataBytes[data.length()];
        for (size_t i = 0; i < data.length(); i++) {
            dataBytes[i] = static_cast<BitSequence>(data[i]);
        }

        // Create a hashState object for SWIFFTX
        hashState state;
        SWIFFTX512_Init(&state); // Initialize with SWIFFTX-512
        SWIFFTX512_Update(&state, dataBytes, data.length() * 8); // Update the hashState with the data
        BitSequence hashResult[SWIFFTX_OUTPUT_BLOCK_SIZE];
        SWIFFTX512_Final(&state, hashResult); // Finalize the hashState and get the SWIFFTX-512 result

        // Convert the SWIFFTX-512 result to a string
        std::string hashedData;
        for (size_t i = 0; i < SWIFFTX_OUTPUT_BLOCK_SIZE; i++) {
            hashedData += static_cast<char>(hashResult[i]);
        }

        return hashedData;
    }


    // Function to generate a random nonce
    std::string generateRandomNonce() {
        // Send a request to the function in "UTILS.HPP" to generate the random nonce
        return SPHINXUtils::generateRandomNonce();
    }

    // Function to derive a key using HKDF
    std::string deriveKeyHKDF(const std::string& inputKeyMaterial, const std::string& salt, const std::string& info, size_t keyLength) {
        std::string derivedKey(keyLength, 0);

        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()); // Set the default hash function to SHA256
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, reinterpret_cast<const uint8_t*>(salt.data()), salt.length());
        EVP_PKEY_CTX_set1_hkdf_key(pctx, reinterpret_cast<const uint8_t*>(inputKeyMaterial.data()), inputKeyMaterial.length());
        EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const uint8_t*>(info.data()), info.length());
        EVP_PKEY_CTX_set1_hkdf_size(pctx, keyLength);
        EVP_PKEY_derive(pctx, reinterpret_cast<uint8_t*>(derivedKey.data()), &keyLength);
        EVP_PKEY_CTX_free(pctx);

        // Compress the derived key using "SPHINXHash" or "SPHINX_256" hash function
        std::string compressedKey = SPHINXHash::SPHINX_256(derivedKey);

        return compressedKey;
    }

    // Function to calculate the SWIFFTX-256 hash of a string
    std::string hash(const std::string& input) {
        return SPHINXHash::SPHINX_256(input);  // Calculate the SWIFFTX-256 hash of the input
    }

    // Function to generate a key pair
    std::pair<std::string, std::string> generateKeyPair() {
        std::string privateKey = generateRandomNonce();
        std::string publicKey = hash(privateKey);  // Calculate the hash of the private key

        return {privateKey, publicKey};
    }

    // Function to generate an address from a public key
    std::string generateAddress(const std::string& publicKey) {
        std::string hash = hash(publicKey);  // Calculate the hash of the public key
        std::string address = hash.substr(0, 20);

        return address;
    }

    // Function to request a digital signature
    std::string requestDigitalSignature(const std::string& data, const HybridKeypair& hybrid_keypair) {
        // Call the verify_data function from "sign.hpp"
        std::string signature = SPHINXSign::verify_data(data, hybrid_keypair.secret_key_pke.data());

        return signature;
    }

    // Function to encrypt a message using Kyber768 KEM
    std::string encryptMessage(const std::string& message, const std::vector<uint8_t>& public_key_pke) {
        constexpr size_t tagLength = 16;  // Specify the desired length of the authentication tag

        std::string encrypted_message(kyber768_pke::cipher_text_len() + tagLength, 0);

        // Generate a random nonce
        std::string nonce = generateRandomNonce();

        // Encrypt the message using Kyber768 KEM
        cpapke::encrypt<1, kyber768_kem::eta1, kyber768_kem::eta2, kyber768_kem::du, kyber768_kem::dv>(
            public_key_pke.data(),
            reinterpret_cast<const uint8_t*>(message.data()),
            reinterpret_cast<const uint8_t*>(nonce.data()),
            reinterpret_cast<uint8_t*>(encrypted_message.data()),
            reinterpret_cast<uint8_t*>(encrypted_message.data() + kyber768_pke::cipher_text_len()),
            tagLength
        );

        return encrypted_message;
    }

    // Function to decrypt a message using Kyber768 KEM
    std::string decryptMessage(const std::string& encrypted_message, const std::vector<uint8_t>& secret_key_pke) {
        constexpr size_t tagLength = 16;  // Specify the length of the authentication tag

        std::string decrypted_message(kyber768_pke::cipher_text_len(), 0);

        // Decrypt the message using Kyber768 KEM
        cpapke::decrypt<1, kyber768_kem::du, kyber768_kem::dv>(
            secret_key_pke.data(),
            reinterpret_cast<const uint8_t*>(encrypted_message.data()),
            reinterpret_cast<const uint8_t*>(encrypted_message.data() + kyber768_pke::cipher_text_len()),
            tagLength,
            reinterpret_cast<uint8_t*>(decrypted_message.data())
        );

        return decrypted_message;
    }

    // Function to encapsulate a shared secret using the hybrid KEM
    std::string encapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, std::vector<uint8_t>& encapsulated_key) {
        // Generate a random X25519 private key
        unsigned char x25519_private_key[32];
        generate_random_bytes(x25519_private_key, sizeof(x25519_private_key));

        // Derive the X25519 public key from the private key
        unsigned char x25519_public_key[32];
        curve25519_derive_public_key(x25519_public_key, x25519_private_key);

        // Perform the X25519 key exchange to get the shared secret
        unsigned char shared_secret[32];
        performX25519KeyExchange(shared_secret, x25519_private_key, hybrid_keypair.merged_key.kyber_public_key.data());

        // Encapsulate the shared secret using Kyber768 KEM
        kyber768_kem::encapsulate(encapsulated_key.data(), x25519_public_key, hybrid_keypair.merged_key.kyber_public_key.data(), hybrid_keypair.merged_key.kyber_private_key.data());

        return std::string(shared_secret, shared_secret + sizeof(shared_secret));
    }

    // Function to decapsulate a shared secret using the hybrid KEM
    std::string decapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, const std::vector<uint8_t>& encapsulated_key) {
        // Perform the Kyber768 KEM decapsulation to obtain the X25519 public key and the shared secret
        unsigned char x25519_public_key[32];
        unsigned char shared_secret[32];
        kyber768_kem::decapsulate(x25519_public_key, shared_secret, encapsulated_key.data(), hybrid_keypair.merged_key.kyber_private_key.data());

        // Perform the X25519 key exchange to get the shared secret
        unsigned char derived_shared_secret[32];
        performX25519KeyExchange(derived_shared_secret, hybrid_keypair.x25519_key.first, x25519_public_key);

        // Compare the derived shared secret with the original shared secret
        if (std::memcmp(shared_secret, derived_shared_secret, sizeof(shared_secret)) != 0) {
            throw std::runtime_error("Shared secret mismatch");
        }

        return std::string(shared_secret, shared_secret + sizeof(shared_secret));
    }
}  // namespace SPHINXHybridKey

#endif // SPHINX_HYBRID_KEY_HPP
