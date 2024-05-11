#include "filesystem"

#include <string>

using std::string;

#include "rsa.h"

using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "integer.h"

using CryptoPP::Integer;

#include "osrng.h"

using CryptoPP::AutoSeededRandomPool;

#include "filters.h"

using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::StringSink;

#include "files.h"

using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "base64.h"

using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "pem.h"
#include "algparam.h"

using CryptoPP::AlgorithmParameters;
using CryptoPP::MakeParameters;

using CryptoPP::byte;

#include "gcm.h"
using CryptoPP::GCM;

#include "aes.h"
using CryptoPP::AES;

#include "secblockfwd.h"
using CryptoPP::SecByteBlock;

using CryptoPP::ByteQueue;

using namespace std;

using CryptoPP::Exception;
using CryptoPP::Redirector;

#include "nbtheory.h"
using CryptoPP::LCM;

using CryptoPP::PrimeAndGenerator;


void SavePubKeyDER(const std::string& filename, const RSA::PublicKey& key);
void SavePriKeyDER(const std::string& filename, const RSA::PrivateKey& key);
void WritePEM(const ByteQueue& queue, std::ofstream& file, const std::string& begin, const std::string& end);
void SavePubKeyPEM(const std::string& filename, const RSA::PublicKey& key);
void SavePriKeyPEM(const std::string& filename, const RSA::PrivateKey& key);


/* Save functions*/
// Functions to save a PublicKey key in DER format (Distinguished Encoding Rules)
void SavePubKeyDER(const std::string& filename, const RSA::PublicKey& key) {
    ByteQueue queue;
    key.DEREncodePublicKey(queue);
    FileSink file(filename.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
}

// Function to save a PrivateKey key in DER format
void SavePriKeyDER(const std::string& filename, const RSA::PrivateKey& key) {
    ByteQueue queue;
    key.DEREncodePrivateKey(queue);
    FileSink file(filename.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
}

// Helper function to encode and write in proper PEM format
void WritePEM(const ByteQueue& queue, std::ofstream& file, const std::string& begin, const std::string& end) {
    file << begin << "\n";

    // Create a Base64Encoder that writes to a std::string
    std::string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64 /* insert line breaks */);

    // Copy queue contents to encoder
    queue.CopyTo(encoder);
    encoder.MessageEnd();

    // Write encoded content to file with proper line breaks
    file << encoded;
    file << end;  // Ensure there's a newline before and after the footer
}

// Function to save a public key in PEM format
void SavePubKeyPEM(const std::string& filename, const RSA::PublicKey& key) {
    std::ofstream file(filename);
    ByteQueue queue;
    key.DEREncodePublicKey(queue); //PKCS#1
    WritePEM(queue, file, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----");
    file.close();
}

// Function to save a private key in PEM format
void SavePriKeyPEM(const std::string& filename, const RSA::PrivateKey& key) {
    std::ofstream file(filename);
    ByteQueue queue;
    key.DEREncodePrivateKey(queue); //PKCS#1-Only sequence of parameters
    WritePEM(queue, file, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----");
    file.close();
}
/* Load functions*/
// Function to load a PublicKey key from a DER format
void LoadPubKeyDER(const std::string& filename, RSA::PublicKey& key) {
    FileSource file(filename.c_str(), true);
    ByteQueue queue;
    file.TransferTo(queue);
    queue.MessageEnd();
    key.BERDecodePublicKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

// Function to load a PrivateKey key from a DER format
void LoadPriKeyDER(const std::string& filename, RSA::PrivateKey& key) {
    FileSource file(filename.c_str(), true);
    ByteQueue queue;
    file.TransferTo(queue);
    queue.MessageEnd();
    key.BERDecodePrivateKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

// Helper function to read and decode from PEM format
void ReadPEM(ByteQueue& queue, const string& filename, const string& begin, const string& end) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Failed to open file: " + filename);
    }
    string line, encoded;
    bool capture = false;
    while (getline(file, line)) {
        // Check for the begin marker to start capturing
        if (line.find(begin) != string::npos) {
            capture = true;
            continue; // Skip the line with the begin marker
        }
        // Stop capturing after finding the end marker and skip it
        if (line.find(end) != string::npos) {
            break;
        }
        // Append the line to the encoded string if capturing is active
        if (capture) {
            encoded += line;
        }
    }
    // Decode the captured Base64 content into the ByteQueue
    StringSource stringSource(encoded, true, new Base64Decoder(new Redirector(queue)));
    cout << "Successfully read the key: " << filename <<endl;
}
// Function to load a public key from PEM format handle both (PKCS#1 and X.509)
void LoadPubKeyPEM(const std::string& filename, RSA::PublicKey& key) {
    ByteQueue queue;
    ReadPEM(queue, filename, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
    try {
        key.Load(queue);  // Attempt to load using CryptoPP's Load function which handles X.509 automatically
    } catch (const Exception& e) {
        // If loading the X.509 format fails, it might be a PKCS#1 formatted key
        queue.Clear();  // Clear the queue to reuse it
        ReadPEM(queue, filename, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----");
        key.BERDecodePublicKey(queue, false, queue.MaxRetrievable());
    }
}

// Function to load a private key from PEM format (both PKCS#1 and X.509)
void LoadPriKeyPEM(const std::string& filename, RSA::PrivateKey& key) {
    ByteQueue queue;
    // Try to read assuming PKCS#8 format
    ReadPEM(queue, filename, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
    try {
        key.Load(queue); // Try to load from PKCS#8
    } catch (const Exception&) {
        queue.Clear(); // Clear queue for retry
        ReadPEM(queue, filename, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----");
        key.BERDecodePrivateKey(queue, false, queue.MaxRetrievable()); // Fallback to PKCS#1
    }
}

// Mock functions for demonstration purposes
/*
void GenerateAndSaveRSAKeys(int keySize, const char* format, const char* privateKeyFile, const char* publicKeyFile) {
    // Implement RSA key generation and saving logic based on specified format
};
*/

void RSAencrypt(const char* publicKeyFile, const char* publicKeyformat, const char* plaintextFile, const char* plaintextFormat, const char* cipherFile, const char* cipherFormat) {
    AutoSeededRandomPool rng;
    RSA::PublicKey publicKey;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    const auto checkPublicKeyFormat = [&](const char* format) {
        if (strcmp(format, "DER") != 0 && strcmp(format, "PEM") != 0) {
            throw runtime_error("Invalid public key format. Supported formats: DER, PEM");
        }
    };

    checkPublicKeyFormat(publicKeyformat);

    switch (&publicKeyformat) {
        case "DER":
            LoadPubKeyDER(publicKeyFile, publicKey);
            switch (plaintextFormat) {
                case "DER":
                    switch (cipherFormat) {
                        case "DER":
                            FileSource file(plaintextFile, true, new PK_EncryptorFilter(rng, encryptor, new FileSink(cipherFile)));
                            break;
                        case "BASE64":
                            FileSource fileBase64(plaintextFile, true, new Base64Encoder(new PK_EncryptorFilter(rng, encryptor, new FileSink(cipherFile))));
                            break;
                        default:
                            throw runtime_error("Invalid cipher format. Supported formats: DER, BASE64");
                    }
                    break;
                case "BASE64":
                    switch (cipherFormat) {
                        case "DER":
                            FileSource file(plaintextFile, true, new Base64Decoder(new PK_EncryptorFilter(rng, encryptor, new FileSink(cipherFile))));
                            break;
                        case "BASE64":
                            FileSource fileBase64(plaintextFile, true, new Base64Encoder(new PK_EncryptorFilter(rng, encryptor, new FileSink(cipherFile))));
                            break;
                        default:
                            throw runtime_error("Invalid cipher format. Supported formats: DER, BASE64");
                    }
                    break;
                default:
                    throw runtime_error("Invalid plaintext format. Supported formats: DER, BASE64");
            }
            break;
        case "PEM":
            LoadPubKeyPEM(publicKeyFile, publicKey);

            switch (plaintextFormat) {
                case "DER":
                    switch (cipherFormat) {
                        case "DER":
                            FileSource file(plaintextFile, true, new PK_EncryptorFilter(rng, encryptor, new FileSink(cipherFile)));
                            break;
                        case "BASE64":
                            FileSource fileBase64(plaintextFile, true, new Base64Encoder(new PK_EncryptorFilter(rng, encryptor, new FileSink(cipherFile))));
                            break;
                        default:
                            throw runtime_error("Invalid cipher format. Supported formats: DER, BASE64");
                    }
                    break;
                case "BASE64":
                    switch (cipherFormat) {
                        case "DER":
                            FileSource file(plaintextFile, true, new Base64Decoder(new PK_EncryptorFilter(rng, encryptor, new FileSink(cipherFile))));
                            break;
                        case "BASE64":
                            FileSource fileBase64(plaintextFile, true, new Base64Encoder(new PK_EncryptorFilter(rng, encryptor, new FileSink(cipherFile))));
                            break;
                        default:
                            throw runtime_error("Invalid cipher format. Supported formats: DER, BASE64");
                    }
                    break;
                default:
                    throw runtime_error("Invalid plaintext format. Supported formats: DER, BASE64");
            }
        default:
            throw runtime_error("Invalid public key format. Supported formats: DER, PEM");
    }
};

void RSAdecrypt(const char* privateKeyFile, const char* privateKeyformat, const char* cipherFile, const char* cipherFormat, const char* plaintextFile, const char* plaintextFormat) {
    AutoSeededRandomPool rng;

    if (!strcmp(privateKeyformat, "DER")) {
        RSA::PrivateKey privateKey;
        LoadPriKeyDER(privateKeyFile, privateKey);
        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

        if (!strcmp(cipherFormat, "DER")) {
            FileSource file(cipherFile, true, new PK_DecryptorFilter(rng, decryptor, new FileSink(plaintextFile)));
        } else if (!strcmp(cipherFormat, "BASE64")) {
            FileSource file(cipherFile, true, new Base64Decoder(new PK_DecryptorFilter(rng, decryptor, new FileSink(plaintextFile))));
        }
    } else if (!strcmp(privateKeyformat, "PEM")) {
        RSA::PrivateKey privateKey;
        LoadPriKeyPEM(privateKeyFile, privateKey);
        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

        if (!strcmp(cipherFormat, "DER")) {
            FileSource file(cipherFile, true, new PK_DecryptorFilter(rng, decryptor, new FileSink(plaintextFile)));
        } else if (!strcmp(cipherFormat, "BASE64")) {
            FileSource file(cipherFile, true, new Base64Decoder(new PK_DecryptorFilter(rng, decryptor, new FileSink(plaintextFile))));
        }
    }
};

/* RSA key generation */
// Function to calculate Carmichael's lambda function
Integer CarmichaelsLambda(const Integer& p, const Integer& q) {
    return LCM(p-1, q-1);
}

void GenerateAndSaveRSAKeys(int keySize, const char* chrformat, const char* chrprivateKeyFile, const char* chrpublicKeyFile) {
    std::string format(chrformat), privateKeyFile(chrprivateKeyFile), publicKeyFile(chrpublicKeyFile);
    AutoSeededRandomPool rng;
    // Generate prime numbers
     // Adjust prime sizes to ensure the modulus n has roughly keySize bits
    int primeSize = keySize / 2;
    Integer p = PrimeAndGenerator(1, rng, primeSize).Prime();
    Integer q = PrimeAndGenerator(1, rng, primeSize).Prime();
    Integer n = p * q;
    Integer lambda_n = CarmichaelsLambda(p, q);

    // Select public exponent
    Integer e = Integer(rng, 257, lambda_n - 1, Integer::PRIME);
    if (Integer::Gcd(e, lambda_n) != Integer::One()) {
    std::cerr << "Error: e and lambda_n are not coprime!" << std::endl;
    return;}

    CryptoPP::ModularArithmetic ma(lambda_n);
    Integer d = ma.Divide(1, e);  // d is the modular inverse of e modulo

    // Create and initialize keys
    RSA::PublicKey publicKey;
    RSA::PrivateKey privateKey;
    publicKey.Initialize(n, e);
    privateKey.Initialize(n, e, d); // d is the modular inverse of e modulo

    // Validate keys
    if (!publicKey.Validate(rng, 3) || !privateKey.Validate(rng, 3)) {
        throw std::runtime_error("Key validation failed"); // should never happen
    }

    // Save keys in specified format
    if (format=="DER") {
        SavePubKeyDER(publicKeyFile, publicKey);
        SavePriKeyDER(privateKeyFile, privateKey);
        cout << "Save keys to " << privateKeyFile << ", and " << publicKeyFile <<endl;
    } else if (format=="PEM")
    {
        SavePubKeyPEM(publicKeyFile, publicKey);
        SavePriKeyPEM(privateKeyFile, privateKey);
        cout << "Save keys to " << privateKeyFile << ", and " << publicKeyFile <<endl; ;
    } else
    {
        std::cout << "The format does not support. Please select DER (binary) or PEM (Base64)" << std::endl;
    }
}

int main(const int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: \n"
             << argv[0] << " genkey <keysize> <format> <privateKeyFile> <publicKeyFile>\n"
             << argv[0] << " encrypt <publicKeyFile> <format> <plaintextFile> <plaintextFormat> <cipherFile> <cipherFormat>\n"
             << argv[0] << " decrypt <privateKeyFile> <format> <cipherFile> <cipherFormat> <plaintextFile> <plaintextFormat>\n";
        return -1;
    }

    string mode = argv[1];

    try {
        if (mode == "genkey" && argc == 6) {
            const int keySize = stoi(argv[2]);
            GenerateAndSaveRSAKeys(keySize, argv[3], argv[4], argv[5]);
        } else if (mode == "encrypt" && argc == 8) {
            RSAencrypt(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
        } else if (mode == "decrypt" && argc == 8) {
            RSAdecrypt(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
        } else {
            cerr << "Invalid arguments. Please check the usage instructions.\n";
            return -1;
        }
    } catch (const Exception& ep) {
        cerr << "Error: " << ep.what() << endl;
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }

    return 0;
}
