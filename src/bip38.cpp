
#include "bip38.h"
#include "base58.h"
#include "hash.h"
#include "pubkey.h"
#include "util.h"
#include "utilstrencodings.h"

#include <string>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/aes.h>


/** 39 bytes - 78 characters
 * 1) Prefix - 2 bytes - 4 chars - strKey[0..3]
 * 2) Flagbyte - 1 byte - 2 chars - strKey[4..5]
 * 3) addresshash - 4 bytes - 8 chars - strKey[6..13]
 * 4) Owner Entropy - 8 bytes - 16 chars - strKey[14..29]
 * 5) Encrypted Part 1 - 8 bytes - 16 chars - strKey[30..45]
 * 6) Encrypted Part 2 - 16 bytes - 32 chars - strKey[46..77]
 */

void DecryptAES(uint256 encryptedIn, uint256 decryptionKey, uint256& output)
{
    AES_KEY key;
    AES_set_decrypt_key(decryptionKey.begin(), 256, &key);
    AES_decrypt(encryptedIn.begin(), output.begin(), &key);
}

void ComputePreFactor(std::string strPassphrase, std::string strSalt, uint256& prefactor)
{
    //passfactor is the scrypt hash of passphrase and ownersalt (NOTE this needs to handle alt cases too in the future)
    uint64_t s = uint256(ReverseEndianString(strSalt)).Get64();
    scrypt_hash(strPassphrase.c_str(), strPassphrase.size(), BEGIN(s), strSalt.size()/2, BEGIN(prefactor), 16384, 8, 8, 32);
}

void ComputePassfactor(std::string ownersalt, uint256 prefactor, uint256& passfactor)
{
    //concat prefactor and ownersalt
    uint512 temp(ReverseEndianString(HexStr(prefactor) + ownersalt));
    Hash(temp.begin(), 40, passfactor.begin()); //40 bytes is the length of prefactor + salt
    Hash(passfactor.begin(), 32, passfactor.begin());
}

bool ComputePasspoint(uint256 passfactor, CPubKey& passpoint)
{
    //passpoint is the ec_mult of passfactor on secp256k1
    int clen = 65;
    return secp256k1_ec_pubkey_create(UBEGIN(passpoint), &clen, passfactor.begin(), true) != 0;
}

void ComputeSeedBPass(CPubKey passpoint, std::string strAddressHash, std::string strOwnerSalt, uint512& seedBPass)
{
    // Derive decryption key for seedb using scrypt with passpoint, addresshash, and ownerentropy
    string salt = ReverseEndianString(strAddressHash + strOwnerSalt);
    uint256 s2(salt);
    scrypt_hash(BEGIN(passpoint), HexStr(passpoint).size()/2, BEGIN(s2), salt.size()/2, BEGIN(seedBPass), 1024, 1, 1, 64);
}

void ComputeFactorB(uint256 seedB, uint256& factorB)
{
    //factorB - a double sha256 hash of seedb
    Hash(seedB.begin(), 24, factorB.begin()); //seedB is only 24 bytes
    Hash(factorB.begin(), 32, factorB.begin());
}

bool BIP38_Decrypt(std::string strPassphrase, std::string strEncryptedKey, uint256& privKey, bool& fCompressed)
{
    std::string strKey = DecodeBase58(strEncryptedKey.c_str());

    //incorrect encoding of key, it must be 39 bytes - and another 4 bytes of base58 checksum
    if(strKey.size() != (78 + 8))
        return false;

    //No support for keys that did not use EC multiply
    std::string type = strKey.substr(2, 2);
    std::string flag = strKey.substr(4, 2);
    std::string strAddressHash = strKey.substr(6, 8);
    std::string ownersalt = strKey.substr(14, 16);
    uint256 encryptedPart1(ReverseEndianString(strKey.substr(30, 16)));
    uint256 encryptedPart2(ReverseEndianString(strKey.substr(46, 32)));

    fCompressed = (uint256(ReverseEndianString(flag)) & 0x20) != 0;

    //not ec multiplied
    if(uint256(ReverseEndianString(type)) != uint256(0x43))
    {
        uint512 hashed;
        encryptedPart1 = uint256(ReverseEndianString(strKey.substr(14, 32)));
        uint64_t salt = uint256(ReverseEndianString(strAddressHash)).Get64();
        scrypt_hash(strPassphrase.c_str(), strPassphrase.size(), BEGIN(salt), strAddressHash.size()/2, BEGIN(hashed), 16384, 8, 8, 64);

        uint256 derivedHalf1(hashed.ToString().substr(64, 128));
        uint256 derivedHalf2(hashed.ToString().substr(0, 64));

        uint256 decryptedPart1;
        DecryptAES(encryptedPart1, derivedHalf2, decryptedPart1);

        uint256 decryptedPart2;
        DecryptAES(encryptedPart2, derivedHalf2, decryptedPart2);

        //combine decrypted parts into 64 bytes
        uint256 temp1 = decryptedPart2 << 128;
        temp1 = temp1 | decryptedPart1;

        //xor the decryption with the derived half 1 for the final key
        privKey = temp1 ^ derivedHalf1;

        return true;
    }

    bool fLotSequence = (uint256(ReverseEndianString(flag)) & 0x04) != 0;

    std::string prefactorSalt = ownersalt;
    if(fLotSequence)
        prefactorSalt = ownersalt.substr(0, 8);

    uint256 prefactor;
    ComputePreFactor(strPassphrase, prefactorSalt, prefactor);

    uint256 passfactor;
    if(fLotSequence)
        ComputePassfactor(ownersalt, prefactor, passfactor);
    else
        passfactor = prefactor;

    CPubKey passpoint;
    if(!ComputePasspoint(passfactor, passpoint))
        return false;

    uint512 seedBPass;
    ComputeSeedBPass(passpoint, strAddressHash, ownersalt, seedBPass);

    //get derived halfs, being mindful for endian switch
    uint256 derivedHalf1(seedBPass.ToString().substr(64, 128));
    uint256 derivedHalf2(seedBPass.ToString().substr(0, 64));

    /** Decrypt encryptedpart2 using AES256Decrypt to yield the last 8 bytes of seedb and the last 8 bytes of encryptedpart1. **/
    uint256 decryptedPart2;
    DecryptAES(encryptedPart2, derivedHalf2, decryptedPart2);

    //xor decryptedPart2 and 2nd half of derived half 1
    uint256 x0 = derivedHalf1>>128; //drop off the first half (note: endian)
    uint256 x1 = decryptedPart2^x0;
    uint256 seedbPart2 = x1>>64;

    /** Decrypt encryptedpart1 to yield the remainder of seedb. **/
    uint256 decryptedPart1;
    uint256 x2 = x1&uint256("0xffffffffffffffff"); // set x2 to seedbPart1 (still encrypted)
    x2 = x2<<64; //make room to add encryptedPart1 to the front
    x2 = encryptedPart1|x2; //combine with encryptedPart1
    DecryptAES(x2, derivedHalf2, decryptedPart1);

    //decrypted part 1: seedb[0..15] xor derivedhalf1[0..15]
    uint256 x3 = derivedHalf1 & uint256("0xffffffffffffffffffffffffffffffff");
    uint256 seedbPart1 = decryptedPart1 ^ x3;
    uint256 seedB = seedbPart1|(seedbPart2<<128);

    uint256 factorB;
    ComputeFactorB(seedB, factorB);

    //multiply passfactor by factorb mod N to yield the priv key
    privKey = factorB;
    return secp256k1_ec_privkey_tweak_mul(privKey.begin(), passfactor.begin());
}
