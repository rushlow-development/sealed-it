<?php

namespace RushlowDevelopment\SealedIt\Encryption;

use RushlowDevelopment\SealedIt\Model\EncryptedMessage;

/**
 * @author Jesse Rushlow <jr@rushlow.dev>
 */
class SodiumEncryptor
{
    public function __construct(
        private string $secretKey
    ) {
    }

    public function encrypt(string $data, array $additionalData): EncryptedMessage
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        $message = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            message: $data,
            additional_data: json_encode($additionalData),
            nonce: $nonce,
            key: $this->secretKey
        );

        return new EncryptedMessage($message, $nonce);
    }

    public function decrypt(EncryptedMessage $encryptedMessage, array $additionalData): ?string
    {
        $decrypted = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext: $encryptedMessage->message,
            additional_data: json_encode($additionalData),
            nonce: $encryptedMessage->nonce,
            key: $this->secretKey
        );

        return empty($decrypted) ? null : $decrypted;
    }

//    public function binToBase64(string $data): string
//    {
//        return sodium_bin2base64($data, \SODIUM_BASE64_VARIANT_ORIGINAL);
//    }
//
//    public function base64ToBin(string $data): string
//    {
//        return sodium_base642bin($data, \SODIUM_BASE64_VARIANT_ORIGINAL);
//    }
}
