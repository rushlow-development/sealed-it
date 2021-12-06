<?php

namespace RushlowDevelopment\Tests\Unit\Encryption;

use PHPUnit\Framework\TestCase;
use RushlowDevelopment\SealedIt\Encryption\SodiumEncryptor;
use RushlowDevelopment\SealedIt\Model\EncryptedMessage;

/**
 * @author Jesse Rushlow <jr@rushlow.dev>
 */
class SodiumEncryptorTest extends TestCase
{
    private string $key;

    protected function setUp(): void
    {
        $this->key = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
    }

    public function testEncryption(): void
    {
        $message = 'Something super secret';
        $additionalData = ['more-data' => 'howdy'];

        $encryptor = new SodiumEncryptor($this->key);
        $result = $encryptor->encrypt($message, $additionalData);

        self::assertInstanceOf(EncryptedMessage::class, $result);
        self::assertTrue($message !== $result->message);

        self::assertNull($encryptor->decrypt($result, []));

        $badKeyEncryptor = new SodiumEncryptor(sodium_crypto_aead_xchacha20poly1305_ietf_keygen());

        self::assertNull($badKeyEncryptor->decrypt($result, $additionalData));

        $goodKeyEncryptor = new SodiumEncryptor($this->key);

        self::assertSame($message, $goodKeyEncryptor->decrypt($result, $additionalData));
    }
}
