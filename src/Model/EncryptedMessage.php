<?php

namespace RushlowDevelopment\SealedIt\Model;

/**
 * @author Jesse Rushlow <jr@rushlow.dev>
 */
class EncryptedMessage
{
    public function __construct(public string $message, public string $nonce)
    {
    }
}
