<?php

namespace RushlowDevelopment\SealedIt\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * @author Jesse Rushlow <jr@rushlow.dev>
 */
class GenerateKeyCommand extends Command
{
    protected static $defaultName = 'app:generate:key';
    protected static $defaultDescription = 'Generate a secret key for encryption.';

    private SymfonyStyle $io;

    protected function initialize(InputInterface $input, OutputInterface $output): void
    {
        $this->io = new SymfonyStyle($input, $output);
    }

    public function execute(InputInterface $input, OutputInterface $output): int
    {

        $key = sodium_bin2base64(sodium_crypto_aead_xchacha20poly1305_ietf_keygen(), SODIUM_BASE64_VARIANT_ORIGINAL);

        $this->io->success(sprintf('Encryption Key: %s', $key));

        $this->io->text('Store this secret key in a safe place.');

        return self::SUCCESS;
    }
}
