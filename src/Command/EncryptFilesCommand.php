<?php

namespace RushlowDevelopment\SealedIt\Command;

use RushlowDevelopment\SealedIt\Encryption\SodiumEncryptor;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Filesystem;

/**
 * @author Jesse Rushlow <jr@rushlow.dev>
 */
class EncryptFilesCommand extends Command
{
    protected static $defaultName = 'app:encrypt';
    protected static $defaultDescription = 'Encrypt files in data/ directory';

    private SymfonyStyle $io;
    private SodiumEncryptor $sodiumEncryptor;
    private Filesystem $filesystem;

    public function initialize(InputInterface $input, OutputInterface $output): void
    {
        $this->io = new SymfonyStyle($input, $output);
        $this->filesystem = new Filesystem();
    }

    public function interact(InputInterface $input, OutputInterface $output): void
    {
        $key = $this->io->askHidden('Please provide the secret key.');
        $this->sodiumEncryptor = new SodiumEncryptor(sodium_base642bin($key, SODIUM_BASE64_VARIANT_ORIGINAL));
    }

    public function execute(InputInterface $input, OutputInterface $output): int
    {
        $dataDir = dirname(__DIR__, 2).'/data';

        $dirContents = scandir($dataDir);

        foreach ($dirContents as $file) {
            $path = sprintf('%s/%s', $dataDir, $file);

            if (!is_file($path) || !is_readable($path)) {
                continue;
            }

            $this->io->text(sprintf('Found and Encrypting %s', $path));

            $fileContents = file_get_contents($path);

            $message = $this->sodiumEncryptor->encrypt($fileContents, ['fileName' => $file]);

            $nonce = sodium_bin2base64($message->nonce, SODIUM_BASE64_VARIANT_URLSAFE);

            $encryptedFilePath = sprintf('%s/encrypted/%s-%s.encrypted', $dataDir, $nonce, $file);
            $this->io->text(sprintf('Saving as %s', $encryptedFilePath));

            $this->filesystem->dumpFile(
                $encryptedFilePath,
                $message->message
            );
        }

        $this->io->success('Encryption Completed.');

        return self::SUCCESS;
    }
}
