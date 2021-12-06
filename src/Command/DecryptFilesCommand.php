<?php

namespace RushlowDevelopment\SealedIt\Command;

use RushlowDevelopment\SealedIt\Encryption\SodiumEncryptor;
use RushlowDevelopment\SealedIt\Model\EncryptedMessage;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Filesystem;

/**
 * @author Jesse Rushlow <jr@rushlow.dev>
 */
class DecryptFilesCommand extends Command
{
    protected static $defaultName = 'app:decrypt';
    protected static $defaultDescription = 'Decrypt files in data/encrypted directory';

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

        $dirContents = scandir($dataDir.'/encrypted');

        foreach ($dirContents as $file) {
            $path = sprintf('%s/encrypted/%s', $dataDir, $file);

            if ('.gitignore' === $file || !is_file($path) || !is_readable($path)) {
                continue;
            }

            $this->io->text(sprintf('Found and Decrypting %s', $path));

            $fileContents = file_get_contents($path);

            $nonce = substr($file, offset: 0, length: 32);
            $fileName = substr($file, offset: 33, length: -strlen('.encrypted'));

            $message = new EncryptedMessage($fileContents, sodium_base642bin($nonce, SODIUM_BASE64_VARIANT_URLSAFE));

            $decryptedContent = $this->sodiumEncryptor->decrypt($message, ['fileName' => $fileName]);

            $decryptedFilePath = sprintf('%s/decrypted/%s', $dataDir, $fileName);
            $this->io->text(sprintf('Saving as %s', $decryptedFilePath));

            $this->filesystem->dumpFile(
                $decryptedFilePath,
                $decryptedContent
            );
        }

        $this->io->success('Decryption Completed.');

        return self::SUCCESS;
    }
}
