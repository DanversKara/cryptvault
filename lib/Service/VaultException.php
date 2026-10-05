<?php
declare(strict_types=1);

namespace OCA\CryptVault\Service;

/** App-level error with an HTTP status code for the API layer. */
class VaultException extends \RuntimeException
{
    public function __construct(string $message, int $httpCode = 400, ?\Throwable $prev = null)
    {
        parent::__construct($message, $httpCode, $prev);
    }

    public function getHttpCode(): int
    {
        return $this->getCode() >= 400 ? $this->getCode() : 400;
    }
}
