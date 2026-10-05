<?php
declare(strict_types=1);

namespace OCA\CryptVault\AppInfo;

use OCA\CryptVault\Controller\ApiController;
use OCA\CryptVault\Controller\PageController;
use OCA\CryptVault\Service\VaultService;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;

class Application extends App implements IBootstrap
{
    public const APP_ID = 'cryptvault';

    public function __construct()
    {
        parent::__construct(self::APP_ID);
    }

    public function register(IRegistrationContext $context): void
    {
        $context->registerService(VaultService::class, function ($c) {
            return new VaultService(
                $c->get(\OCP\Files\IRootFolder::class),
                $c->get(\Psr\Log\LoggerInterface::class)
            );
        });
        $context->registerService(PageController::class, function ($c) {
            return new PageController(
                self::APP_ID,
                $c->get(\OCP\IRequest::class),
                $c->get(\OCP\Files\IRootFolder::class),
                $c->get(VaultService::class),
                $c->get(\OCP\IUserSession::class)
            );
        });
        $context->registerService(ApiController::class, function ($c) {
            $throttler = null;
            try {
                $throttler = $c->get(\OCP\Security\Bruteforce\IThrottler::class);
            } catch (\Throwable) {
                // brute-force throttling unavailable; unlock still works
            }
            return new ApiController(
                self::APP_ID,
                $c->get(\OCP\IRequest::class),
                $c->get(\OCP\IUserSession::class),
                $c->get(VaultService::class),
                $throttler
            );
        });
    }

    public function boot(IBootContext $context): void
    {
    }
}
