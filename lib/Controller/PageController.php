<?php
declare(strict_types=1);

namespace OCA\CryptVault\Controller;

use OCA\CryptVault\Service\VaultService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\Files\IRootFolder;
use OCP\IRequest;
use OCP\IUserSession;

class PageController extends Controller
{
    public function __construct(
        string $appName,
        IRequest $request,
        private IRootFolder $rootFolder,
        private VaultService $vault,
        private ?IUserSession $userSession = null,
    ) {
        parent::__construct($appName, $request);
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    /** @NoCSRFRequired */
    #[\OCP\AppFramework\Http\Attribute\NoCSRFRequired]
    public function index(): TemplateResponse
    {
        $volumes = [];
        $preselect = (int)$this->request->getParam('fileid', 0);
        $user = $this->userSession?->getUser();
        if ($user !== null) {
            try {
                $userFolder = $this->rootFolder->getUserFolder($user->getUID());
                // find .hc/.tc files (non-recursive scan of top level + one depth is
                // expensive; do a light search via getById? Instead list by search)
                $results = $userFolder->search('.hc');
                foreach ($results as $node) {
                    if ($node->getType() !== \OCP\Files\FileInfo::TYPE_FILE) {
                        continue;
                    }
                    $name = $node->getName();
                    if (!preg_match('/\.hc$/i', $name) && !preg_match('/\.tc$/i', $name)) {
                        continue;
                    }
                    $volumes[] = [
                        'id' => $node->getId(),
                        'name' => $name,
                        'path' => $userFolder->getRelativePath($node->getPath()),
                        'size' => $node->getSize(),
                        'mtime' => $node->getMTime(),
                    ];
                }
                usort($volumes, fn($a, $b) => strcasecmp($a['name'], $b['name']));
            } catch (\Throwable) {
                // search may be unavailable; page still renders with empty list
            }
        }

        return new TemplateResponse('cryptvault', 'index', [
            'volumes' => $volumes,
            'preselect' => $preselect,
        ]);
    }
}
