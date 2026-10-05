<?php
declare(strict_types=1);

return [
    'routes' => [
        ['name' => 'page#index', 'url' => '/', 'verb' => 'GET'],
        ['name' => 'api#unlock', 'url' => '/api/unlock', 'verb' => 'POST'],
        ['name' => 'api#lock', 'url' => '/api/lock', 'verb' => 'POST'],
        ['name' => 'api#list', 'url' => '/api/list', 'verb' => 'GET'],
        ['name' => 'api#download', 'url' => '/api/download', 'verb' => 'GET'],
        ['name' => 'api#upload', 'url' => '/api/upload', 'verb' => 'POST'],
        ['name' => 'api#mkdir', 'url' => '/api/mkdir', 'verb' => 'POST'],
        ['name' => 'api#delete', 'url' => '/api/delete', 'verb' => 'POST'],
        ['name' => 'api#info', 'url' => '/api/info', 'verb' => 'GET'],
        ['name' => 'api#createVolume', 'url' => '/api/create-volume', 'verb' => 'POST'],
        ['name' => 'api#changePassword', 'url' => '/api/change-password', 'verb' => 'POST'],
        ['name' => 'api#headerBackup', 'url' => '/api/header-backup', 'verb' => 'GET'],
    ],
];
