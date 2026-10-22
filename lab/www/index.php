<?php
header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'lab' => 'php2shell',
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'memory_limit' => ini_get('memory_limit'),
    'post_max_size' => ini_get('post_max_size'),
    'upload_progress_enabled' => ini_get('session.upload_progress.enabled'),
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
