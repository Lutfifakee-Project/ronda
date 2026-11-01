<?php
// Fixture: assignment-like text inside heredoc and nowdoc bodies only.
$wp_version = '6.4.2';
$wp_db_version = 56657;
$heredoc = <<<EOT
$wp_local_package = 'ja';
more documentation text
EOT;
$nowdoc = <<<'EOT'
$wp_local_package = 'de_DE';
static documentation text
EOT;
