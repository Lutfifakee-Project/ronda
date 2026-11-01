<?php
// Fixture: the marker name appears only inside string literals and a
// backtick string; no code-level assignment exists.
$wp_version = '6.4.2';
$wp_db_version = 56657;
$doc1 = "read the $wp_local_package docs here";
$doc2 = 'example: $wp_local_package = \'de_DE\';';
$doc3 = "concatenated: " . '$wp_local_package = "ja";';
$doc4 = `text $wp_local_package = 'ja'; inside backticks`;
