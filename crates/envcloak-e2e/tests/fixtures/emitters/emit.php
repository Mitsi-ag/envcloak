<?php
// Gate 8's PHP serializer for the fixture story (emit.py runs it): for each
// variable name given, the value in this process's environment as
// json_encode writes a string with its default flags, then NUL, then the
// SHA-256 of the value in hex, then NUL. Nothing else is written, and no
// error holds a value.
foreach (array_slice($argv, 1) as $name) {
    $value = getenv($name);
    if ($value === false) {
        fwrite(STDERR, "emit.php: a variable is not set\n");
        exit(1);
    }
    $json = json_encode($value);
    if ($json === false) {
        exit(1);
    }
    echo $json, "\0", hash('sha256', $value), "\0";
}
