<?php
function parse_arg() {
    global $argv;
    $arg_data = [];
    foreach ($argv as &$arg) {
        // index.php cmd cmd key:val key:val
        if (strpos($arg, ':') !== FALSE) {
            list($arg_key, $arg_value) = explode(':', $arg, 2);
            if (isset($arg_data[$arg_key])) {
                // array support
                if (!is_array($arg_data[$arg_key])) {
                    $arg_data[$arg_key] = [
                        $arg_data[$arg_key]
                    ];
                }
                $arg_data[$arg_key][] = $arg_value;
            } else {
                $arg_data[$arg_key] = $arg_value;
            }
            unset($arg_item);
        }
    }
    return $arg_data;
}

$arg_data = parse_arg();
$method   = $arg_data['method'];
$value    = $arg_data['value'];
$query    = ['method' => $method, 'value' => $value];

require_once('hash.php');