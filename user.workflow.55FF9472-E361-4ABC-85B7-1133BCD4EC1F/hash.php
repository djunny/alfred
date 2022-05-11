<?php
//$query = 'PASSWORD_DEFAULT purple monkey dishwasher';
// ****************
error_reporting(0);
require_once('workflows.php');
chdir(__DIR__);
$w = new Workflows();

mb_internal_encoding('UTF-8');


//set default env
function env($key = null, $def = '') {
    static $env;
    if (is_null($env)) {
        $load_env = function () {
            $env_file = './.env';
            if (is_file($env_file)) {
                $env = parse_ini_file($env_file);
            }
            return $env;
        };
        $env      = $load_env();
    }
    if (!is_null($key)) {
        return $env[$key] ?? $def;
    }

    return $env;
}


class b64 {

    const  DEFAULT_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const  CUSTOM_ALPHA  = "VWXefoABCqrsghijkGHIJKlmntYZabcdwxyTU567z01234NOPQRS89uvDEFLMp!_";
    const  PREFIX        = 'b64';

    /**
     * random
     *
     * @param $seed
     *
     * @return int
     */
    static function random($seed) {
        $seed = ($seed * 3307 + 49257) % 23328;
        $seed = ceil(($seed * 10000000) / 23328);
        return $seed;
    }

    static function fast_shuffle(&$input, $seed = 0) {
        if (!$input) {// 判断空，固定返回数组
            $input = [];
            return $input;
        }
        if (!is_numeric($seed)) {
            static $seed_cache = [];
            if (!isset($seed_cache[$seed])) {
                $seed_cache[$seed] = hexdec(hash('crc32', $seed));
            }
            $seed = $seed_cache[$seed];
        }
        $tmp_rand = static::random($seed) + 9832;
        for ($i = 0, $l = count($input); $i < $l; $i++) {
            $sort    = ($tmp_rand * ($i + 1) + 4997) % 9823;
            $sorts[] = $sort;
        }
        array_multisort($sorts, $input);
    }

    private static function alphabets() {
        return str_split(env('B64_ALPHABET', static::CUSTOM_ALPHA));

    }

    private static function random_char() {
        return rand(0, 9);
//        return substr(static::CUSTOM_ALPHA, rand(0, strlen(static::CUSTOM_ALPHA) - 1), 1);
    }

    public static function encode_seed($random = -1) {
        // rand char: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
        $alphabets = static::alphabets();
        // make random char
        $random = $random == -1 ? static::random_char() : max(9, min($random, 0));
        static::fast_shuffle($alphabets, $random);
        // print_r([implode('', $alphabets), $random]);
        return [$alphabets, $random];
    }

    public static function decode_seed($random) {
        $alphabets = static::alphabets();
        static::fast_shuffle($alphabets, $random);
        return $alphabets;
    }

    public static function encode($string, $random = -1) {
        if (strpos($string, static::PREFIX) === 0) {
            return '';// need decode
        }
        $seed   = static::encode_seed($random);
        $string = base64_encode($string);
        // echo $string, PHP_EOL;

        return static::PREFIX . $seed[1] . strtr($string, static::DEFAULT_ALPHA, implode('', $seed[0]));
    }

    public static function decode($string) {
        if (strpos($string, static::PREFIX) === 0) {
            //return '';// not b64
            $string = substr($string, strlen(static::PREFIX));
        }
        $random    = substr($string, 0, 1);
        $alphabets = static::decode_seed($random);
        $string    = substr($string, 1);
        // decode
        $string = strtr($string, implode('', $alphabets), static::DEFAULT_ALPHA);
        return base64_decode($string);
    }
}

//echo b64::encode('我的', 9), PHP_EOL;

// use defined algos
$user_defined_algos = [
    'base64Encode' => function ($input) {
        return base64_encode($input);
    },
    'base64Decode' => function ($input) {
        return base64_decode($input);
    },
    'b64Encrypt'   => function ($input) {
        return b64::encode($input);
    },
    'b64Decrypt'   => function ($input) {
        return b64::decode($input);
    },
    'urlEncode'    => function ($input) {
        return rawurlencode($input);
    },
    'urlDecode'    => function ($input) {
        return rawurldecode($input);
    },
    /*'pass_def'  => function ($input) {
        return password_hash($input, PASSWORD_DEFAULT);
    },
    'pass_bc'   => function ($input) {
        return password_hash($input, PASSWORD_BCRYPT);
    },*/
    'rev'          => function ($input) {
        $result = [];
        for ($i = mb_strlen($input) - 1; $i >= 0; $i--) {
            $result[] = mb_substr($input, $i, 1);
        }
        return implode('', $result);
    }
];
$algos              = array_merge([
    "md5",
    "sha1", "sha256",
    "crc32",
], array_keys($user_defined_algos));


// has algo set
if (is_string($query)) {
    $query   = explode(' ', $query, 2);
    $method  = '';
    $is_find = false;
    foreach ($algos as $algo) {
        if (strpos($algo, $query[0]) !== false) {
            $method  = $query[0];
            $query   = $query[1];
            $is_find = true;
            break;
        }
    }
    if (!$is_find) {
        $query = implode(' ', $query);
    }
    $query = [
        'method' => $method,
        'value'  => $query
    ];
}
$method = $query['method'] ?: '';
$string = $query['value'];
foreach ($algos as $algo) {
    if (!$method || strpos($algo, $method) !== false) {

        if ($user_defined_algos[$algo]) {
            $hash = $user_defined_algos[$algo]($string);
        } else {
            $hash = hash($algo, $string);
        }
        if (!$hash) {
            continue;
        }
        //echo "hash-$algo", $hash, "$method", $hash, 'icon.png', 'yes\n';
        // 修复可能乱码导致的问题
        $hash = htmlentities($hash);
        $w->result("hash-$algo", $hash, ucfirst($algo) . ": " . mb_substr($string, 0, 16), $hash, 'icon.png', 'yes');
    }
}

//echo json_encode($w->toJson(), JSON_PRETTY_PRINT);exit;
echo $w->toxml();
?>