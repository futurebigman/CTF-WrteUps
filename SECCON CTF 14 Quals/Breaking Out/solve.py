import base64
import zlib
import re
import json

def solve():
    print("[*] Parsing game.js...")
    try:
        with open("game.js", "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print("[-] game.js not found. Please verify the file name.")
        return

    # 1. Extract the obfuscated string array
    # The array is defined at the top: const _0x49f141 = ['...', ...];
    array_match = re.search(r"const _0x49f141\s*=\s*\[(.*?)\];", content, re.DOTALL)
    if not array_match:
        print("[-] Could not find string array _0x49f141.")
        return
    
    # Simple parsing of the JS array representation to a Python list
    raw_array = array_match.group(1)
    # Remove newlines and split by comma, respecting quotes is tricky but standard split might work for simple obfuscation
    # Better approach: find all single-quoted strings
    string_array = [s.strip("'") for s in re.findall(r"'([^']*)'", raw_array)]

    def get_str(index):
        # Logic from a0_0x3fa8: index - 0x1ac (428)
        real_index = index - 0x1ac
        if 0 <= real_index < len(string_array):
            val = string_array[real_index]
            # Logic from _0x935b41: Base64 decode + URL decode logic
            # The JS code basically does a standard Base64 decode then decodeURIComponent
            # Since mostly it's standard base64:
            try:
                # Add padding if necessary
                padded = val + '=' * (-len(val) % 4)
                return base64.b64decode(padded).decode('utf-8', errors='ignore')
            except:
                return val
        return None

    # 2. Extract input values (Hardcoded in the script)
    # These are found in lines like: a0_0x543e69[a0_0x9638eb(0x1f5)] = 0xe31329f4;
    # 0x1f5 - 0x1ac = 73. get_str(0x1f5) should be 'value' or similar property name.
    # However, we can just regex the hex values assigned to variables.
    
    # We need the ORDER. The order is defined in a0_0x3f33e7[...0x272] = [a0_0x543e69, a0_0x3b1ebc, ...];
    # Let's map variable names to values first.
    # Regex to find: const (VAR_NAME) = {}; ... (VAR_NAME)[...0x1f5...] = (HEX_VALUE);
    
    var_values = {}
    assignments = re.findall(r"(a0_0x[0-9a-f]+)\[a0_0x9638eb\(0x1f5\)\]\s*=\s*(0x[0-9a-f]+);", content)
    for var_name, hex_val in assignments:
        var_values[var_name] = int(hex_val, 16)

    # Now find the order array
    # a0_0x3f33e7[...0x272] = [a0_0x543e69, a0_0x3b1ebc, ...];
    # 0x272 - 0x1ac = 198.
    order_match = re.search(r"a0_0x3f33e7\[a0_0x9638eb\(0x272\)\]\s*=\s*\[(.*?)\]", content)
    if not order_match:
        print("[-] Could not find the order array.")
        return
    
    order_vars = [v.strip() for v in order_match.group(1).split(',')]
    
    ordered_values = []
    for var in order_vars:
        if var in var_values:
            ordered_values.append(var_values[var])
        else:
            print(f"[!] Warning: Variable {var} not found in value map.")

    print(f"[*] Found {len(ordered_values)} input values for hash generation.")

    # 3. Simulate Logic to generate Key
    # Initialization (from _0x270)
    # 0x1ed -> width (10), 0x1c3 -> height (10)
    width = 10
    height = 10
    
    acc1 = 0x13572468
    acc2 = 0x24681357
    acc3 = (width << 16 ^ height) & 0xFFFFFFFF # logic from `_0x30b47f << 0x10 ^ _0x1a8b15`

    print(f"[*] Initial Hash State: {hex(acc1)}, {hex(acc2)}, {hex(acc3)}")

    # Update Loop (from _0x210)
    for val in ordered_values:
        _0x455fb0 = val & 0xFFFFFFFF
        # Rotate left 7 bits
        _0x4c893b = ((_0x455fb0 << 7) | (_0x455fb0 >> 25)) & 0xFFFFFFFF
        
        acc1 = (acc1 + _0x455fb0) & 0xFFFFFFFF
        acc2 = (acc2 + _0x4c893b) & 0xFFFFFFFF
        acc3 = (acc3 + ((_0x455fb0 ^ 0x9e3779b9) & 0xFFFFFFFF)) & 0xFFFFFFFF

    # Generate Key String (from _0x1c5)
    # JS: toString(16).padStart(8, '0')
    key = f"{acc1:08x}{acc2:08x}{acc3:08x}"
    print(f"[*] Generated Key: {key}")

    # 4. Extract Encrypted Payload
    # a0_0x3f33e7[...0x229] = ...0x1fc...
    # 0x1fc - 0x1ac = 80.
    # We need the string at index 80 of the array.
    encrypted_b64 = get_str(0x1fc)
    
    # Double check if extraction worked (it should look like base64)
    if not encrypted_b64 or len(encrypted_b64) < 10:
        print("[-] Failed to extract encrypted string correctly.")
        # Fallback: manually find the long string 'ndu3mZe1nMHNvfPLuW' seen in analysis?
        # Actually, looking at the provided text, index 80 is 'ndu3mZe1nMHNvfPLuW'
        # Let's try to base64 decode it.
        # Wait, 'ndu3mZe1nMHNvfPLuW' decodes to 13 bytes. That seems short but possible for compressed data.
        # Let's verify the index logic.
        pass

    print(f"[*] Encrypted Payload (Base64): {encrypted_b64}")
    try:
        encrypted_data = base64.b64decode(encrypted_b64)
    except:
        print("[-] Base64 decode failed.")
        return

    # 5. RC4 Decrypt (from _0x201)
    def rc4_decrypt(key_str, data):
        # Key setup
        key = [ord(c) for c in key_str] # Key is the hex string treated as bytes
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # PRGA
        i = 0
        j = 0
        res = bytearray()
        for char in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            res.append(char ^ k)
        return res

    decrypted_rc4 = rc4_decrypt(key, encrypted_data)
    print(f"[*] RC4 Decrypted (hex): {decrypted_rc4.hex()}")

    # 6. Decompress (from _0x1f7)
    # JS uses DecompressionStream('deflate-raw'). Python zlib wbits=-15 handles this.
    try:
        decompressed = zlib.decompress(decrypted_rc4, wbits=-15)
        print("\n[+] Success! Decrypted JSON:")
        print(decompressed.decode('utf-8'))
        
        # Parse JSON just to be sure
        obj = json.loads(decompressed)
        print("\n[+] Parsed Object:", obj)
        
    except zlib.error as e:
        print(f"[-] Decompression failed: {e}")
        print("    Note: Check if the key generation order or input values are correct.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
