# 鍵データ: バイナリ内の "expand 32-byte k"
key_string = b"expand 32-byte k"

flag_enc_1 = bytes([
    0x03, 0x15, 0x13, 0x03, 0x11, 0x55, 0x1f, 0x43,
    0x63, 0x61, 0x59, 0xef, 0xbc, 0x10, 0x1f, 0x43,
    0x54, 0xa8
])

flag_enc_2 = bytes([
    0x03, 0x15, 0x13, 0x03, 0x11, 0x5b, 0x1f, 0x43,
    0x63, 0x61, 0x59, 0xef, 0xbc, 0x10, 0x1f, 0x43,
    0x54, 0xa8
])

decoded_chars_1 = []
decoded_chars_2 = []

for i in range(18):
    # 暗号化ロジック: Out = In ^ (Key + i)
    # 復号ロジック:   In  = Out ^ (Key + i)

    # 1. 鍵の文字を取得 (expand 32-byte k の i%16 番目)
    k = key_string[i % 16]

    # 2. インデックスを加算 (8bitで切り捨て)
    mask = (k + i) & 0xFF

    # 3. 暗号文とXOR
    dec_1 = flag_enc_1[i] ^ mask
    dec_2 = flag_enc_2[i] ^ mask

    decoded_chars_1.append(chr(dec_1))
    decoded_chars_2.append(chr(dec_2))

# フラグの形式に整形して表示
flag_content_1 = "".join(decoded_chars_1)
flag_content_2 = "".join(decoded_chars_2)
print(f"フラグ1:SECCON{{{flag_content_1}}}")
print(f"フラグ2:SECCON{{{flag_content_2}}}")