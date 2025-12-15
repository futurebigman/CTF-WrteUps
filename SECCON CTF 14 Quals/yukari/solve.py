from pwn import *
from Crypto.Util.number import isPrime
import math
import time
import sys

# サーバー情報
HOST = 'yukari.seccon.games'
PORT = 15809

def count_trailing_zeros(x):
    """x を 2 で割り切れる回数 (v2) を返す"""
    count = 0
    while x > 0 and x % 2 == 0:
        x //= 2
        count += 1
    return count

def find_q_ultimate(p):
    """
    v2(q-1) - v2(p-1) >= 4 を満たす q を探索
    """
    p_minus_1 = p - 1
    vp = count_trailing_zeros(p_minus_1)
    
    # 目標: vq >= vp + 4
    target_vq_min = vp + 4
    
    # k を 2^(target_vq_min) の倍数にする
    # これにより vq = v2(k*p) = v2(k) >= vp + 4 が保証される
    step = 1 << target_vq_min
    
    # k = step, 2*step, 3*step ...
    # k は必ず target_vq_min 個以上の因数2を持つ
    k = step
    MAX_TRIES = 100000 

    for i in range(MAX_TRIES):
        q = k * p + 1
        
        # 素数判定
        if isPrime(q):
            # 念のため確認
            vk = count_trailing_zeros(k)
            if vk >= vp + 4:
                return q, k, vp, vk
            
        k += step
            
    return None, None, None, None

def run_exploit():
    attempt_count = 0
    
    while True:
        attempt_count += 1
        print(f"\n[*] 接続試行: {attempt_count} 回目")
        
        try:
            conn = remote(HOST, PORT)
            
            round_num = 0
            while round_num < 32:
                round_num += 1
                
                # p 受信
                conn.recvuntil(b"p = ")
                p_str = conn.recvline().strip().decode()
                p = int(p_str)
                
                print(f"[*] Round {round_num}/32: p 受信")
                
                q, k, vp, vq = find_q_ultimate(p)
                
                if q is None:
                    print("[-] q の計算に失敗しました。再接続します。")
                    conn.close()
                    break
                
                diff = vq - vp
                print(f"[*] q 計算完了: Diff(vq-vp)={diff} (Target >= 4)")
                
                # q 送信
                conn.sendlineafter(b"q: ", str(q).encode())
                
                # 結果受信
                result_line = conn.recvline().decode().strip()
                
                if "error!" in result_line:
                    print(f"[+] 成功")
                elif "key setup successful" in result_line:
                    print(f"[-] 失敗") 
                    conn.close()
                    break
                else:
                    # フラグの可能性
                    print(f"[?] サーバー応答: {result_line}")
                    try:
                        rest = conn.recvall(timeout=2).decode()
                        print(f"[!] 残りの出力:\n{rest}")
                        return
                    except:
                        pass
                    conn.close()
                    break

            if round_num == 32:
                print("[*] 32ラウンド完了！")
                rest = conn.recvall().decode()
                print(f"[!!!] FLAG:\n{rest}")
                return

        except Exception as e:
            print(f"[!] エラー: {e}")
            try:
                conn.close()
            except:
                pass
            time.sleep(1)

if __name__ == "__main__":
    run_exploit()