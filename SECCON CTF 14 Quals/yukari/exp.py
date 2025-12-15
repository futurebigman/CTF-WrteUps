from pwn import *
from Crypto.Util.number import isPrime
import math
import time
import sys

# サーバー情報
HOST = 'yukari.seccon.games'
PORT = 15809

# ログファイルの設定
LOG_FILE = "attack_log.txt"

def log_to_file(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")

def find_q_force_reconstruction_failure(p):
    """
    復元アルゴリズムが失敗しやすい q = k*p + 1 を探索します。
    """

    MAX_TRIES = 100000000

    for i in range(MAX_TRIES):
        q = 2*(i+1) * p + 1
        
        # 素数判定
        if isPrime(q):
            return q, 2*(i+1)

def run_exploit():
    attempt_count = 0
    
    while True:
        attempt_count += 1
        print(f"\n[*] 接続試行: {attempt_count} 回目")
        
        try:
            # サーバーに接続
            conn = remote(HOST, PORT)
            
            round_num = 0
            while round_num < 32:
                round_num += 1
                
                # p を受信
                # 出力例: "p = 12345..."
                conn.recvuntil(b"p = ")
                p_str = conn.recvline().strip().decode()
                p = int(p_str)
                
                print(f"[*] Round {round_num}/32: p 受信 ")
                
                # q を計算
                q, i = find_q_force_reconstruction_failure(p)
                
                if q is None:
                    print("[-] q の計算に失敗しました。再接続します。")
                    log_to_file(f"[FAIL] Round {round_num}: p={p}, q=None")
                    conn.close()
                    break
                
                gcd_val = math.gcd(p-1, q-1)
                print(f"[*] q 計算完了: i={i}, gcd={gcd_val}")
                
                # q を送信
                conn.sendlineafter(b"q: ", str(q).encode())
                
                # 結果を受信
                # 成功(error!で継続) か 失敗(key setup successfulで終了) か判定
                result_line = conn.recvline().decode().strip()
                
                # ログ記録
                log_msg = f"Round {round_num}: p={p}, q={q}, gcd={gcd_val}, Result={result_line}"
                log_to_file(log_msg)
                
                if "error!" in result_line:
                    print(f"[+] 成功！ (error! 発生) - Round {round_num} クリア")
                elif "key setup successful" in result_line:
                    print(f"[-] 失敗... (鍵生成成功) - 再接続します")
                    conn.close()
                    break # while round_num ループを抜けて再接続へ
                else:
                    # フラグまたは予期せぬ出力
                    print(f"[?] サーバーからの応答: {result_line}")
                    # フラグかもしれないので残りを全て受信して表示
                    try:
                        rest = conn.recvall(timeout=2).decode()
                        print(f"[!] 残りの出力:\n{rest}")
                        log_to_file(f"[FLAG?] {result_line}\n{rest}")
                        return # フラグゲットなら終了
                    except:
                        pass
                    conn.close()
                    break

            if round_num == 32:
                print("[*] 32ラウンド完了！フラグを確認してください。")
                rest = conn.recvall().decode()
                print(f"[!!!] FLAG:\n{rest}")
                log_to_file(f"[FINAL] {rest}")
                return

        except Exception as e:
            print(f"[!] エラー発生: {e}")
            try:
                conn.close()
            except:
                pass
            time.sleep(1) # 少し待って再接続

if __name__ == "__main__":
    run_exploit()
