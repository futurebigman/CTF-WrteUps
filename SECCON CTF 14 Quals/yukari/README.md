# yukari

## 前提
Crypto.Publickey.RSA.construct()に32回エラーを吐かせてフラグをゲットする問題です。
- 1024ビットの素数pが与えられます
- qはユーザが入力しますが、次のような条件があります。
  - q≠p
  - qは1024ビット以上
  - qは素数
  
## 解法
チームメンバーによって
$`q=kp+1`$
がたまにエラーを吐くが解明されました。
これを32回連続で起こすことを目標とします。

数学的なアプローチでクリアしたかったのですが、終了まで残り1時間を切っていたので、大量にログを集めて生成AIに傾向を分析してもらおうと考えました。

分析したところ次のような条件のとき、**100**%の確率でエラーを吐くことが判明しました。
> $`v_2(x) := xが2^kで割り切れる最大のk`$
> 
> $`v_2(q-1)-v_2(p-1)\ge 4`$

もう一度この条件で試すとフラグがゲット出来ました。
```
SECCON{9cb27d297988cdae22deca33d5e54a6955d6f95a010c6aec737ff7509f4ac715}
```

## 原理解説
そもそも変数は全てRSAの条件を満たしているのになぜエラーが起きるのでしょうか？
Githubの実装を見てみましょう。
https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/PublicKey/RSA.py
エラーが起きるのは次の箇所のようです。
```python
637            u = p.inverse(q)

675                if u <= 1 or u >= q:
676                    raise ValueError("Invalid RSA component u")
```

uはqを法とするpの逆元なので、u=1にしてエラーを発生させればいいということが分かります。

さらに今回はp,qを明示的に関数に渡していないため、アルゴリズム内で計算されています。
```python
t = d * e - 1
while t % 2 == 0:
    t //= 2
spotted = False
a = Integer(2)
while not spotted and a < 100:
    k = Integer(t)
    # Cycle through all values a^{t*2^i}=a^k
    while k < ktot:
        cand = pow(a, k, n)
        # Check if a^k is a non-trivial root of unity (mod n)
        if cand != 1 and cand != (n - 1) and pow(cand, 2, n) == 1:
            # We have found a number such that (cand-1)(cand+1)=0 (mod n).
            # Either of the terms divides n.
            p = Integer(n).gcd(cand + 1)
            spotted = True
            break
        k *= 2
    # This value was not any good... let's try another!
    a += 2
```


1. **初期化**: $`ed - 1`$ を計算し、$`2^s \cdot t`$（偶数部分と奇数部分）に分解します。
2. **ループ探索**: 偶数 $`a`$ を順に選び、検証を行います。
3. **計算**: 各 $`a`$ について、$`x_i \equiv a^{t \cdot 2^i} \pmod n`$ を計算します。
4. **判定**: $`x_i`$ が「1の非自明な平方根」であるかを確認します。
5. **因数分解**: 条件を満たせば、$`\gcd(x_i + 1, n)`$ を計算することで素因数 $`p`$ が得られます。

このp,qの順序を決定的にする条件が$`v_2(q-1)-v_2(p-1)\ge 4`$です。
ここで中国人の剰余定理を考えてみましょう。$x_i$ が「1の非自明な平方根」を持つというのは次のような条件に書き換えられます。

$x_i \equiv (1 \pmod p, -1 \pmod q)または(-1 \pmod p, 1 \pmod q)$

また

$x_i \equiv a^{t \cdot 2^i} \equiv a^{(p-1の奇数部分) \cdot (p-1の奇数部分) \cdot 2^i} \pmod n$

なのでiを増やしていくと必ず$2^i=v_2(p-1)$が先にきてフェルマーの小定理より

$x_i \equiv (1 \pmod p, -1 \pmod q)$

で反復が終了します。

**具体的な例**

| ループ回数 $i$ | mod $p$ の状態 | mod $q$ の状態 | 全体 $n$ での状態と判定 |
| :--- | :--- | :--- | :--- |
| $0$ | まだ途中 | まだ途中 | 何も起きない |
| $1$ | $-1$ | まだ途中 | 何も起きない |
| $2$ ($=v_p$) | $1$ (収束完了!) | まだ途中 | $x^2 \neq 1$ なのでスルー |
| $\dots$ | $1$ のまま ($1^2=1$) | $\dots$ | mod $p$ 側はずっと $1$ を維持 |
| $9$ ($=v_q-1$) | $1$ | $-1$ | **アルゴリズム終了** |

さらに

$`x_i + 1 \equiv (2 \pmod p, 0 \pmod q)`$

なので$`x_i+1とn=p \cdot q`$の最大公約数は必ずqになります。つまり入力したp,qはアルゴリズム内で逆になります。最後にuの計算に戻ると

$p \equiv kq+1 \equiv 1 \pmod q$

なのでその逆元uも1になります。したがって毎回エラーを起こすことが出来ます。

~~(理論的には$`v_2(q-1)-v_2(p-1)\ge 1`$でも良いはずですが、失敗する時がありました...)~~

$`v_2(q-1)-v_2(p-1)\ge 1`$でも成功することを確認しました。
