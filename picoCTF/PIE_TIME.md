## 解法
Cファイルとバイナリファイルが与えられている。
Cを見るとwin関数を呼び出すことでflagが得られるとわかった。
```
objdump -d vuln | grep "main"
objdump -d vuln | grep "win"
```
でmainからwinの相対位置を把握。
netcatで接続すると参照先アドレスの変更ができることがわかったので、現在のmainの位置からwinを計算して終了
