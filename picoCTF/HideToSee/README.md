# HideToSee

##  解法

1. stegseek atbash.jpg /usr/share/wordlists/rockyou.txt
2. AtBash変換

フラグゲット！
```
picoCTF{atbash_crack_8a0feddc}
```

---

# steghide / stegseek CTF用まとめ

## 1. steghide

### 概要・原理

* **パスワード付きステガノグラフィ**
* 画像や音声ファイルの **LSB（最下位ビット）中心** にデータを埋め込む
* 対応形式

  * 画像: jpeg, bmp
  * 音声: wav, au
* **暗号化 + 圧縮** を行うため、パスワードがないと基本的に取り出せない

CTFでは以下のケースで使われる:

* パスワードが問題文や別ファイルで与えられている
* 簡単な英単語パスワード
* 辞書攻撃前提

### ファイル情報確認

```
steghide info target.jpg
```

確認ポイント:

* embedded file があるか
* encrypted: yes / no
* compression: yes / no


### データ抽出（パスワードあり）

```
steghide extract -sf target.jpg
```

```
steghide extract -sf target.jpg -p password
```

主要オプション:

* extract : 埋め込みデータを抽出
* -sf     : cover file（対象ファイル）
* -p      : パスワード指定(なしで通ることも)
* -xf     : 出力ファイル名指定

```
steghide extract -sf target.jpg -p password -xf secret.txt
```

### データ埋め込み（参考）

```
steghide embed -cf image.jpg -ef secret.txt -p password
```

オプション:

* embed : データ埋め込み
* -cf   : cover file
* -ef   : embed file
* -p    : パスワード

### CTFでの典型的流れ（steghide）

1. file / binwalk / strings で確認
2. JPEG / WAV などのメディアファイル
3. steghide info
4. パスワードを探す
5. steghide extract

## 2. stegseek

### 概要・原理

* **steghide専用の高速パスワードクラックツール**
* steghideの認証処理を最適化して高速化
* CPUのみで高速動作
* 辞書攻撃前提（rockyou.txtなど）

CTFでは:

* steghideっぽいがパスワード不明
* → まず stegseek

### 基本構文

```
stegseek target.jpg wordlist.txt
```

### よく使うオプション

```
stegseek --extract target.jpg wordlist.txt
```

オプション:

* --extract : クラック成功後に自動抽出
* --quiet   : 余計な表示を消す
* --threads : スレッド数指定

```
stegseek --extract --quiet target.jpg /usr/share/wordlists/rockyou.txt
```

### 出力先指定

```
stegseek --extract target.jpg rockyou.txt -o output.txt
```

## 3. steghide vs stegseek（CTF視点）

| 項目     | steghide | stegseek |
| ------ | -------- | -------- |
| 役割     | 正規ツール    | クラック専用   |
| パスワード  | 必要       | 辞書攻撃     |
| 速度     | 遅い       | 高速       |
| CTF使用率 | 高        | 非常に高     |


## 4. CTF即判断フロー

```
画像/音声ファイル
│
├─ binwalk / strings → 何も出ない
│
├─ steghide info
│   ├─ パスワード不明 → stegseek
│   └─ パスワード判明 → steghide extract
│
└─ それでもダメ → zsteg / exiftool / 手動LSB解析
```

## 5. 覚えておく一発コマンド

```
stegseek --extract target.jpg /usr/share/wordlists/rockyou.txt
```

```
steghide extract -sf target.jpg -p password
```
