# AES (Advanced Encryption Standard)

アメリカが2001年に標準暗号として定めた共通鍵暗号アルゴリズムである。アメリカ国立標準技術研究所（NIST）が公募し、Rijndael（ラインダール）がAESとして採用された。

<!-- spell-checker:words Rijndael -->

## Block cipher mode of operation

ブロック暗号を利用して、ブロック長よりも長いメッセージを暗号化するメカニズムのこと。

### Authenticated encryption with additional data (AEAD) modes

認証暗号化モード

暗号文を作り出すと同時に認証するための情報を（認証子）を作り出す。

- GCM (Galois/counter)
    > 暗号化のカウンタ モードと新しい認証のガロア モードを組み合わせたもの。  
    > 認証に使用されるガロア体の乗算の並列計算が容易であることで、暗号化アルゴリズムよりも高いスループットが可能になる。
- CCM (Counter with CBC-MAC)  
    > AES-
CCMはWPA2で使われているCCMPと同じもの。
- [RFC 5084 ...](https://datatracker.ietf.org/doc/html/rfc5084)

<!-- spell-checker:words CCMP -->

### Confidentiality only modes

機密性のみ

- ECB (Electric CodeBlock mode)
    > もっとも単純な暗号利用モード.メッセージはブロックに分割され、それぞれのブロックは独立して暗号化される
- CBC (Cipher Block Chaining mode)
    > 平文の各ブロックは前の暗号文とのXORを取ってから暗号化される。各々の暗号文ブロックはそれ以前のすべての平文ブロックに依存することとなる。最初のブロックの暗号化には初期化ベクトルが用いられる。
- CFB (Chiper FeedBack mode)
    > １つ前の暗号文ブロックを暗号アルゴリズムの入力に戻す。  
    > ブロック暗号を自己同期型のストリーム暗号として扱う。
- OFB (Output-Feedback) mode.
    > ブロック暗号を同期型のストリーム暗号として扱う。  
    > 鍵ストリームを生成し、これと平文ブロックのXORを取ることで暗号文を得る。
- CTR (CounTeR) mode.
    > ブロック暗号を同期型のストリーム暗号として扱うものである。  
    > 「カウンター」と呼ばれる値を暗号化することで鍵ストリームブロックを生成する。

<!-- spell-checker:words Chiper -->
