# dns-self-resolver

OS のスタブリゾルバ (フルサービスリゾルバ) に依存せず、ルートサーバーから自前で DNS を辿るための共通ユーティリティです。
[dns-delegation-check](https://github.com/) と [dnssec-validator](https://github.com/yoshigoto/dnssec-validator) の間で重複していた、
DNS パケットの送受信・キャッシュ・NS 名前解決ロジックを切り出したものです。

## インストール

SSH 鍵の設定不要な HTTPS URL 経由でインストールできます。

```bash
npm install git+https://github.com/yoshigoto/dns-self-resolver.git
```

`package.json` の dependencies:

```json
{
  "dependencies": {
    "dns-self-resolver": "git+https://github.com/yoshigoto/dns-self-resolver.git"
  }
}
```

## 提供する機能

- `queryDirectlyUDP` / `queryDirectlyTCP`: EDNS0・FORMERR 再試行・TC=1 時の TCP フォールバックに対応した DNS クエリ送受信。transaction ID・question・(UDP の場合) 送信元アドレスが一致しない応答は無視して正規の応答を待ち続ける
- `resolveRecordFromServer`: 指定した権威サーバーから特定レコード (A / AAAA 等) を直接取得するヘルパー
- `resolveServerIPs` / `resolveHostnameIPv4Self` / `resolveRecordFromRoot`: ルートサーバーから NS 名の IP アドレスを再帰的に自己解決 (同一ホスト名の並行解決 Promise 共有・循環参照検出・`knownAddresses` や共有キャッシュ対応)
- `isInBailiwickGlue` / `hasParentChildRelationship` / `isSubdomainOrEqual` / `normalizeDnsName`: ドメイン名比較・グルー(bailiwick)判定
- `getReferralAddressRecords`: 委任応答の追加セクションから、次の問い合わせ先選定に使う参照アドレス (out-of-bailiwick を含む) を抽出。`isInBailiwickGlue` による正式な glue 判定とは区別される
- `DNS_CACHE_TTL` / `getCacheEntry` / `setCacheEntry`: 呼び出し側が用意する `Map` を使った DNS 応答キャッシュ。成功応答は応答内レコードの TTL と上限値(既定 30秒)の小さい方でキャッシュされ、タイムアウトは短時間 (既定 2秒) のみキャッシュされる (恒久的な障害固定を防ぐため `Infinity` にはしない)

## エラー形式

`queryDirectlyUDP` / `queryDirectlyTCP` はエラー時に次の形の構造化オブジェクトを返します。

```js
{
  error: 'TIMEOUT', // 'TIMEOUT' | 'SOCKET_ERROR' | 'SEND_ERROR' | 'DECODE_ERROR' | 'TCP_FALLBACK_ERROR'
  name: 'example.com',
  serverIp: '192.0.2.1',
  qType: 'A',
  transport: 'udp',
  retryable: true,
  detail: '...' // 例外メッセージ等 (存在する場合)
}
```


## 使い方

```js
import { queryDirectlyUDP, resolveServerIPs, normalizeDnsName } from 'dns-self-resolver';

const cache = new Map();
const res = await queryDirectlyUDP('example.com', '198.41.0.4', cache, 'NS');

const dnssecRes = await queryDirectlyUDP('com', '198.41.0.4', cache, 'DS', {
	useEdns: true,
	dnssecOk: true,
	udpPayloadSize: 1232,
	timeoutMs: 5000
});
```

`queryDirectlyTCP` の第5引数にも同じオプションオブジェクトを指定できます。`queryDirectlyUDP` の従来の第5引数 (`useEdns` の boolean) も引き続き利用できます。UDP応答の `TC` フラグによるTCPフォールバックではオプションが維持され、キャッシュはEDNSとDNSSEC OK (DO) の有無ごとに分離されます。

依存性注入 (`dependencies` 引数) でクエリ関数を差し替えられるため、ユニットテストではモックを渡してネットワークアクセスなしに検証できます。

## スコープ外 (呼び出し側アプリケーションの責務)

- ゾーン頂点の探索 (`getZoneApex`) や委任チェーンの追跡ロジック
- DNSSEC の署名検証 (RRSIG/DNSKEY/NSEC(3) など)
- 入力バリデーションやレート制限などアプリケーション固有の処理
