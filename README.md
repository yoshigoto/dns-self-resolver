# dns-self-resolver

OS のスタブリゾルバ (フルサービスリゾルバ) に依存せず、ルートサーバーから自前で DNS を辿るための共通ユーティリティです。
[dns-delegation-check](https://github.com/) と [dnssec-validator](https://github.com/yoshigoto/dnssec-validator) の間で重複していた、
DNS パケットの送受信・キャッシュ・NS 名前解決ロジックを切り出したものです。

## 提供する機能

- `queryDirectlyUDP` / `queryDirectlyTCP`: EDNS0・FORMERR 再試行・TC=1 時の TCP フォールバックに対応した DNS クエリ送受信
- `resolveServerIPs` / `resolveHostnameIPv4Self` / `resolveRecordFromRoot`: ルートサーバーから NS 名の IP アドレスを再帰的に自己解決 (循環参照検出・グルーレコードキャッシュ付き)
- `isInBailiwickGlue` / `hasParentChildRelationship` / `isSubdomainOrEqual` / `normalizeDnsName`: ドメイン名比較・グルー(bailiwick)判定
- `DNS_CACHE_TTL` / `getCacheEntry` / `setCacheEntry`: 呼び出し側が用意する `Map` を使った DNS 応答キャッシュ

## 使い方

```js
import { queryDirectlyUDP, resolveServerIPs, normalizeDnsName } from 'dns-self-resolver';

const cache = new Map();
const res = await queryDirectlyUDP('example.com', '198.41.0.4', cache, 'NS');
```

依存性注入 (`dependencies` 引数) でクエリ関数を差し替えられるため、ユニットテストではモックを渡してネットワークアクセスなしに検証できます。

## スコープ外 (呼び出し側アプリケーションの責務)

- ゾーン頂点の探索 (`getZoneApex`) や委任チェーンの追跡ロジック
- DNSSEC の署名検証 (RRSIG/DNSKEY/NSEC(3) など)
- 入力バリデーションやレート制限などアプリケーション固有の処理
