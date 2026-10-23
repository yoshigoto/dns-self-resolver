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

- `queryDirectlyUDP` / `queryDirectlyTCP`: EDNS0・FORMERR 再試行・TC=1 時の TCP フォールバックに対応した DNS クエリ送受信。transaction ID は暗号論的乱数 (`crypto.randomInt`) で生成する。transaction ID が一致しない応答、question が存在して問い合わせ内容と一致しない応答、(UDP の場合) 送信元アドレス・ポートが問い合わせ先と一致しない応答は無視して正規の応答を待ち続ける。question が省略された応答は、transaction ID が一致する FORMERR 応答のみ受け入れる。`udpPort` / `tcpPort`、`timeoutMs` と `AbortSignal` を指定可能 (ポートの既定値は 53。偽装応答への対策の詳細は「[セキュリティ対策](#セキュリティ対策)」を参照)
- `resolveRecordFromServer`: 指定した権威サーバーから特定レコード (A / AAAA 等) を直接取得するヘルパー
- `resolveServerIPs` / `resolveHostnameIPv4Self` / `resolveHostnameIPv6Self` / `resolveRecordFromRoot`: ルートサーバーから NS 名の IP アドレスを再帰的に自己解決 (同一ホスト名の並行解決 Promise 共有・循環参照検出・CNAME 追跡・ルートサーバー切り替え・`knownAddresses` や共有キャッシュ対応)
- `resolveDnsServerAddressByType` / `resolveDnsServerAddress`: DNS サーバー名を A / AAAA の指定型で解決。後者は IPv4 優先時に AAAA へフォールバックするため、既存の `resolveDnsServerAddress` 呼び出しを置き換えやすい
- `resolveRecordFromRoot` の `dependencies.gluePolicy`: 既定の `strict` は委任先ゾーン内の glue と root referral が返す TLD NS glue を利用。RFC 9471 §2.3 の循環 sibling 委任を扱う場合は `allow-sibling` を明示すると、問い合わせ中のサーバーゾーン配下にある sibling glue も利用する
- `isInBailiwickGlue` / `hasParentChildRelationship` / `isSubdomainOrEqual` / `normalizeDnsName`: ドメイン名比較・グルー(bailiwick)判定
- `getReferralAddressRecords`: 委任応答の追加セクションからglueを抽出。NS名・レコード名は大文字小文字と末尾ドットを正規化して比較する。`strict` は委任 owner name 配下を許可し、root referral では `serverZone: '.'` を渡すと root が返す NS glue も許可する。`allow-sibling` は問い合わせ元ゾーン配下までを許可する。問い合わせ元ゾーンが省略された場合は委任ゾーン内に限定する
- `DNS_CACHE_TTL` / `getCacheEntry` / `setCacheEntry`: 呼び出し側が用意する `Map` を使った DNS 応答キャッシュ。UDP/TCP ともに完全な `NOERROR` 応答を応答内レコードの TTL と上限値(既定 30秒)の小さい方でキャッシュする。切り詰められた UDP 応答は TCP フォールバックし、タイムアウトは短時間 (既定 2秒) のみキャッシュされる (恒久的な障害固定を防ぐため `Infinity` にはしない)

## エラー形式

`queryDirectlyUDP` / `queryDirectlyTCP` はエラー時に構造化オブジェクトを返します。通常のエラーは次の形です。

```js
{
  error: 'TIMEOUT', // 'TIMEOUT' | 'ABORTED' | 'SOCKET_ERROR' | 'SEND_ERROR' | 'DECODE_ERROR'
  name: 'example.com',
  serverIp: '192.0.2.1',
  qType: 'A',
  transport: 'udp',
  retryable: true,
  detail: '...' // 例外メッセージ等 (存在する場合)
}
```

`serverIp` が IPv4/IPv6 アドレスリテラルでない場合は、ソケットを作成せずに `SEND_ERROR` (`retryable: false`) を返します。UDP では、transaction ID が一致してもデコードできないデータグラムは偽装の可能性があるため無視して待ち続け、タイムアウトまで正しい応答が届かなかった場合に `DECODE_ERROR` を返します。

UDP からの TCP フォールバック自体が例外で失敗した場合は `TCP_FALLBACK_ERROR` を返します。この場合は `error`、`detail`、`transport: 'tcp'`、`retryFrom: 'udp-truncated'`、`isFallback: true` を含み、通常のエラー形式にある `name`、`serverIp`、`qType`、`retryable` は含みません。


## 使い方

```js
import { queryDirectlyUDP, resolveServerIPs, normalizeDnsName } from 'dns-self-resolver';

const cache = new Map();
const res = await queryDirectlyUDP('example.com', '198.41.0.4', cache, 'NS');

const dnssecRes = await queryDirectlyUDP('com', '198.41.0.4', cache, 'DS', {
  useEdns: true,
  dnssecOk: true,
  udpPayloadSize: 1232,
  udpPort: 5353,
  tcpPort: 5353,
  timeoutMs: 5000,
  signal: AbortSignal.timeout(30000)
});
```

`queryOptions.udpPort` と `queryOptions.tcpPort` でそれぞれ問い合わせ先の UDP/TCP ポートを指定できます (1〜65535 の整数)。UDP 応答の送信元ポートも指定した UDP ポートと照合します。`queryDirectlyTCP` の第5引数にも同じオプションオブジェクトを指定でき、UDP 応答の `TC` フラグによる TCP フォールバックでも `tcpPort` を含むオプションが維持されます。ポート設定が異なる問い合わせは DNS 応答キャッシュに加え、上位の NS アドレスキャッシュ・ネガティブキャッシュ・並行解決の共有対象でも分離されます。`queryDirectlyUDP` の従来の第5引数 (`useEdns` の boolean) も引き続き利用できます。キャッシュは EDNS と DNSSEC OK (DO) の有無ごとにも分離されます。

ルートからの探索では、問い合わせ1回ごとの制限を `queryOptions.timeoutMs`、探索全体の制限を `signal` で指定します。`signal` が中断されると進行中のUDP/TCPソケットを閉じ、後続サーバーへの再試行も停止します。

```js
import { resolveRecordFromRoot } from 'dns-self-resolver';

const addresses = await resolveRecordFromRoot('example.com', 'A', cache, {
  queryOptions: { timeoutMs: 2000 },
  signal: AbortSignal.timeout(30000)
});
```

タイムアウト結果を含むキャッシュは `timeoutMs` ごとに分離されます。全体制限に `Promise.race` だけを使うと裏側の問い合わせは継続するため、停止が必要な場合は `AbortSignal` を利用してください。

依存性注入 (`dependencies` 引数) でクエリ関数を差し替えられるため、ユニットテストではモックを渡してネットワークアクセスなしに検証できます。

## セキュリティ対策

### 偽装応答・キャッシュポイズニング (Kaminsky 型) 対策

- transaction ID (16 bit) を `crypto.randomInt` で生成 (偏りのない一様分布。FORMERR 再試行・TCP フォールバック・0x20 なし再試行でも毎回新しい ID を生成する)
- 応答待ちの同一 UDP 問い合わせ (サーバー・名前・タイプ・オプションが同じもの) は 1 本にまとめ、結果を全呼び出し元で共有する。同じ問い合わせを並行して複数送ると偽装応答がいずれかに一致する確率が送信数に比例して上がる誕生日攻撃 (CERT VU#457875) への対策。呼び出し元ごとの `AbortSignal` はその呼び出し元だけを中断し、実際の問い合わせは待っている呼び出し元が全員中断した時点で中断する。異なる応答キャッシュを渡した呼び出し元にも結果のキャッシュを反映する
- UDP のソースポートを `crypto.randomInt` で 1024〜65535 から選んでバインド (OS のエフェメラルポート範囲に依存しない。使用中の場合は数回選び直し、最終的に OS 割り当てへフォールバック)。応答の送信元 UDP ポートは問い合わせ先ポート (`queryOptions.udpPort`、既定 53) と一致する場合のみ受理
- DNS 0x20: UDP の question 名の英字の大文字小文字をランダム化し、応答の question 名の完全一致を要求する。結果のレコード名は呼び出し側が指定した表記に戻して返す。`queryOptions.use0x20: false` で無効化できる。transaction ID と質問内容が一致し大文字小文字だけが異なる応答しか届かなかった場合 (大文字小文字を保持しないサーバー) は、タイムアウト後に 0x20 なしで 1 回だけ再試行し、結果に `caseRandomizationFallback: true` を付与する
- 送信元アドレス・ポート (既定 53、`udpPort` で変更可能)、ヘッダの transaction ID と QR ビットを**デコード前に**検証する。不正なデータグラムを偽装して送り付けても問い合わせは打ち切られない
- 応答キャッシュには問い合わせ名と完全に一致する応答のみを保存し、referral の glue は保存しない
- `gluePolicy: 'strict'` (既定) では out-of-bailiwick な glue を利用しない
- referral は「問い合わせ中のサーバーゾーンの真の子孫」かつ「問い合わせ名の祖先」である場合のみ受け入れる。上向き・横向きの referral は lame として扱い、次の候補サーバーへ切り替える

### 増幅攻撃 (NXNS / CVE-2020-12667 型)・リソース枯渇対策

`RESOLUTION_LIMITS` に既定値があり、`dependencies.resolutionLimits` で上書きできます。

| 項目 | 既定値 | 内容 |
|------|--------|------|
| `maxQueriesPerResolution` | 100 | 1 回のトップレベル解決 (入れ子の NS 名解決を含む) で送る問い合わせ数の上限 |
| `maxGluelessNsPerReferral` | 5 | 1 つの referral から、glue なしで自己解決を試みる NS 名の上限 |
| `maxCandidatesPerReferral` | 20 | 1 つの referral から試行する、アドレス付き候補の上限 |
| `maxNsResolutionDepth` | 5 | glue なし NS 名の入れ子解決の深さの上限 |

```js
await resolveRecordFromRoot('example.com', 'A', cache, {
  resolutionLimits: { maxQueriesPerResolution: 50 }
});
```

- 入れ子の NS 名解決には、呼び出し側の応答キャッシュと問い合わせ予算を引き継ぐ
- 自己解決に失敗した NS 名は短時間 (`NAMESERVER_NEGATIVE_CACHE_TTL`、既定 5 秒) ネガティブキャッシュする。上限や中断で打ち切られた失敗はキャッシュしない
- 応答キャッシュ (`setCacheEntry`) と NS アドレスキャッシュはエントリ数に上限を設け (`DNS_RESPONSE_CACHE_MAX_ENTRIES` / `NAMESERVER_CACHE_MAX_ENTRIES`、既定 10000)、超えた分は古い順に追い出す。TCP は 1 接続あたりの受信量にも上限を設ける

### キャッシュの分離

- NS アドレスのキャッシュと並行解決の合流 (Singleflight) は、呼び出し側固有の差し替え (`knownAddresses`、`queryDirectlyUDP`、`resolveHostnameIPv4Self`、`resolveHostnameIPv6Self`) のオブジェクトごとに分離する。ある呼び出し元が持ち込んだアドレスが、別の呼び出し元の解決結果を汚染しない。リクエストごとに新しい `knownAddresses` オブジェクトを渡せば、利用者間でキャッシュは共有されない
- NS アドレスのキャッシュ期間は、レコード TTL と `NAMESERVER_IP_CACHE_TTL` (5 分) の小さい方
- `getCachedNameserverIPs(hostname, gluePolicy, dependencies)` / `cacheNameserverIPs(hostname, ips, ttlMs, gluePolicy, dependencies)` の最後の引数で、対象のスコープを指定できる (省略時は差し替えなしの既定スコープ)

### 入力値の扱い

- `knownAddresses` は、プレーンオブジェクトでも自身のプロパティのみを参照する (`constructor` / `__proto__` などの NS 名で `Object.prototype` を引かない)。IP アドレスリテラルでない値は無視する
- referral・glue・NS 名解決で得たアドレスは、IP アドレスリテラルであることを確認してから利用する。クエリ関数が例外を投げた場合は、そのサーバーの失敗として扱い、次の候補へ進む

### 呼び出し側で考慮すべき点

- `retryWithoutEdns: true` の結果は EDNS/DO なしで再取得したもの。偽装された FORMERR によるダウングレードの可能性があるため、DNSSEC 検証を行う呼び出し側は署名がない応答を「insecure」ではなく「bogus」として扱うこと
- 本ライブラリは DNSSEC 検証を行わない。0x20 とランダムなソースポートで偽装の難易度は上がるが、改ざんを暗号学的に検出するには DNSSEC 検証が必要

## スコープ外 (呼び出し側アプリケーションの責務)

- ゾーン頂点の探索 (`getZoneApex`) や委任チェーンの追跡ロジック
- DNSSEC の署名検証 (RRSIG/DNSKEY/NSEC(3) など)
- 入力バリデーションやレート制限などアプリケーション固有の処理
