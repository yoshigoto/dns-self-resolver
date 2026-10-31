# dns-self-resolver

OS のスタブリゾルバ（フルサービスリゾルバ）に頼らず、ルート DNS サーバーから委任をたどって DNS レコードやネームサーバーの IP アドレスを解決する Node.js ライブラリです。

[dns-delegation-check](https://github.com/yoshigoto/dns-delegation-check) と [dnssec-validator](https://github.com/yoshigoto/dnssec-validator) で共通していた DNS 通信、応答キャッシュ、ネームサーバー解決の処理をまとめています。

## 動作要件

- Node.js 18 以降

## インストール

```bash
npm install git+https://github.com/yoshigoto/dns-self-resolver.git
```

## 主な機能

- `queryDirectlyUDP` / `queryDirectlyTCP`: 指定した DNS サーバーへ直接問い合わせます。EDNS、FORMERR を受けた場合の EDNS なし再試行、UDP 応答が切り詰められた場合の TCP フォールバックに対応しています。
- `resolveRecordFromRoot`: ルートサーバーから委任をたどり、指定したレコードを解決します。CNAME の追跡、サーバー候補の切り替え、問い合わせ予算、キャンセルに対応しています。
- `resolveServerIPs` / `resolveHostnameIPv4Self` / `resolveHostnameIPv6Self`: ネームサーバー名の IP アドレスを、ルートからたどって解決します。glue がない場合は再帰的に解決します。
- `resolveRecordFromServer`: 指定した DNS サーバーからレコードを取得します。
- `resolveDnsServerAddressByType` / `resolveDnsServerAddress`: DNS サーバー名を指定したアドレス種別で解決します。後者は IPv4 を優先し、取得できない場合は IPv6 を試します。
- `getReferralAddressRecords` / `isInBailiwickGlue` など: 委任応答から利用可能な glue を判定します。
- `classifyReferralAddressRecords`: NS 名に対応する ADDITIONAL の A/AAAA を `in-domain`、`sibling`、`unrelated` に分類します。解決候補への採用とは独立した処理です。
- `isPublicDnsServerAddress`: 公開権威 DNS 向けの問い合わせ先アドレスを判定します。
- `createQueryBudget`: 再送・TCP フォールバックを含む送信回数の共有予算を作ります。

## 使い方

### DNS サーバーへの直接問い合わせ

```js
import { queryDirectlyUDP } from 'dns-self-resolver';

const cache = new Map();
const response = await queryDirectlyUDP('example.com', '198.41.0.4', cache, 'NS');

if (response.error) {
  console.error(response.error, response.detail);
} else {
  console.log(response.answers);
}
```

第 5 引数には問い合わせオプションを指定できます。

```js
const dnssecResponse = await queryDirectlyUDP('com', '198.41.0.4', cache, 'DS', {
  useEdns: true,
  dnssecOk: true,
  udpPayloadSize: 1232,
  udpPort: 5353,
  tcpPort: 5353,
  timeoutMs: 5000,
  signal: AbortSignal.timeout(30000)
});
```

`udpPort` と `tcpPort` は問い合わせ先のポート（1〜65535）です。UDP 応答は送信元アドレスとポートも照合します。UDP の第 5 引数には従来どおり `useEdns` の boolean も指定できます。

### ルートからのレコード解決

```js
import { resolveRecordFromRoot } from 'dns-self-resolver';

const cache = new Map();
const addresses = await resolveRecordFromRoot('example.com', 'A', cache, {
  queryOptions: { timeoutMs: 2000 },
  signal: AbortSignal.timeout(30000)
});
```

`queryOptions.timeoutMs` は 1 回の問い合わせのタイムアウトです。解決処理全体を中断するには `signal` を指定してください。中断すると進行中のソケットを閉じ、後続サーバーへの再試行も停止します。`Promise.race` だけでは、タイムアウト後も内部の問い合わせが続くことがあります。

### glue の利用方針

`resolveRecordFromRoot` の `dependencies.gluePolicy` で glue の利用方針を指定できます。

- `strict`（既定）: 委任先ゾーン内の glue を利用します。ルートから TLD への referral では、ルートが返す TLD ネームサーバーのアドレスも利用します。
- `in-domain-only`: ルート referral も例外にせず、委任先ゾーン内の glue のみ利用します。親が保持する委任情報を調べる委任チェッカー向けの方針です。
- `allow-sibling`: 問い合わせ中のサーバーゾーン配下にある sibling glue も利用します。RFC 9471 §2.3 の循環 sibling 委任が必要な場合に指定してください。

`getReferralAddressRecords(additionals, nsNames, delegatedZone, gluePolicy, serverZone)` でも同じ方針を指定できます。既存の `strict` と `allow-sibling` の採用動作は変更していません。分類が同じでも、ポリシーに応じて採用するレコードは異なります。たとえばルートが返す TLD ゾーン外の NS アドレスは `sibling` に分類され、`strict` では採用し、`in-domain-only` では採用しません。

```js
import { classifyReferralAddressRecords, getReferralAddressRecords } from 'dns-self-resolver';

const classified = classifyReferralAddressRecords(additionals, nsNames, delegatedZone, parentZone);
const candidates = getReferralAddressRecords(
  additionals, nsNames, delegatedZone, 'in-domain-only', parentZone
);
```

分類結果は `{ inDomainGlueRecords, siblingGlueRecords, unrelatedAddressRecords }` です。NS 名に対応しないレコードや A/AAAA 以外はどの配列にも含めません。名前は大文字・小文字と末尾ドットを正規化して比較し、元のレコードと順序を維持します。DNS 応答は変更しません。親ゾーンには実際に応答したサーバーのゾーンを渡してください（ルートは `'.'` または `''`）。省略時のみ、従来の診断処理との互換性のため委任先名から左端のラベルを除いた名前を使います。この省略時の値は実際のゾーンカットを探索した結果ではありません。

## 問い合わせオプション

| オプション | 既定値 | 説明 |
|---|---:|---|
| `useEdns` | `true` | EDNS を有効にします。 |
| `dnssecOk` | `false` | EDNS の DO ビットを設定します。 |
| `udpPayloadSize` | `1232` | EDNS の UDP ペイロードサイズです。 |
| `udpPort` | `53` | 問い合わせ先の UDP ポートです。 |
| `tcpPort` | `53` | 問い合わせ先の TCP ポートです。 |
| `timeoutMs` | `5000` | 1 回の問い合わせのタイムアウト（ミリ秒）です。 |
| `signal` | なし | 問い合わせまたは解決処理を中断する `AbortSignal` です。 |
| `use0x20` | `true` | UDP の質問名の大文字・小文字をランダム化します。 |
| `isAllowedServerIP` | なし | 問い合わせ先 IP アドレスを受け取り、許可する場合に `true` を返す同期関数です。 |
| `queryBudget` | なし | `createQueryBudget(maxQueries)` で作った、DNS メッセージ送信回数の共有予算です。 |

`queryDirectlyUDP` と `queryDirectlyTCP` は、指定された DNS サーバーが IPv4 または IPv6 のアドレスリテラルであることを要求します。ホスト名を渡す場合は、先に `resolveDnsServerAddress` などで IP アドレスへ解決してください。

### 送信回数の共有予算

```js
import { createQueryBudget, queryDirectlyUDP, resolveServerIPs } from 'dns-self-resolver';

const queryBudget = createQueryBudget(1000);
const cache = new Map();
const controller = new AbortController();
const dependencies = { queryBudget, signal: controller.signal, dnsResponseCache: cache };
const addresses = await resolveServerIPs('ns.example.com', dependencies);
if (!addresses?.length) throw new Error('NS address resolution failed');
const response = await queryDirectlyUDP('example.com', addresses[0], cache, 'NS', {
  queryBudget, signal: controller.signal
});
```

同じ検査のすべての問い合わせに同じ予算オブジェクトを渡してください。直接問い合わせと `resolveRecordFromServer` では第 5 引数、ルート・NS 自己解決では `dependencies.queryBudget`（または `dependencies.queryOptions.queryBudget`）に指定します。両方ある場合は前者を優先します。入れ子の NS 解決、EDNS / 0x20 再試行、TCP フォールバックにも引き継ぎます。差し替えた問い合わせ関数は、受け取った `queryBudget` と `signal` を実トランスポートへ渡す必要があります。

UDP の `send` / TCP の DNS メッセージ `write` の直前に `remaining` を 1 減らします。UDP と TCP の取得はそれぞれ 1 回、A と AAAA も別々に数えます。送信処理に渡した後の失敗では予算を戻しません。バイト数、TCP 接続のハンドシェイク、OS による TCP 再送の回数は数えません。キャッシュ利用、送信前のキャンセル・宛先拒否・入力不備では減らしません。

同じ予算の並行 UDP 問い合わせは合流して 1 送信として数えます。異なる予算間では問い合わせと NS 自己解決の合流を分離し、片方の検査がもう片方の予算を消費しないようにします。完了した応答キャッシュは予算が異なっていても再利用できます。

残り 0 で新たな送信が必要になると、送信せず `QUERY_LIMIT_EXCEEDED`（`retryable: false`）を返し、`exhausted` を `true` にします。このエラーはキャッシュしません。最後の許可された送信を行っただけでは `exhausted` は立たず、残り 0 でもキャッシュは利用できます。自己解決の戻り値規約は変わりませんが、予算で打ち切られた結果を NS のネガティブキャッシュや完全なアドレス一覧として保存しません。アプリは `queryBudget.exhausted` を確認し、結果が不完全であることを表示してください。

省略時は送信予算を強制しません。`maxQueries` は 0 以上の安全な整数で、不正な値は `TypeError` になります。時間制限・クライアント切断時のキャンセルは、アプリが作った `AbortSignal` を併用してください。

### 問い合わせ先のポリシー

ライブラリの既定動作は公開 IP 限定ではありません。社内 DNS やループバック上のテストサーバーにも利用できます。公開 DNS を調べるアプリでは、共通のポリシーを明示的に選択してください。

```js
import { isPublicDnsServerAddress, queryDirectlyUDP, resolveServerIPs } from 'dns-self-resolver';

const cache = new Map();
const policy = { isAllowedServerIP: isPublicDnsServerAddress };
const response = await queryDirectlyUDP('example.com', '198.41.0.4', cache, 'NS', policy);
const addresses = await resolveServerIPs('ns.example.com', {
  ...policy,
  dnsResponseCache: cache
});
```

`isPublicDnsServerAddress` は IPv4 の内部・特殊用途範囲を除外し、IPv6 は `2000::/3` 内に限定して Teredo、ベンチマーク、ORCHID / ORCHIDv2、文書用、6to4 の範囲を除外します。IPv4-mapped、NAT64、ULA、リンクローカル、マルチキャスト、`%` 付きアドレスも許可しません。これは公開権威 DNS 向けの保守的な方針であり、すべての特殊用途アドレスの到達可能性を分類するものではありません。アドレス割り当ての変更に応じてライブラリ側の一覧を更新します。

独自の同期判定関数も指定できます。直接問い合わせでは第 5 引数、自己解決では `dependencies.isAllowedServerIP`（または `dependencies.queryOptions.isAllowedServerIP`）に指定します。両方ある場合は前者を優先します。ポリシーは入れ子の NS 解決、glue から得た宛先、EDNS / 0x20 再試行、TCP フォールバックに引き継がれ、送信前と応答キャッシュの参照前に判定されます。NS アドレス解決では、リテラル・既知アドレス・キャッシュ・解決結果から拒否対象を除外します。ポリシーごとにキャッシュと並行問い合わせの共有範囲も分離します。

拒否された直接問い合わせは `BLOCKED_ADDRESS`（`retryable: false`）を返し、拒否結果はキャッシュしません。NS アドレス解決は既存の戻り値規約に従い、許可されたアドレスがなければ `null` または例外となります。`resolveRecordFromRoot` は許可された経路で取得できなければ空配列を返します。判定関数には同じ関数インスタンスを再利用することを推奨します。

委任診断などで拒否された最終アドレスも必要な場合、`resolveServerIPs` に `dependencies.includeBlockedAddresses: true` を指定できます。戻り値には最終的な A/AAAA 応答・既知アドレス・キャッシュに含まれる拒否対象も残りますが、解決途中の問い合わせ先や glue 候補には同じ宛先ポリシーが適用されます。このオプションは入れ子の NS 解決には引き継がれません。呼び出し側は戻り値を診断用に分類し、実際の問い合わせには必ず宛先ポリシーを適用してください。既定の戻り値は引き続き許可されたアドレスのみです。

## エラー

`queryDirectlyUDP` / `queryDirectlyTCP` は、通常の問い合わせ失敗を例外ではなく次の形式のオブジェクトで返します。

```js
{
  error: 'TIMEOUT',
  name: 'example.com',
  serverIp: '192.0.2.1',
  qType: 'A',
  transport: 'udp',
  retryable: true,
  detail: '...' // ある場合のみ
}
```

`error` には `TIMEOUT`、`ABORTED`、`QUERY_LIMIT_EXCEEDED`、`SOCKET_ERROR`、`SEND_ERROR`、`DECODE_ERROR` などが入ります。`serverIp` が IP アドレスリテラルでない場合やポートが範囲外の場合は、ソケットを作成せず `SEND_ERROR`（`retryable: false`）を返します。

UDP では、不正なデータグラムを受け取っても問い合わせを打ち切らず、正しい応答を待ちます。送信元・トランザクション ID・QR ビットの検証を通過した応答でデコードに失敗し、その後も正しい応答が届かずタイムアウトした場合は `DECODE_ERROR` を返します（大文字・小文字の不一致による 0x20 なし再試行の条件も満たす場合は、再試行を優先します）。送信元や ID が一致しない応答だけを受け取った場合は `TIMEOUT` を返します。UDP から TCP へのフォールバック自体が例外で失敗した場合は `TCP_FALLBACK_ERROR` を返します。このエラー形式には `retryFrom: 'udp-truncated'` と `isFallback: true` が含まれます。

## キャッシュ

問い合わせ結果のキャッシュには、呼び出し側が用意した `Map` を渡します。

- `NOERROR` の応答を、応答内の answer / authority レコード TTL の最小値と上限（既定 30 秒）の小さい方でキャッシュします。対象レコードに TTL がない場合は上限を使い、TTL が 0 の場合はキャッシュをすぐ期限切れにします。
- タイムアウトは既定 2 秒、その他の一時的な失敗も短時間キャッシュします。失敗を長時間固定しないよう、無期限にはキャッシュしません。
- キャッシュキーは問い合わせ先、名前、レコード種別、ポート、EDNS / DO の設定、タイムアウトごとに分かれます。
- UDP の同一問い合わせが応答待ちの間に重複した場合は 1 回にまとめます。別々の `Map` を渡した呼び出し元にも、結果をそれぞれのキャッシュへ反映します。

ネームサーバー IP のキャッシュは、レコード TTL と `NAMESERVER_IP_CACHE_TTL`（既定 5 分）の小さい方を使います。失敗した名前は `NAMESERVER_NEGATIVE_CACHE_TTL`（既定 5 秒）だけネガティブキャッシュします。キャッシュと並行解決の共有範囲は、glue 方針や `knownAddresses`、差し替えた解決関数、DNS ポートなどに応じて分離されます。

`DNS_CACHE_TTL`、`getCacheEntry`、`setCacheEntry` は DNS 応答キャッシュ用の定数・関数です。ネームサーバー IP キャッシュを扱う `getCachedNameserverIPs` / `cacheNameserverIPs` も利用できます。

## 解決回数の上限

NXNS 型の増幅や過剰なリソース消費を抑える上限があります。`dependencies.resolutionLimits` で変更できます。

| 項目 | 既定値 | 説明 |
|---|---:|---|
| `maxQueriesPerResolution` | 100 | 入れ子のネームサーバー解決を含む、1 回の解決での問い合わせ関数呼び出し数。キャッシュ利用も数え、内部再送は別途数えません。 |
| `maxGluelessNsPerReferral` | 5 | 1 つの referral で自己解決を試す、glue のない NS 名の数。 |
| `maxCandidatesPerReferral` | 20 | 1 つの referral で試す、アドレス付き候補の数。 |
| `maxNsResolutionDepth` | 5 | glue のない NS 名を入れ子で解決する深さ。 |

```js
const addresses = await resolveRecordFromRoot('example.com', 'A', cache, {
  resolutionLimits: { maxQueriesPerResolution: 50 }
});
```

この既存の探索量制限は維持しています。実際の送信回数を制限する `queryBudget` とは別の上限です。

問い合わせ応答キャッシュとネームサーバー IP キャッシュには、それぞれエントリ数の上限（既定 10,000 件）があり、上限を超えると古いエントリから削除します。TCP 応答の受信量にも上限があります。

## セキュリティ上の注意

- トランザクション ID と UDP 送信元ポートは `crypto.randomInt` で生成します。UDP では送信元アドレス・ポート、トランザクション ID、QR ビット、質問内容を検証します。
- DNS 0x20 により UDP の質問名の大文字・小文字をランダム化します。大文字・小文字を保持しないサーバーには、該当する応答を検出した場合に限り、タイムアウト後に 0x20 を無効にして 1 回再試行します。結果には `caseRandomizationFallback: true` が付きます。
- 同一 UDP 問い合わせをまとめることで、並行送信によって偽装応答が当たる機会が増えることを抑えます。呼び出し元ごとの `AbortSignal` は個別に扱い、すべての呼び出し元が中断した場合に共有問い合わせを中断します。
- 不正な transaction ID や質問内容を持つ応答は無視します。質問セクションが省略された応答を受け入れるのは、ID が一致する FORMERR の場合だけです。
- `strict` では委任に関係しない out-of-bailiwick glue を候補にしません。受け入れた referral の glue は解決候補として使いますが、ネームサーバー IP キャッシュへ独立した解決結果として登録するわけではありません。
- 上向き・横向きの referral は受け入れず、次の候補サーバーを試します。

このライブラリは DNSSEC 検証を行いません。ランダム化や応答検証は偽装の難易度を上げますが、応答の真正性を暗号学的に確認するには、呼び出し側で DNSSEC 検証が必要です。`retryWithoutEdns: true` が付いた応答は EDNS / DO なしで再取得したものです。DNSSEC 検証を行う呼び出し側は、偽装された FORMERR によるダウングレードの可能性を考慮し、署名の欠如を単なる insecure として扱わないでください。

## スコープ外

次の処理は呼び出し側アプリケーションの責務です。

- ゾーン頂点の探索（`getZoneApex`）やアプリケーション固有の委任チェーン追跡
- DNSSEC 署名検証（RRSIG、DNSKEY、NSEC / NSEC3 など）
- 入力値の検証やレート制限
