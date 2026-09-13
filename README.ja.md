# pseudowire-etherip

[English](README.md) | [日本語](README.ja.md)

本書は [README.md](README.md) の日本語訳です。内容が食い違う場合は英語版を優先します。

L2 セグメントを EtherIP（RFC 3378）トンネルで延伸する DPDK アプリケーションです。トンネルは IPv4 上にも IPv6 上にも構築できます。

ginzado-pseudowire（<https://github.com/ginzado/dpdk>）から派生し，その独自のカプセル化を標準の EtherIP（IP プロトコル番号 97）に置き換えたものです。そのため対向は本アプリケーションである必要はなく，EtherIP を話す実装（BSD 系 OS の gif/etherip インタフェース，各社のルータ製品など）であれば相互接続できます。

サポートするモードは次の 2 つで，トンネルエンドポイントアドレスのアドレスファミリで選ばれます。

* EtherIP over IPv4
* EtherIP over IPv6

本アプリケーションは 2 つのポートを使います。DL（ダウンリンク）ポートで受信したフレームは EtherIP でカプセル化して UL（アップリンク）ポートから送出し，UL ポートで受信した EtherIP パケットはデカプセル化して DL ポートから送出します。

> **状態: 実験的です。** データプレーンと制御プレーンは DPDK 25.11 上で `net_pcap` PMD を用いて検証済みです（RFC 3378 とビット単位で一致するカプセル化，フラグメント化と再構築を含むカプセル化・デカプセル化の往復，ARP/NDP によるネクストホップ解決）。また，実 NIC（UL 側に 82599ES/X520，DL 側に I226-V）を用い，NDP でネクストホップを解決しながら，本アプリケーション以外の EtherIP 実装との EtherIP over IPv6 トンネルで実トラフィックを流しています。本番環境ではまだ使われていません。

## ginzado-pseudowire との違い

* カプセル化は標準の EtherIP（RFC 3378）なので，対向は任意の EtherIP 実装でかまいません。
* サイズ超過のパケットは独自形式ではなく，標準の IP フラグメント化（IPv4 フラグメント／IPv6 フラグメント拡張ヘッダ）で分割します。フラグメント化と再構築には DPDK の `librte_ip_frag` を使います。
* トンネルは IPv6 上だけでなく IPv4 上にも構築できます。
* ネクストホップの MAC アドレスは ARP（IPv4）または NDP（IPv6）で自動的に解決するか，コマンドラインで静的に指定できます。
* すべての設定はコマンドラインで与えます。設定ファイルと SIGHUP による再読み込みはありません。

## カプセル化

カプセル化の際に前置されるヘッダは次のとおりです。

### EtherIP over IPv4

| ヘッダ                  |   サイズ |
|:------------------------|---------:|
| 外側 Ethernet ヘッダ    | 14 バイト |
| 外側 IPv4 ヘッダ        | 20 バイト |
| EtherIP ヘッダ          |  2 バイト |
| 元の Ethernet フレーム  |          |

### EtherIP over IPv6

| ヘッダ                  |   サイズ |
|:------------------------|---------:|
| 外側 Ethernet ヘッダ    | 14 バイト |
| 外側 IPv6 ヘッダ        | 40 バイト |
| EtherIP ヘッダ          |  2 バイト |
| 元の Ethernet フレーム  |          |

EtherIP ヘッダは 16 ビットで，上位 4 ビットがバージョン（3），残る 12 ビットは予約（0）です。つまり固定値 `0x3000` です。外側 IP のプロトコル番号（IPv6 では Next Header）は 97（EtherIP）です。

受信時，EtherIP バージョンが 3 でないパケットは（RFC 3378 の要求どおり）破棄します。

## フラグメント化と MTU

カプセル化後のパケットが UL 側の MTU（`--mtu`，既定 1500）を超える場合，標準の IP フラグメント化で分割してから送信します。UL 側で受信したフラグメントは，デカプセル化の前に再構築します。

内側 MTU 1500（1514 バイトのフレーム）を外側 MTU 1500 で通す場合，フルサイズのフレームはすべて 2 つに分割されます。外側の経路がジャンボフレームを通せるなら，`--mtu` を上げてフラグメント化が起きないようにするのが望ましいです。1514 バイトの内側フレームには 1536（IPv4）または 1556（IPv6）で足り，VLAN タグ付きならさらに 4 バイト必要で，9000 まで指定できます。一方，経路 MTU を変えられない場合（例: 日本の NTT フレッツ網内の「IPv6 折り返し通信」）でも，フラグメント化によってそうしたフレームをそのまま通せます。

UL ポートには `--mtu` の値が MTU として設定されるので，NIC とその PMD がそのサイズに対応している必要があります（2048 バイトの mbuf 1 個に収まらないサイズでは，スキャッタ受信にも対応している必要があります）。DL ポートは標準の MTU 1500 のままで，ginzado-pseudowire と同様にこれが内側フレームサイズの上限になります。それより大きい内側フレームは DL 側で受け付けません。

再構築には次の制約があります（`librte_ip_frag` と本実装によるもの）。

* 1 パケットあたりのフラグメントは最大 8 個です。
* IPv6 フラグメント拡張ヘッダは，IPv6 ヘッダの直後にある場合のみ扱います（一般的な EtherIP 実装はこの形で送ります）。
* ヘッダオプション付き（IHL != 5）の IPv4 パケットは扱いません。
* 再構築待ちのパケットは同時に最大 2048 個で，タイムアウトは 250 ms です。

## ネクストホップの解決

カプセル化したパケットの宛先（外側 Ethernet ヘッダの宛先 MAC アドレス）は次のいずれかで決まります。解決されるまで，DL 側で受信したフレームは破棄します。

* `--nexthop-mac` が与えられていれば，常にその値を使います。
* IPv4: 対向アドレスに対する ARP 要求を毎秒送信し，応答を学習します。自アドレスに対する ARP 要求には応答します（対向が同一リンク上にあることを前提としています。オフリンクの場合は，ゲートウェイの MAC アドレスを `--nexthop-mac` で指定してください）。
* IPv6: 対向アドレスに対する NS と，RS を毎秒送信し，NA を学習します（対向が同一リンク上にある場合）。ginzado-pseudowire と同様に，自アドレスと同じプレフィクスを広告する RA を受信すると，その送信元（ルータ）の MAC アドレスを学習します（NTT フレッツ網の折り返し通信のように，対向がルータの先にある場合のためです）。自アドレスに対する NS には NA で応答します。

## ビルド

必要なもの:

* DPDK 25.11 LTS（テスト済みのターゲットです。24.11 より古い DPDK では `struct rte_ipv6_addr` がないためビルドできません）
* meson と ninja
* C ツールチェインと pkg-config

Ubuntu 26.04 では次のようにします。

```
$ sudo apt install build-essential meson pkg-config dpdk libdpdk-dev
$ meson setup build
$ meson compile -C build
```

これで `build/dpdk-pseudowire-etherip` と `build/pestats` ができます。

あるいは，他の out-of-tree の DPDK アプリケーションと同様に，インストール済みの DPDK に対して直接コンパイルすることもできます。

```
$ cc $(pkg-config --cflags libdpdk) -DALLOW_EXPERIMENTAL_API \
	-o dpdk-pseudowire-etherip pseudowire_etherip.c \
	$(pkg-config --libs libdpdk)
```

## 使い方

### DPDK の準備

他の DPDK アプリケーションと同様に，hugepage を用意して NIC をバインドします。

```
$ sudo sh -c 'echo 64 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages'
$ sudo modprobe vfio-pci
$ sudo dpdk-devbind.py -u 0000:01:00.0 0000:01:00.1
$ sudo dpdk-devbind.py -b vfio-pci 0000:01:00.0 0000:01:00.1
```

本アプリケーション自体には 2 MB の hugepage が 64 枚あれば足ります（約 60 MB を使います）。`dpdk-testpmd` は既定でもっと多く要求するので，`--total-num-mbufs=16384` を付けるか hugepage を増やしてください。最近のディストリビューションは `/dev/hugepages` を自動的にマウントします。

`vfio-pci` を使うには IOMMU（Intel VT-d または AMD-Vi）が有効である必要があります。IOMMU が有効なホストで `uio_pci_generic` を使うと，NIC の DMA が黙って遮断されます。アプリケーションは起動してリンクアップを報告するのにパケットは一切流れず，`dmesg` に `DMAR: ... PTE Read access is not set` のフォールトが出ます。IOMMU のないホストでは，`uio_pci_generic` を使うか，vfio の no-IOMMU モードを有効にしてください（`echo 1 | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode`）。

本アプリケーションは 2 つのポート，DL 側（生の Ethernet フレーム）と UL 側（EtherIP パケット）を使います。どのポートをどちらの役割にするかは `--dl-port` / `--ul-port` で選びます（[オプション](#オプション) を参照）。既定では最初のポートが DL 側，2 番目のポートが UL 側です。

### オプション

アプリケーションのオプションは，EAL オプションと `--` の後に置きます。

| オプション            | 意味                                                             |
|:----------------------|:-----------------------------------------------------------------|
| `--remote=ADDR`       | 対向トンネルエンドポイントの IP アドレス（必須）                  |
| `--local=ADDR`        | 自トンネルエンドポイントの IP アドレス（必須）                    |
| `--mtu=N`             | UL 側 MTU（IPv4: 576-9000，IPv6: 1280-9000。既定 1500）           |
| `--nexthop-mac=MAC`   | 静的なネクストホップ MAC アドレス（省略時は ARP または NDP で解決） |
| `--stats-socket=PATH` | 統計情報ソケットのパス（既定 `/run/pestats.socket`）              |
| `--ul-port=PORT`      | UL 側として使うポート                                            |
| `--dl-port=PORT`      | DL 側として使うポート                                            |
| `-h`, `--help`        | 使い方を表示して終了                                             |

`--remote` と `--local` はトンネルエンドポイントのアドレスで，こちらが送るパケットの外側 IP ヘッダの宛先アドレスと送信元アドレスになります（対向は RFC 3378 の "remote EtherIP station" です）。両方が IPv4 か両方が IPv6 でなければならず，これによって EtherIP over IPv4 か EtherIP over IPv6 かが選ばれます。ginzado-pseudowire と同様に，区切りのない 16 進文字列（IPv4 は 8 桁，IPv6 は 32 桁）でも書けます。`--nexthop-mac` も同様に 12 桁の 16 進数を受け付け，区切りは `:` でも `-` でも，なしでもかまいません。

`PORT` は DPDK のポート ID またはデバイス名です。デバイス名は PCI アドレス（`0000:01:00.1`，または短く `01:00.1`）か vdev 名（`net_pcap1`）です。どちらのポートオプションも与えない場合，利用可能なポートがちょうど 2 つでなければならず，最初のポートが DL 側，2 番目が UL 側になります。一方だけ与えた場合，もう一方の側は 2 つのポートの残りになります。両方与えた場合はその 2 つのポートを使い，他のポートには触れません。

### 実行

EtherIP over IPv4:

```
$ sudo ./dpdk-pseudowire-etherip -l 1-3 -- --remote 192.0.2.2 --local 192.0.2.1
```

EtherIP over IPv6 で，静的なネクストホップを指定し，2 つのポートの役割を入れ替えた例:

```
$ sudo ./dpdk-pseudowire-etherip -l 1-3 -- --remote 2001:db8:1::1 --local 2001:db8::1 \
	--nexthop-mac 00:1a:2b:3c:4d:5e --ul-port 0000:01:00.0
```

有効な設定と実際に選ばれたポートは，起動時に表示されます。

```
mode: EtherIP over IPv6
remote: 2001:db8:1::1
local: 2001:db8::1
mtu: 1500
nexthop-mac: 00:1A:2B:3C:4D:5E
stats-socket: /run/pestats.socket
...
Port UL: 0 (0000:01:00.0) MAC: ...
Port DL: 1 (0000:01:00.1) MAC: ...
Port UL: Link up at 10 Gbps FDX Autoneg
Port DL: Link up at 1 Gbps FDX Autoneg
```

起動時には両ポートのリンクアップを最大 10 秒待ち，その状態を報告します。まだダウンしているリンクは警告として報告されます（アプリケーションは動き続けますが，リンクが上がるまでその側には何も流れません）。

ginzado-pseudowire と同様に，本アプリケーションにはちょうど 3 つの lcore が必要です（上の例で `-l 1-3` としているのはこのためです）。

* UL ポートで受信したパケットを処理するループ（`lcore_ul`）
* DL ポートで受信したフレームを処理するループ（`lcore_dl`）
* それ以外のすべて，すなわち破棄するフレームや ARP/NDP などを処理するループ（`lcore_main`）

設定は実行中に変更できません。アプリケーションを再起動してください。

### 統計情報

`pestats` コマンドは，`--stats-socket` で選んだ UNIX ドメインソケットを通じて，実行中のアプリケーションから統計情報を読み出します。既定以外のパスは引数で与えます。

```
$ sudo ./pestats [/path/to/pestats.socket]
pestats.ul_rx_packets                 27811573
...
```

| カウンタ            | 意味                                               |
|:--------------------|:---------------------------------------------------|
| ul_rx_packets/bytes | UL ポートで受信したパケット数／バイト数            |
| ul_rx_bpdus         | デカプセル化したフレーム中に見つかった BPDU 数     |
| ul_tx_packets/bytes | UL ポートから送出したパケット数／バイト数          |
| ul_tx_errors        | UL ポートで送出できなかったパケット数              |
| dl_rx_packets/bytes | DL ポートで受信したフレーム数／バイト数            |
| dl_rx_bpdus         | DL ポートで受信した BPDU 数                        |
| dl_tx_packets/bytes | DL ポートから送出したフレーム数／バイト数          |
| dl_tx_errors        | DL ポートで送出できなかったフレーム数              |
| encap_frags         | カプセル化時にフレームをフラグメント化した回数     |
| decap_reasms        | デカプセル化時に再構築が完了した回数               |
| decap_reasm_drops   | 再構築されずに破棄されたフラグメント数             |
| encap_noready_drops | ネクストホップ未解決のまま破棄されたフレーム数     |

BPDU カウンタ（`ul_rx_bpdus` / `dl_rx_bpdus`）は ginzado-pseudowire と同じ振る舞いなので，その `check_gpwbpdu.pl` と同じ要領で死活監視に使えます。

## テスト

`tests/pwtest.py` は，NIC，hugepage，root 権限なしでアプリケーションを動かして検査します。`net_pcap` 仮想デバイスが DL/UL ポートの役を演じ，スクリプトが書き出した pcap ファイルを入力として，アプリケーションの送出内容を RFC 3378 の規定とバイト単位で比較します（両アドレスファミリ，フラグメント化と再構築，ジャンボフレーム，ポート選択などのオプション，ソケット経由で読み出した統計情報）。

```
$ meson compile -C build
$ tests/pwtest.py             # または tests/pwtest.py <部分文字列> で一部のみ
```

`net_pcap` PMD を含む DPDK，3 つの CPU コア，約 512 MB の空きメモリが必要で，各シナリオに数秒かかります。

## 制限事項と注意

* 対向は 1 つだけです（送信元・宛先 IP アドレスが `--remote` と `--local` に一致しないパケットは，トンネルパケットとして扱いません）。
* EtherIP にはキープアライブも認証もありません。必要なら，BPDU カウンタの監視などで代替してください。ペイロードのチェックサムもないため，誤り検出は ginzado-pseudowire と同様に Ethernet FCS に依存します。
* 他の拡張ヘッダを持つ外側 IPv6 パケットは扱いません。
* 3 つの lcore は常にビジーポーリングします。

## 生成 AI の利用について

本プログラムとそのドキュメントは，Claude Code などの生成 AI によるコーディングエージェントの支援を受けて作成しました。その出力は作者がレビューし，テストしています。エージェントの支援を受けたコミットには，エージェントとモデルを示す `Assisted-by:` トレーラを付けています。

## ライセンス

BSD-3-Clause です。[LICENSE](LICENSE) を参照してください。

* Copyright (c) 2022, Ginzado Co., Ltd.
* Copyright (c) 2026, Taisuke "paina" SATO
