# 🔐 MySSH

**MySSH** 是一個以 Rust 開發的輕量化遠端終端與檔案傳輸工具，提供經過 TLS 保護的連線、Ed25519 公開金鑰驗證、互動式遠端 Shell，以及雙向檔案傳輸。

MySSH 並不是 OpenSSH 的相容實作，而是擁有獨立通訊協定與 Client／Host 架構的專案。

> ⚠️ 本文件中的網域、IP、使用者名稱、路徑與金鑰資料皆為示範值。請依照實際環境替換，不要直接把範例憑證或金鑰用於正式環境。

---

## ✨ 功能特色

- 🔒 **TLS 加密連線**：驗證 Host 憑證，保護傳輸中的資料。
- 🔑 **Ed25519 身分驗證**：Client 使用私鑰簽署挑戰內容，Host 使用已登記的公開金鑰驗證。
- 🖥️ **遠端互動式 Shell**：透過 PTY 操作遠端終端。
- 📤 **檔案上傳**：將 Client 本機檔案傳送至 Host 指定的檔案根目錄。
- 📥 **檔案下載**：從 Host 指定的檔案根目錄取得檔案。
- 🧩 **傳輸層抽象化**：應用層協定與底層傳輸方式分離。
- ⏱️ **逾時與資源限制**：提供操作逾時及檔案大小限制等設定。

## 🏗️ 架構概覽

```text
┌──────────────────────────┐
│       MySSH Client       │
│                          │
│  CLI / Shell / File I/O  │
│  TLS / Ed25519 Auth      │
└────────────┬─────────────┘
             │
             │  MySSH Protocol
             │  over TLS
             ▼
┌──────────────────────────┐
│        Transport         │
│                          │
│   TCP / Other Adapters   │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│        MySSH Host        │
│                          │
│  TLS / Authentication    │
│  PTY / File Operations  │
└──────────────────────────┘
```

MySSH 的應用層不應綁定單一網路路徑。只要底層傳輸能提供雙向資料流，就能由對應的 Transport Adapter 承載 MySSH Protocol。

目前的 TCP Transport Adapter 負責一般 TCP 連線；它本身不會自動建立 Cloudflare Tunnel、DNS 或其他第三方隧道。

## 📦 專案結構

目前 Workspace 主要包含以下 Crates：

```text
MySSH-Server/
├── Cargo.toml
├── crates/
│   ├── myssh-core/
│   ├── myssh-protocol/
│   ├── myssh-transport/
│   ├── myssh-security/
│   ├── myssh-auth/
│   ├── myssh-host/
│   ├── myssh-client/
│   └── myssh-transport-cloudflare/
└── README.md
```

| Crate | 職責 |
|---|---|
| `myssh-core` | 核心共用型別與基礎功能 |
| `myssh-protocol` | MySSH 封包格式與訊息定義 |
| `myssh-transport` | 傳輸層抽象介面 |
| `myssh-security` | TLS 安全連線相關功能 |
| `myssh-auth` | Ed25519 身分驗證 |
| `myssh-host` | Host 端服務與命令列程式 |
| `myssh-client` | Client 端命令列程式 |
| `myssh-transport-cloudflare` | 目前以 TCP Socket 實作的 Transport Adapter；不負責建立 Cloudflare Tunnel |

---

# 🚀 建置

## 🧰 環境需求

- Rust Toolchain（含 Cargo）
- 可用的網路環境
- OpenSSL（用於建立及簽發 TLS 憑證）
- Host 與 Client 端皆須能讀寫各自的設定及金鑰檔案

確認 Rust 與 Cargo：

```bash
rustc --version
cargo --version
```

## 🔨 建置整個 Workspace

在專案根目錄執行：

```bash
cargo check --workspace
cargo test --workspace
cargo build --workspace
```

分別建置 Host 與 Client：

```bash
cargo build -p myssh-host
cargo build -p myssh-client
```

Debug 執行檔通常位於：

```text
target/debug/myssh-host
target/debug/myssh
```

正式部署可使用 Release Build：

```bash
cargo build --release -p myssh-host
cargo build --release -p myssh-client
```

Release 執行檔通常位於：

```text
target/release/myssh-host
target/release/myssh
```

---

# 🔐 TLS 憑證設定

MySSH 使用 TLS 保護 Client 與 Host 之間的連線。Client 必須驗證 Host 的憑證，不能因為連線失敗就直接停用憑證驗證。

以下示範建立一個自訂 CA，再由該 CA 簽發 Host 憑證。

## 1. 📁 建立憑證工作目錄

在 **Host 端**：

```bash
mkdir -p ~/.myssh
chmod 700 ~/.myssh
cd ~/.myssh
```

## 2. 🏛️ 建立 CA 私鑰

```bash
openssl genrsa -out ca-key.pem 3072
chmod 600 ca-key.pem
```

`ca-key.pem` 是 CA 的私鑰，必須妥善保管，不能傳給 Client，也不應放進公開版本控制庫。

## 3. 📜 建立 CA 憑證

```bash
openssl req -x509 -new \
  -key ca-key.pem \
  -sha256 \
  -days 3650 \
  -out ca-cert.pem \
  -subj "/CN=MySSH Example CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```

## 4. 🔑 建立 Host 私鑰

```bash
openssl genrsa -out server-key.pem 2048
chmod 600 server-key.pem
```

## 5. 📝 建立 Host CSR

以下使用文件保留網域 `myssh.example.com` 作為示範。若使用 IP 連線，請改用實際 IP，並在 SAN 中使用 `IP:` 格式。

```bash
openssl req -new \
  -key server-key.pem \
  -out server.csr \
  -subj "/CN=myssh.example.com"
```

## 6. 🧾 設定憑證用途與 SAN

```bash
cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:myssh.example.com
EOF
```

若 Host 使用 IP 位址，例如 `192.0.2.10`，SAN 範例應改為：

```text
subjectAltName=IP:192.0.2.10
```

若需要同時支援網域與 IP，可以在同一行列出兩者：

```text
subjectAltName=DNS:myssh.example.com,IP:192.0.2.10
```

憑證的 SAN 必須符合 Client 使用的 Host 身分名稱。

## 7. ✍️ 使用 CA 簽發 Host 憑證

```bash
openssl x509 -req \
  -in server.csr \
  -CA ca-cert.pem \
  -CAkey ca-key.pem \
  -CAcreateserial \
  -out server-cert.pem \
  -days 825 \
  -sha256 \
  -extfile server.ext
```

## 8. ✅ 驗證憑證

```bash
openssl verify -CAfile ca-cert.pem server-cert.pem
```

成功時應看到類似：

```text
server-cert.pem: OK
```

查看憑證 SAN：

```bash
openssl x509 -in server-cert.pem -noout -ext subjectAltName
```

查看憑證基本資訊：

```bash
openssl x509 -in server-cert.pem -noout -subject -issuer -dates
```

## 9. 📂 檢查檔案權限

```bash
chmod 600 ca-key.pem server-key.pem
chmod 644 ca-cert.pem server-cert.pem
```

Host 端需要保留：

```text
~/.myssh/
├── ca-key.pem       # CA 私鑰：只應由憑證管理者保管
├── ca-cert.pem      # CA 公開憑證
├── server-key.pem   # Host TLS 私鑰
├── server-cert.pem  # Host TLS 憑證
├── server.csr       # 憑證簽署請求
└── server.ext       # 憑證擴充設定
```

Host 執行 MySSH 時需要 `server-cert.pem` 與 `server-key.pem`。CA 私鑰不需要放在 MySSH 服務執行環境中；完成簽發後，應依照憑證管理需求安全保存。

## 10. 📤 將 CA 公開憑證提供給 Client

只需要把 **`ca-cert.pem`** 提供給 Client。不要傳送 `ca-key.pem` 或 Host 私鑰。

Client 端建立設定目錄：

```bash
mkdir -p ~/.myssh
chmod 700 ~/.myssh
```

將 CA 憑證放到：

```text
~/.myssh/ca.pem
```

例如可以使用安全的檔案傳輸方式，或透過其他可信任管道提供檔案。接收後可檢查：

```bash
openssl x509 -in ~/.myssh/ca.pem -noout -subject -issuer -dates
```

---

# 🔑 Client 身分金鑰

MySSH 使用 Ed25519 金鑰進行 Client 身分驗證。Client 私鑰留在 Client 端，Host 只需要登記對應的公開金鑰。

## 1. 建立 Client 設定目錄

```bash
mkdir -p ~/.myssh
chmod 700 ~/.myssh
```

## 2. 產生 Ed25519 金鑰

```bash
myssh keygen
```

預設私鑰位置：

```text
~/.myssh/id_ed25519
```

也可以指定輸出位置：

```bash
myssh keygen --output ~/.myssh/work_key
```

## 3. 查看公開金鑰

```bash
myssh keygen --show-public ~/.myssh/id_ed25519
```

輸出會包含 Key ID 與公開金鑰 Hex。將公開金鑰提供給 Host 管理者登記即可。

⚠️ **不要傳送 Client 私鑰 `id_ed25519`。** Host 只需要公開金鑰。

---

# 🖥️ Host 端設定

以下命令假設 Host 執行檔位於目前目錄的 `target/debug/myssh-host`。若使用 Release Build，請改成 `target/release/myssh-host`。

## 1. 建立 Host 設定與檔案目錄

```bash
mkdir -p ~/.myssh
mkdir -p ~/myssh-files
chmod 700 ~/.myssh
```

`--file-root` 指定 MySSH 檔案傳輸可使用的根目錄。檔案操作應限制在這個目錄範圍內，不代表 Client 能任意讀寫 Host 的整個檔案系統。

## 2. 初始化 Trust Store

```bash
./target/debug/myssh-host trust-init \
  --trust-store ~/.myssh/trust-store
```

Trust Store 用來保存允許連線的使用者及其公開金鑰。請妥善限制其檔案權限；目前實作要求 Unix 權限為 `0600`。

## 3. 登記 Client 公開金鑰

假設 Client 提供的公開金鑰 Hex 為下列示範值：

```text
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

登記指令：

```bash
./target/debug/myssh-host trust-add \
  --trust-store ~/.myssh/trust-store \
  --username alice \
  --public-key-hex 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

請將範例公開金鑰替換成 Client 實際產生的公開金鑰。

## 4. 啟動 Host

```bash
./target/debug/myssh-host serve \
  --listen 0.0.0.0:22345 \
  --tls-cert ~/.myssh/server-cert.pem \
  --tls-key ~/.myssh/server-key.pem \
  --trust-store ~/.myssh/trust-store \
  --file-root ~/myssh-files
```

參數說明：

| 參數 | 說明 |
|---|---|
| `--listen` | Host 監聽的 TCP 位址與 Port |
| `--tls-cert` | Host TLS 憑證 |
| `--tls-key` | Host TLS 私鑰 |
| `--trust-store` | 已授權 Client 的公開金鑰資料庫 |
| `--file-root` | MySSH 檔案傳輸根目錄 |
| `--max-file-size` | 最大檔案大小，單位為 Bytes |
| `--operation-timeout` | 操作逾時秒數 |

也可以指定額外限制：

```bash
./target/debug/myssh-host serve \
  --listen 0.0.0.0:22345 \
  --tls-cert ~/.myssh/server-cert.pem \
  --tls-key ~/.myssh/server-key.pem \
  --trust-store ~/.myssh/trust-store \
  --file-root ~/myssh-files \
  --max-file-size 2147483648 \
  --operation-timeout 30
```

> 🛡️ `0.0.0.0` 代表監聽所有 IPv4 網路介面。正式部署前，請先確認防火牆、網路隔離與存取控制設定。若只需要區域網路或單一介面，建議改成實際需要的監聽位址。

## 5. 管理已授權金鑰

查看 Host 指令說明：

```bash
./target/debug/myssh-host --help
```

移除已授權金鑰：

```bash
./target/debug/myssh-host trust-remove \
  --trust-store ~/.myssh/trust-store \
  --key-id 'ed25519:替換成實際的KEY_ID'
```

請使用實際的 Key ID，不要直接使用範例文字。

---

# 💻 Client 端操作

以下假設 Client 執行檔為 `target/debug/myssh`。正式版本可改用 `target/release/myssh`。

## 1. 查看指令說明

```bash
./target/debug/myssh --help
```

## 2. 遠端 Shell

假設：

- 使用者名稱：`alice`
- Host 身分名稱：`myssh.example.com`
- TCP Endpoint：`192.0.2.10:22345`
- CA 憑證：`~/.myssh/ca.pem`
- Client 私鑰：`~/.myssh/id_ed25519`

連線：

```bash
./target/debug/myssh \
  --endpoint 192.0.2.10:22345 \
  --tls-ca ~/.myssh/ca.pem \
  --identity ~/.myssh/id_ed25519 \
  shell alice@myssh.example.com
```

進入遠端 Shell 後：

```bash
whoami
pwd
ls
exit
```

`exit` 用於離開遠端 Shell。

## 3. 上傳檔案 📤

將本機 `example.txt` 上傳至 Host 的檔案根目錄下：

```bash
./target/debug/myssh \
  --endpoint 192.0.2.10:22345 \
  --tls-ca ~/.myssh/ca.pem \
  --identity ~/.myssh/id_ed25519 \
  upload ./example.txt alice@myssh.example.com:/example.txt
```

## 4. 下載檔案 📥

將 Host 檔案根目錄中的 `example.txt` 下載到 Client 目前目錄：

```bash
./target/debug/myssh \
  --endpoint 192.0.2.10:22345 \
  --tls-ca ~/.myssh/ca.pem \
  --identity ~/.myssh/id_ed25519 \
  download alice@myssh.example.com:/example.txt ./downloaded-example.txt
```

## 5. Client 參數說明

| 參數 | 說明 |
|---|---|
| `--endpoint ADDRESS` | 實際 TCP 連線位址，例如 `192.0.2.10:22345` |
| `--tls-ca FILE` | 用來驗證 Host 憑證的 CA 憑證檔 |
| `--identity FILE` | Client Ed25519 私鑰檔 |
| `--timeout SECONDS` | 連線或操作逾時秒數 |

`USER@HOST` 中的 `HOST` 是用來識別 TLS Host 身分的名稱；`--endpoint` 則是實際要連線的 TCP 位址。兩者可以不同，但 Host 憑證的 SAN 必須符合 `HOST`。

---

# 🌐 網路與 Transport

MySSH 使用 TCP Port 建立連線。IP 位址負責定位主機，Port 負責定位主機上的特定服務。

例如：

```text
192.0.2.10:22345
│          └── MySSH Host TCP Port
└───────────── Host IP 位址
```

SSH 常見的預設 Port 是 `22`，但它仍然需要 TCP Port。MySSH 使用自己的服務 Port；範例使用 `22345`，可依環境調整。

## 一般 TCP

```text
MySSH Client
     │
     │ TCP + TLS
     ▼
MySSH Host
```

只要 Client 能透過網路路由連到 Host 的監聽位址與 Port，就可以使用一般 TCP 連線。

## 私有網路或隧道

```text
MySSH Client
     │
     ▼
私有網路／隧道／TCP 轉發
     │
     ▼
MySSH Host
```

如果使用 Sing-box、VPN、Cloudflare Tunnel 或其他網路工具，請由該工具負責建立網路路徑，再讓 MySSH Client 連到可用的 TCP Endpoint。

⚠️ Transport Adapter 不等於隧道管理工具。目前名稱為 `myssh-transport-cloudflare` 的 Crate 使用一般 TCP Socket；它不會自行建立 Cloudflare Tunnel、設定 DNS 或管理 Cloudflare Access。

---

# 🔍 常見問題與排錯

## ❓ TLS 憑證驗證失敗

檢查：

1. Client 使用的 CA 憑證是否正確。
2. Host 憑證是否由該 CA 簽發。
3. 憑證是否過期。
4. Host 憑證 SAN 是否符合 `USER@HOST` 中的 Host 名稱。
5. Client 是否連到正確的 Host。

可以使用：

```bash
openssl verify -CAfile ~/.myssh/ca.pem server-cert.pem
```

## ❓ 找不到 CSR 檔案

若看到類似：

```text
Can't open "server.csr" for reading
```

請確認已成功執行 `openssl req -new`，而且目前工作目錄中確實存在 `server.csr`：

```bash
pwd
ls -l server.csr
```

## ❓ TCP 連線失敗

檢查：

- Host 服務是否正在執行。
- Client 使用的 Endpoint 與 Port 是否正確。
- Host 是否監聽該網路介面。
- 防火牆是否允許該連線。
- Client 與 Host 之間是否有可用路由。

## ❓ Ed25519 驗證失敗

檢查：

- Client 是否使用正確的私鑰。
- Host Trust Store 是否登記了對應的公開金鑰。
- 登記的使用者名稱是否與連線時的使用者名稱一致。
- 公開金鑰 Hex 是否完整且沒有多餘字元。

## ❓ 檔案傳輸失敗

檢查：

- Host 的 `--file-root` 目錄是否存在。
- Host 執行帳號是否有必要的檔案存取權限。
- 遠端路徑是否位於檔案根目錄允許的範圍。
- 檔案是否超過 `--max-file-size` 限制。
- 操作是否超過逾時設定。

---

# 🛡️ 安全注意事項

- 🔐 不要公開 CA 私鑰、Host TLS 私鑰或 Client Ed25519 私鑰。
- 🔑 Host Trust Store 只登記可信任 Client 的公開金鑰。
- 📜 Client 必須驗證 Host TLS 憑證；不要停用驗證來繞過錯誤。
- 🔥 對外開放 TCP Port 前，先確認防火牆與存取控制。
- 📁 將檔案傳輸限制在專用的 `--file-root` 目錄。
- 🧪 正式部署前，先在受控環境測試 Shell、上傳、下載及錯誤處理。
- 🧰 定期更新憑證，並安全保存 CA 簽發私鑰。

---

# 📌 開發狀態

目前專案已完成主要 Workspace、Protocol、TLS、安全驗證、Host／Client CLI 整合，以及遠端 Shell 連線測試。

| 項目 | 狀態 |
|---|---|
| Rust Workspace | ✅ 已建立 |
| MySSH Protocol | ✅ 已實作 |
| TLS 憑證驗證 | ✅ 已整合 |
| Ed25519 Client 驗證 | ✅ 已整合 |
| Host CLI | ✅ 已整合 |
| Client CLI | ✅ 已整合 |
| 遠端 Shell | ✅ 已完成實機連線測試 |
| 檔案上傳 | 🧪 尚待完整端到端測試 |
| 檔案下載 | 🧪 尚待完整端到端測試 |
| 額外 Transport | 🧩 可依需求擴充 |

> 以上狀態反映目前已知的開發與測試進度；尚未完成端到端驗證的功能，不應視為已通過完整實機測試。

---

## 📄 License

本專案採用 MIT License。

---

## 📬 聯繫創作者

- Gmail: b0953166696@gmail.com
- 本人17歲 🤔 做的不好請見諒
- 獨立開發 ＆ AI 協作
- 緩慢更新 ＆ 除錯
- 純手機 Termux 開發 👀
- 持續開發中…

---

## 👀 作品 & 產品集

- [MySSH](https://github.com/a370373/MySSH-Server)
- [UTE - Universal Training Engine](https://github.com/a370373/UTE-Universal-Training-Engine)
- [0-or-1](https://github.com/a370373/0-or-1)
- [MyDNS](https://github.com/a370373/MyDNS/tree/main)
- [Cyber-Fly-Android-Bridge](https://github.com/a370373/Cyber-Fly-Android-Bridge)
- [My-ADB-Shell](https://github.com/a370373/My-ADB-Shell/tree/main)
- [Cyber-Fly](https://github.com/a370373/Cyber-Fly)
- [MyOS](https://github.com/a370373/MyOS)
- [RWM-1:1 Real World Minecraft](https://github.com/a370373/RWM-Real-World-Minecraft)
- [MyAI - Offline Personal AI Agent System](https://github.com/a370373/MyAI-Offline-Personal-AI-Agent-System-/tree/main)
- [WCL - Web Clone Lab](https://github.com/a370373/web-clone-lab/)
- 持續增加中… 👀

---

## 🤖 AI 協作

MySSH 由 a370373/XRH 發起、設計與開發。

開發過程中使用 OpenAI ChatGPT 作為 AI 協作夥伴，協助進行技術分析、程式碼檢查、除錯與文件整理。

產品方向、設計理念與最終決策由專案創作者負責。
