#!/bin/bash

# 設定相關路徑（在腳本中使用 $HOME 取代 ~ 以確保在任何執行環境下都能正確解析）
BIN_PATH="./target/debug/myssh-host"
TLS_CERT="$HOME/.myssh/server-cert.pem"
TLS_KEY="$HOME/.myssh/server-key.pem"
TRUST_STORE="$HOME/.myssh/trust-store"
FILE_ROOT="$HOME/myssh-files"

# 捕捉 Ctrl+C (SIGINT) 與一般終止訊號 (SIGTERM)，確保手動想關閉腳本時不會無限重啟
trap "echo '收到終止訊號，停止自動重啟並退出...'; exit 0" SIGINT SIGTERM

echo "開始啟動 myssh-host 守護迴圈..."

while true; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 正在啟動 myssh-host..."
    
    $BIN_PATH serve \
      --listen 192.168.50.95:22345 \
      --tls-cert "$TLS_CERT" \
      --tls-key "$TLS_KEY" \
      --trust-store "$TRUST_STORE" \
      --file-root "$FILE_ROOT"

    EXIT_CODE=$?
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 程式已結束 (退出代碼: $EXIT_CODE)，將在 3 秒後重新啟動..."
    sleep 3
done
