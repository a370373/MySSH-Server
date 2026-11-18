#!/bin/bash

echo "🛑 正在關閉自動重啟腳本 (run_myssh.sh)..."
pkill -f run_myssh.sh

echo "🛑 正在關閉主程式 (myssh-host)..."
pkill -f myssh-host

sleep 1
echo "✅ 已經全部關閉！"
