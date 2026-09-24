#!/data/data/com.termux/files/usr/bin/sh
# proxy_update.sh — фоновый апдейт прокси раз в час
cd ~/storage/shared/omnistrike-v2
while true; do
    python -c "
import sys
sys.path.insert(0, '/data/data/com.termux/files/home/storage/shared/omnistrike-v2')
from core.proxy_manager import update_all
working = update_all(kinds=('https','socks5'), limit=100)
print(f'updated: {len(working)} working proxies')
" >> ~/.proxy_update.log 2>&1
    # ждём час
    sleep 3600
done
