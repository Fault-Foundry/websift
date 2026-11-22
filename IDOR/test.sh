# xss-test, Kali Linux
#!/bin/bash
set -uo pipefail

TARGETS_FILE="targets.txt"
HISTORY_FILE="seen_urls.txt"
OUT_ROOT="scan_results"
RUN_ID=$(date +%Y%m%d_%H%M%S)
OUT_DIR="$OUT_ROOT/$RUN_ID"
mkdir -p "$OUT_DIR"

KATANA_CONC=2
KATANA_PAR=1
KATANA_RL=10
KATANA_DEPTH=3
GAU_SLEEP=5
DALFOX_WORKERS=1
DALFOX_DELAY=1500
DALFOX_TIMEOUT=3600

# EZXSS_CALLBACK="https://your-ezxss.com/YOUR_PAYLOAD_ID"
# export EZXSS_CALLBACK

for t in katana gau dalfox timeout; do
    command -v "$t" >/dev/null 2>&1 || { echo "[-] Не найден: $t"; exit 1; }
done

[ -f "$TARGETS_FILE" ] || { echo "[-] Нет $TARGETS_FILE"; exit 1; }
touch "$HISTORY_FILE"

find "$OUT_ROOT" -mindepth 1 -maxdepth 1 -type d \
    ! -path "$OUT_DIR" -mtime +14 -exec rm -rf {} + 2>/dev/null || true

log() { echo "[$(date +%H:%M:%S)] $*"; }

log "[1/5] Katana (depth=$KATANA_DEPTH, rl=$KATANA_RL)..."
katana -list "$TARGETS_FILE" -d "$KATANA_DEPTH" -silent \
    -c "$KATANA_CONC" -p "$KATANA_PAR" -rl "$KATANA_RL" \
    -timeout 20 \
    -aff \
    -H "User-Agent: ..." \
    >> "$OUT_DIR/raw.txt" 2>/dev/null || true

log "[2/5] gau (threads=1, пауза до ${GAU_SLEEP}s)..."
while IFS= read -r target; do
    [[ -z "$target" || "$target" =~ ^[[:space:]]*# ]] && continue
    gau --threads 1 --timeout 20 "$target" >> "$OUT_DIR/raw.txt" 2>/dev/null || true
    sleep "$((RANDOM % GAU_SLEEP + 3))"
done < "$TARGETS_FILE"

grep -aE '^https?://' "$OUT_DIR/raw.txt" | sort -u > "$OUT_DIR/all_urls.txt" || true
log "[+] Всего URL: $(wc -l < "$OUT_DIR/all_urls.txt" | tr -d ' ')"

log "[3/5] Фильтр и дельта..."
grep -aE '\.(php|asp|aspx|jsp|do|action|cgi|pl|cfm)([?#]|$)|[?&][A-Za-z_][A-Za-z0-9_]*=' \
    "$OUT_DIR/all_urls.txt" \
  | grep -avE '\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|pdf|zip|gz)([?#]|$)' \
  | grep -avE '/(logout|signout|delete|remove)([?/]|$)' \
    > "$OUT_DIR/filtered.txt" || true

touch "$OUT_DIR/fresh.txt"
awk 'NR==FNR{h[$0]; next} !($0 in h)' \
    "$HISTORY_FILE" "$OUT_DIR/filtered.txt" \
    > "$OUT_DIR/fresh.txt"

NEW_COUNT=$(wc -l < "$OUT_DIR/fresh.txt" | tr -d ' ')
log "[+] Новых URL: $NEW_COUNT"

DALFOX_OK=0

if [ "$NEW_COUNT" -gt 0 ]; then
    log "[4/5] dalfox (worker=$DALFOX_WORKERS, delay=${DALFOX_DELAY}ms, timeout=${DALFOX_TIMEOUT}s)..."

    timeout "$DALFOX_TIMEOUT" dalfox file "$OUT_DIR/fresh.txt" \
        --worker "$DALFOX_WORKERS" \
        --delay "$DALFOX_DELAY" \
        --timeout 20 \
        --silence \
        --output "$OUT_DIR/dalfox.txt"
    DALFOX_RC=$?

    case "$DALFOX_RC" in
        0)
            DALFOX_OK=1
            log "[+] dalfox завершился успешно"
            ;;
        124)
            log "[!] dalfox убит по timeout ${DALFOX_TIMEOUT}s"
            ;;
        *)
            log "[!] dalfox упал (код $DALFOX_RC)"
            ;;
    esac
    # История обновляется ТОЛЬКО при успехе
    if [ "$DALFOX_OK" -eq 1 ]; then
        cat "$OUT_DIR/fresh.txt" >> "$HISTORY_FILE"
        sort -u "$HISTORY_FILE" -o "$HISTORY_FILE"
        log "[+] История обновлена (+$NEW_COUNT URL)"
    else
        log "[-] История НЕ обновлена. URL пересканируются в след. раз."
    fi
else
    log "[-] Новых URL нет, dalfox пропущен"
    touch "$OUT_DIR/dalfox.txt"
fi

log "[5/5] Результаты:"
if [ -s "$OUT_DIR/dalfox.txt" ]; then
    echo "-----------------------------------------"
    cat "$OUT_DIR/dalfox.txt"
    echo "-----------------------------------------"
    log "[!] Проверь URL вручную в браузере."
else
    log "[-] dalfox ничего не нашёл (или упал)."
fi

log "[✓] Готово. Артефакты: $OUT_DIR/"