#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

GH="$SCRIPT_DIR/gh"
BRANCH="master"
MOS_TOKEN="${AUTO_TOKEN:-}"
LIMIT="${1:-}"

echo "=========================================="
echo " Gemini + Latency Lab Checker v3.0"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="

# Venv
if [ ! -d "venv" ]; then
    echo "[*] Создание venv..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install -q requests pyyaml 2>/dev/null

# Запуск чекера
echo ""
echo "[*] Запуск чекера..."
echo "=========================================="
if [ -n "$LIMIT" ]; then
    python3 gemini_latency_checker.py --limit "$LIMIT"
else
    python3 gemini_latency_checker.py
fi

# Итоги
echo ""
echo "=========================================="
echo " ИТОГИ:"
echo "=========================================="
for f in subip.json subip.txt wl.txt all.txt gemini.txt; do
    if [ -f "$f" ] && [ -s "$f" ]; then
        echo "  $f  $(wc -l < "$f") строк"
    fi
done
echo "=========================================="

# Готовим git
echo ""
echo "[*] ПUSH..."

if [ ! -d ".git" ]; then
    git init
    git checkout -b "$BRANCH"
fi

FILES_TO_ADD=""
for f in subip.json subip.txt wl.txt all.txt gemini.txt; do
    if [ -f "$f" ] && [ -s "$f" ]; then
        FILES_TO_ADD="$FILES_TO_ADD $f"
    fi
done

if [ -z "$FILES_TO_ADD" ]; then
    echo "[*] Нет файлов с результатами, пуш пропущен"
else
    git add $FILES_TO_ADD .gitignore .github/

    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    if git diff --cached --quiet; then
        echo "[*] Нет изменений, пуш пропущен"
    else
        git commit -m "update: $TIMESTAMP"
        
        # hub.mos.ru
        if [ -n "$MOS_TOKEN" ]; then
            git remote set-url mos "https://$MOS_TOKEN@hub.mos.ru/kfwl/auto.git" 2>/dev/null || \
                git remote add mos "https://$MOS_TOKEN@hub.mos.ru/kfwl/auto.git" 2>/dev/null
            git push mos "$BRANCH" && echo "[+] ЗАПУШЕНО на hub.mos.ru!" || echo "[!] Ошибка пуша на hub.mos.ru"
        else
            echo "[!] AUTO_TOKEN не задан, пропускаю hub.mos.ru"
        fi
    fi
fi

echo ""
echo "=========================================="
echo " ВСЁ ГОТОВО!"
echo "=========================================="
