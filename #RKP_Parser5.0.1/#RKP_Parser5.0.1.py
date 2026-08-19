# =============================================================================
# ПАРСЕР КОНФИГУРАЦИЙ (VLESS/Trojan/Hysteria2) - RKP_Parser 5.0.1
# =============================================================================
# Данный скрипт предназначен для автоматического сбора, проверки и конвертации
# прокси-конфигураций из различных источников (HTTP-ссылки, Telegram-каналы).
# Основные этапы:
#   1. Загрузка настроек из config.json и config.py.
#   2. Загрузка конфигов из источников (sources.txt, tg.txt, my_configs.txt).
#   3. Извлечение конфигов из текста, декодирование base64/JSON/YAML/Happ.
#   4. Дедупликация и фильтрация по IP/SNI.
#   5. Проверка работоспособности через локальные ядра (Xray/Hysteria2).
#   6. Определение страны по IP (через API или MaxMind).
#   7. Конвертация в форматы Clash, Xray JSON, Sing-box.
#   8. Сохранение результатов в whitelist/blacklist и другие файлы.
#
# Структура файла:
#   - Импорты и глобальные настройки.
#   - Загрузка/сохранение настроек (config.json).
#   - Меню и пользовательский интерфейс.
#   - Вспомогательные функции (чистка текста, валидация, нормализация).
#   - Регулярные выражения для поиска конфигов.
#   - Дедупликация (по uuid+ip+port+sni).
#   - Конвертеры JSON/YAML -> URL-конфиги.
#   - Telegram-парсер (с использованием Telethon).
#   - HTTP-загрузчик (многопоточный).
#   - Фильтрация по IP и SNI (с whitelist/blacklist).
#   - Проверка конфигов (TCP pre-filter + Xray/Hysteria2).
#   - Определение страны через API или MaxMind DB.
#   - Генерация выходных форматов (Clash, Xray, Sing-box).
#   - Основной цикл парсера (run_parser).
#   - Инструменты (очистка, обновление ядер, фильтрация источников).
#   - Точка входа (main).
# =============================================================================

import asyncio
import aiohttp
import aiofiles
import os
import re
import sys
import json
import yaml
import base64
import subprocess
import time
import html
import urllib.parse
import socket
import threading
import random
import shutil
import tempfile
import platform
import zipfile
import signal
from pathlib import Path
from typing import Set, List, Tuple, Optional, Callable
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from urllib.parse import urlparse, parse_qs
from enum import Enum

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import httpx
except ImportError:
    httpx = None

# --- Блок импорта Telethon (для Telegram-парсинга) ---
# Если библиотека не установлена, функции Telegram будут отключены.
try:
    from telethon import TelegramClient
    from telethon.errors import FloodWaitError
    from telethon import connection
    HAS_TELEGRAM = True
except ImportError:
    HAS_TELEGRAM = False
    TelegramClient = None
    FloodWaitError = None
    connection = None

# --- Блок импорта MaxMind DB (для определения страны по IP) ---
try:
    import maxminddb
    HAS_MAXMIND = True
except ImportError:
    HAS_MAXMIND = False
    maxminddb = None

# Глобальный флаг для остановки по Ctrl+C
_stop_requested = False
__version__ = "5.0.1"  # <-- изменено с 5.0 на 5.0.1

# Обработчик сигналов для корректного завершения
def _handle_sigint(sig, frame):
    global _stop_requested
    _stop_requested = True
    _safe_print("\n[!] Получен сигнал остановки. Завершаем после текущей операции...")

signal.signal(signal.SIGINT, _handle_sigint)
signal.signal(signal.SIGTERM, _handle_sigint)

# --- Загрузка конфиденциальных данных из config.py (API_ID, API_HASH, прокси) ---
# Если файл отсутствует, Telegram-функции не будут работать.
try:
    from config import (
        API_ID,
        API_HASH,
        SESSION_NAME,
        TG_MTProto_SERVER,
        TG_MTProto_PORT,
        TG_MTProto_SECRET,
    )
    CONFIG_LOADED = True
except ImportError:
    API_ID = None
    API_HASH = None
    SESSION_NAME = "session"
    TG_MTProto_SERVER = None
    TG_MTProto_PORT = None
    TG_MTProto_SECRET = None
    CONFIG_LOADED = False

# ============================================================
# 1. ЗАГРУЗКА/СОХРАНЕНИЕ НАСТРОЕК (config.json)
# ============================================================
# Определение путей к файлам и директориям
CONFIG_FILE = "config.json"          # Основной файл настроек (переопределяет DEFAULT_CONFIG)
SOURCES_DIR = "sources"              # Папка для файлов-источников (sources.txt, tg.txt, my_configs.txt, ip_list.txt, sni_list.txt)
CONFIGS_DIR = "configs"              # Папка для готовых конфигураций в разных форматах
CORES_DIR = "cores"                  # Папка для бинарных файлов ядер (Xray, Hysteria2)
TEMP_DIR = "temp"                    # Временная папка для промежуточных файлов
BACKUPS_DIR = "backups"              # Папка для бэкапов (например, источников)

GENERIC_DIR = os.path.join(CONFIGS_DIR, "generic")  # для общих файлов (whitelist, blacklist)
CLASH_DIR = os.path.join(CONFIGS_DIR, "clash")      # Clash конфигурации (YAML)
XRAY_DIR = os.path.join(CONFIGS_DIR, "xray")        # Xray JSON
SINGBOX_DIR = os.path.join(CONFIGS_DIR, "sing-box") # Sing-box JSON

# MaxMind DB (страны) — скачивается автоматически при первом использовании
MAXMIND_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
MAXMIND_DB_PATH = os.path.join(TEMP_DIR, "GeoLite2-Country.mmdb")
_maxmind_reader = None

# Создание всех необходимых директорий
def _ensure_dirs():
    for d in (TEMP_DIR, SOURCES_DIR, CORES_DIR, GENERIC_DIR, CLASH_DIR, XRAY_DIR, SINGBOX_DIR, BACKUPS_DIR):
        Path(d).mkdir(parents=True, exist_ok=True)
    Path(TELEGRAM_DOWNLOAD_DIR).mkdir(parents=True, exist_ok=True)

# Значения настроек по умолчанию (будут перезаписаны из config.json)
DEFAULT_CONFIG = {
    "verbose": True,                     # Подробный вывод в консоль
    "cycles": 0,                         # Количество полных циклов (0 - бесконечно)
    "single_cycle": False,               # Режим одиночного цикла (для теста)
    "rest_time": 30,                     # Пауза между циклами (в минутах, 0 - без паузы)
    "import_whitelist": True,            # Импортировать whitelist в начало configs.txt
    "import_blacklist": True,            # Импортировать blacklist в начало configs.txt
    "use_telegram": False,               # Включить парсинг Telegram-каналов
    "use_mtproto": True,                 # Использовать MTProto прокси (если задан в config.py)
    "save_vless_tg": True,               # Сохранять VLESS из Telegram
    "save_trojan_tg": True,              # Сохранять Trojan из Telegram
    "save_hy2_tg": True,                 # Сохранять Hysteria2 из Telegram
    "download_files_tg": True,           # Скачивать прикреплённые файлы из Telegram
    "decrypt_happ_tg": True,             # Расшифровывать Happ-ссылки в Telegram
    "save_sources_tg": True,             # Искать новые источники (URL) в сообщениях Telegram
    "decode_base64_tg": True,            # Декодировать base64 в сообщениях Telegram
    "decode_json_tg": True,              # Конвертировать JSON-конфиги в Telegram
    "decode_yaml_tg": True,              # Конвертировать YAML (Sing-box) в Telegram
    "tg_messages_limit": 1000,           # Максимальное количество сообщений на канал
    "load_sources": True,                # Загружать источники из sources.txt (HTTP)
    "http_threads": 50,                  # Количество потоков для HTTP-загрузки
    "save_vless_http": True,             # Сохранять VLESS из HTTP-источников
    "save_trojan_http": True,            # Сохранять Trojan из HTTP-источников
    "save_hy2_http": True,               # Сохранять Hysteria2 из HTTP-источников
    "decrypt_happ_http": True,           # Расшифровывать Happ-ссылки в HTTP-источниках
    "decode_base64_http": True,          # Декодировать base64 в HTTP-источниках
    "decode_json_http": True,            # Конвертировать JSON в HTTP-источниках
    "decode_yaml_http": True,            # Конвертировать YAML в HTTP-источниках
    "filter_sources": True,              # Фильтровать источники: оставлять только те, где есть конфиги
    "fix_github_urls": True,             # Исправлять ссылки raw.githubusercontent.com с коммитами на main/master
    "save_failed_sources": True,         # Сохранять неудачные источники в blacklist_sources.txt
    "use_dedup": True,                   # Включить дедупликацию конфигов
    "dedup_by_sni": True,                # Дедупликация по uuid+ip+port+sni (если False — только uuid+ip+port)
    "sort_grpc_xhttp_top": True,         # Помещать конфиги с типом grpc/xhttp в начало белого списка
    "sort_unsafe_bottom": True,          # Помещать небезопасные (без TLS/Reality) вниз белого списка
    "filter_ip": True,                   # Фильтровать конфиги по IP (из ip_list.txt)
    "filter_sni": True,                  # Фильтровать конфиги по SNI (из sni_list.txt)
    "filter_others": True,               # Остальные конфиги (не прошедшие IP/SNI) отправлять в чёрный список
    "check_timeout": 12,                 # Таймаут проверки конфига (сек)
    "check_threads": 80,                 # Количество потоков для проверки конфигов
    "country_threads": 20,               # Потоков для определения страны
    "check_whitelist": True,             # Проверять белый список (wl_filtered.txt) -> whitelist
    "check_blacklist": True,             # Проверять чёрный список (bl_filtered.txt) -> blacklist
    "check_via_xray": True,              # Использовать Xray для проверки (если False, только TCP + Hysteria2)
    "tcp_check": False,                  # Быстрый TCP pre-filter (проверка доступности host:port)
    "save_garbage": True,                # Сохранять нерабочие конфиги в garbage_conf.txt
    "determine_country": True,           # Определять страну для рабочих конфигов
    "use_maxmind_country": False,        # Использовать MaxMind DB вместо API (быстрее, но требуется загрузка БД)
    "encode_names": True,                # Кодировать названия (URL-encode) в тегах
    "save_clash": True,                  # Генерировать Clash YAML
    "save_xray": True,                   # Генерировать Xray JSON
    "save_singbox": True,                # Генерировать Sing-box JSON
}

def load_config():
    """Загружает пользовательские настройки из config.json, дополняя значениями по умолчанию."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
                config = DEFAULT_CONFIG.copy()
                config.update(user_config)
                return config
        except:
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()

def save_config(config):
    """Сохраняет текущие настройки в config.json."""
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4, ensure_ascii=False)

# ============================================================
# 2. МЕНЮ
# ============================================================
# Функции для отображения меню и взаимодействия с пользователем.
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title):
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

def show_main_menu():
    _show_banner()
    print_header("ГЛАВНОЕ МЕНЮ")
    print("1. Запуск парсера")
    print("2. Одиночный цикл (тест)")
    print("3. Настройки парсера")
    print("4. Инструменты")
    print("5. Выход")
    print("="*60)
    choice = input("Выберите пункт (1-5): ").strip()
    return choice

def _show_banner():
    """Показывает баннер из файла sources/banner.txt, если существует."""
    banner_path = os.path.join(SOURCES_DIR, "banner.txt")
    if os.path.exists(banner_path):
        try:
            with open(banner_path, 'r', encoding='utf-8') as f:
                banner = f.read()
            if banner.strip():
                print(banner.format(version=__version__))
        except Exception:
            pass

# Описание групп настроек для меню (используется в show_settings_menu)
_SETTINGS_GROUPS = [
    ("ОСНОВНЫЕ", [
        ("verbose", "Подробный вывод (verbose)", "bool"),
        ("cycles", "Полные циклы (0-бесконечно)", "int", 0, 999),
        ("single_cycle", "Одиночный цикл (для теста)", "bool"),
        ("rest_time", "Отдых между циклами (мин, 0-выкл)", "int", 0, 600),
    ]),
    ("ЗАГРУЗКА ИСТОЧНИКОВ", [
        ("load_sources", "Скачивать источники из sources.txt", "bool"),
        ("http_threads", "Потоков загрузки (1-100)", "int", 1, 100),
        ("filter_sources", "Фильтр: только источники с конфигами", "bool"),
        ("fix_github_urls", "Исправлять GitHub коммит → main/master", "bool"),
        ("save_vless_http", "Сохранять VLESS из источников", "bool"),
        ("save_trojan_http", "Сохранять TROJAN из источников", "bool"),
        ("save_hy2_http", "Сохранять HY2 из источников", "bool"),
        ("decrypt_happ_http", "Расшифровка Happ из источников", "bool"),
        ("decode_base64_http", "Декодировать base64", "bool"),
        ("decode_json_http", "Конвертировать JSON", "bool"),
        ("decode_yaml_http", "Конвертировать Sing-Box YAML", "bool"),
        ("save_failed_sources", "Чёрный список неудачных источников", "bool"),
    ]),
    ("TELEGRAM", [
        ("use_telegram", "Использовать Telegram", "bool"),
        ("use_mtproto", "MTProto прокси", "bool"),
        ("save_vless_tg", "VLESS из Telegram", "bool"),
        ("save_trojan_tg", "TROJAN из Telegram", "bool"),
        ("save_hy2_tg", "HY2 из Telegram", "bool"),
        ("decode_base64_tg", "Декодировать base64", "bool"),
        ("decode_json_tg", "Конвертировать JSON", "bool"),
        ("decode_yaml_tg", "Конвертировать YAML", "bool"),
        ("download_files_tg", "Скачивать файлы", "bool"),
        ("decrypt_happ_tg", "Расшифровка Happ", "bool"),
        ("save_sources_tg", "Искать источники", "bool"),
        ("tg_messages_limit", "Лимит сообщений (100-20000)", "int", 100, 20000),
    ]),
    ("ДЕДУПЛИКАЦИЯ И СОРТИРОВКА", [
        ("use_dedup", "Дедупликация конфигов", "bool"),
        ("dedup_by_sni", "Дедуплицировать по uuid+ip+port+sni", "bool"),
        ("sort_grpc_xhttp_top", "GRPC/XHTTP в начало белого списка", "bool"),
        ("sort_unsafe_bottom", "Небезопасные конфиги вниз", "bool"),
    ]),
    ("ФИЛЬТРАЦИЯ ПО IP/SNI", [
        ("filter_ip", "Фильтр по IP", "bool"),
        ("filter_sni", "Фильтр по SNI", "bool"),
        ("filter_others", "Остальные в чёрный список", "bool"),
        ("import_whitelist", "Импорт whitelist в configs.txt", "bool"),
        ("import_blacklist", "Импорт blacklist в configs.txt", "bool"),
    ]),
    ("ПРОВЕРКА КОНФИГОВ", [
        ("check_whitelist", "Проверять белый список", "bool"),
        ("check_blacklist", "Проверять чёрный список", "bool"),
        ("check_via_xray", "Проверка через Xray (vless/trojan)", "bool"),
        ("tcp_check", "TCP pre-filter (fast host:port check)", "bool"),
        ("check_timeout", "Таймаут проверки (5-15 сек)", "int", 5, 15),
        ("check_threads", "Потоков проверки (10-150)", "int", 10, 150),
        ("save_garbage", "Сохранять нерабочие в garbage", "bool"),
    ]),
    ("ОПРЕДЕЛЕНИЕ СТРАНЫ", [
        ("determine_country", "Определять страну", "bool"),
        ("use_maxmind_country", "Использовать MaxMind DB (вместо API)", "bool"),
        ("country_threads", "Потоков (1-50)", "int", 1, 50),
        ("encode_names", "Кодировать названия", "bool"),
    ]),
    ("ФОРМАТЫ ВЫВОДА", [
        ("save_clash", "Конвертировать в Clash", "bool"),
        ("save_xray", "Конвертировать в Xray JSON", "bool"),
        ("save_singbox", "Конвертировать в Sing-box", "bool"),
    ]),
]

def show_settings_menu(config):
    """Интерактивное меню для изменения настроек."""
    while True:
        clear_screen()
        print_header("НАСТРОЙКИ ПАРСЕРА")
        num = 0
        for group_name, items in _SETTINGS_GROUPS:
            print(f"\n── {group_name} ──")
            for key, label, typ, *args in items:
                val = config.get(key)
                if typ == "bool":
                    display = "Да" if val else "Нет"
                elif typ == "int":
                    display = str(val) if val != 0 else "∞" if "бесконечно" in label else str(val)
                else:
                    display = str(val)
                print(f"  {num}. {label} | {display}")
                num += 1
        print(f"\nВсего: {num} настроек. Введите номер для изменения, 'q' для выхода:")
        choice = input("-> ").strip()
        if choice.lower() == 'q':
            save_config(config)
            break
        if choice.isdigit():
            idx = int(choice)
            flat = []
            for group_name, items in _SETTINGS_GROUPS:
                for item in items:
                    flat.append(item)
            if 0 <= idx < len(flat):
                edit_setting(config, flat[idx])
            else:
                print("Неверный номер.")
                input("Нажмите Enter...")
        else:
            print("Неверный ввод.")
            input("Нажмите Enter...")

def edit_setting(config, item):
    """Редактирует одну настройку (bool или int)."""
    key, label, typ, *args = item
    if typ == "bool":
        current = config.get(key, True)
        new_val = input(f"Введите 'y' для включения, 'n' для выключения (текущее: {'Да' if current else 'Нет'}): ").strip().lower()
        if new_val in ('y', 'yes', 'да'):
            config[key] = True
        elif new_val in ('n', 'no', 'нет'):
            config[key] = False
        else:
            print("Неверный ввод.")
            input("Нажмите Enter...")
            return
    elif typ == "int":
        lo, hi = args[0], args[1]
        val = input(f"Введите значение ({lo}-{hi}, текущее: {config.get(key, lo)}): ").strip()
        if val.isdigit() and lo <= int(val) <= hi:
            config[key] = int(val)
        else:
            print(f"Некорректное значение. Допустимо {lo}-{hi}.")
            input("Нажмите Enter...")
            return
    print("Настройка сохранена.")
    input("Нажмите Enter...")

# ============================================================
# 3. ОБЩИЕ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================
# Эти функции используются повсеместно для обработки строк, проверки форматов и т.д.
def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)

def clean_text(text: str) -> str:
    """Удаляет невидимые символы и HTML-сущности из текста."""
    if not text:
        return ""
    text = text.replace('\ufeff', '').replace('\u200b', '')
    text = html.unescape(text)
    return text

def is_valid_config(url: str) -> bool:
    """Проверяет, что строка выглядит как валидный конфиг (vless/trojan/hy2)."""
    url = url.strip()
    if url.startswith("vless://"):
        return "@" in url and UUID_REGEX.search(url)
    if url.startswith("trojan://"):
        return "@" in url
    if url.startswith(("hysteria2://", "hy2://")):
        return "@" in url
    return False

def normalize_config(url: str) -> str:
    """Нормализует URL конфига: удаляет фрагмент (#), сортирует параметры запроса."""
    try:
        if "#" in url:
            url = url.split("#", 1)[0]
        if "?" in url:
            base, query = url.split("?", 1)
            params = {}
            for p in query.split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    params[k] = v
                else:
                    params[p] = ""
            sorted_params = sorted(params.items())
            new_query = "&".join(f"{k}={v}" for k, v in sorted_params)
            url = f"{base}?{new_query}"
        return url
    except:
        return url

def ensure_hash_suffix(url: str) -> str:
    """Гарантирует, что в конце URL есть символ '#' (для добавления тега)."""
    url = url.strip()
    if not url.endswith('#'):
        url += '#'
    return url

def normalize_source(url: str) -> str:
    """Нормализует URL источника (сортирует параметры запроса)."""
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        sorted_params = sorted(params.items())
        new_query = urllib.parse.urlencode(sorted_params, doseq=True)
        new_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, ""
        ))
        return new_url
    except:
        return url

# ============================================================
# 4. РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ
# ============================================================
# Шаблоны для поиска различных типов конфигов и служебных данных.
VLESS_REGEX = re.compile(r"vless://[^\s#]+", re.IGNORECASE)
TROJAN_REGEX = re.compile(r"trojan://[^\s#]+", re.IGNORECASE)
HY2_REGEX = re.compile(r"(?:hysteria2|hy2)://[^\s#]+", re.IGNORECASE)
URL_REGEX = re.compile(r'https?://[^\s<>"\'(){}|\\^`\[\]]+', re.IGNORECASE)
HAPP_REGEX = re.compile(r"happ://crypt[0-9]*/[A-Za-z0-9+/=]+", re.IGNORECASE)
BASE64_REGEX = re.compile(r'^[A-Za-z0-9+/]+=*$', re.MULTILINE)
UUID_REGEX = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')

# ============================================================
# 5. ДЕДУПЛИКАЦИЯ
# ============================================================
# Удаление дубликатов конфигов на основе ключевых полей.
VLESS_REGEX_DEDUP = re.compile(r"vless://([^@]+)@([^:]+):(\d+)", re.IGNORECASE)
TROJAN_REGEX_DEDUP = re.compile(r"trojan://([^@]+)@([^:]+):(\d+)", re.IGNORECASE)
HY2_REGEX_DEDUP = re.compile(r"(?:hysteria2|hy2)://(?:([^@]+)@)?([^:]+):(\d+)", re.IGNORECASE)

def extract_sni_from_url(url: str) -> str:
    """Извлекает параметр sni или host из URL конфига."""
    m = re.search(r'[?&](?:sni|host)=([^&#]+)', url, re.IGNORECASE)
    if m:
        return urllib.parse.unquote(m.group(1))
    return ""

def extract_vless_key(url: str) -> Optional[Tuple[str, str, int, str]]:
    """Извлекает (uuid, host, port, sni) из VLESS-конфига."""
    match = VLESS_REGEX_DEDUP.search(url)
    if not match:
        return None
    uuid = match.group(1)
    host = match.group(2)
    port = int(match.group(3))
    sni = extract_sni_from_url(url)
    return (uuid, host, port, sni)

def extract_trojan_key(url: str) -> Optional[Tuple[str, str, int, str]]:
    """Извлекает (password, host, port, sni) из Trojan-конфига."""
    match = TROJAN_REGEX_DEDUP.search(url)
    if not match:
        return None
    password = urllib.parse.unquote(match.group(1))
    host = match.group(2)
    port = int(match.group(3))
    sni = extract_sni_from_url(url)
    return (password, host, port, sni)

def extract_hy2_key(url: str) -> Optional[Tuple[str, str, int, str]]:
    """Извлекает (auth, host, port, sni) из Hysteria2-конфига."""
    match = HY2_REGEX_DEDUP.search(url)
    if not match:
        return None
    auth = urllib.parse.unquote(match.group(1)) if match.group(1) else ""
    host = match.group(2)
    port = int(match.group(3))
    sni = extract_sni_from_url(url)
    return (auth, host, port, sni)

def get_config_key(url: str) -> Optional[Tuple[str, str, str, int, str]]:
    """Возвращает универсальный ключ для дедупликации: (тип, id, host, port, sni)."""
    if url.startswith("vless://"):
        key = extract_vless_key(url)
        if key:
            return ("vless", key[0], key[1], key[2], key[3])
    elif url.startswith("trojan://"):
        key = extract_trojan_key(url)
        if key:
            return ("trojan", key[0], key[1], key[2], key[3])
    elif url.startswith(("hysteria2://", "hy2://")):
        key = extract_hy2_key(url)
        if key:
            return ("hy2", key[0], key[1], key[2], key[3])
    return None

def deduplicate_configs(input_file: str, output_file: str) -> int:
    """Читает конфиги из input_file, удаляет дубликаты по ключу, записывает в output_file.
       Возвращает количество уникальных конфигов."""
    if not os.path.exists(input_file):
        print(f"Файл {input_file} не найден для дедупликации.")
        return 0
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        configs = [line.strip() for line in f if line.strip()]
    if not configs:
        return 0
    seen_keys: Set[Tuple[str, str, str, int, str]] = set()
    unique = []
    for cfg in configs:
        key = get_config_key(cfg)
        if key is None:
            continue
        if key not in seen_keys:
            seen_keys.add(key)
            unique.append(cfg)
    with open(output_file, 'w', encoding='utf-8') as f:
        for cfg in unique:
            f.write(cfg + '\n')
    print(f"Дедупликация по uuid+ip+port+sni: {input_file} -> {output_file}, {len(unique)} уникальных (удалено {len(configs)-len(unique)})")
    return len(unique)

# ============================================================
# 6. КОНВЕРТЕРЫ JSON/YAML
# ============================================================
# Функции для преобразования структурированных форматов (JSON, YAML) в URL-конфиги.
def safe_quote(s: str) -> str:
    """URL-кодирование строки."""
    return urllib.parse.quote(s, safe='')

def build_query(params: dict) -> str:
    """Строит строку запроса из словаря параметров, кодируя значения."""
    parts = []
    for k, v in params.items():
        if v is None or v == '':
            continue
        if isinstance(v, bool):
            v = 'true' if v else 'false'
        parts.append(f"{k}={safe_quote(str(v))}")
    return '&'.join(parts)

def outbound_to_vless_url(out: dict) -> Optional[str]:
    """Преобразует outbound Xray JSON (протокол vless) в URL vless://."""
    settings = out.get('settings', {})
    vnext = settings.get('vnext', [])
    if not vnext:
        return None
    first = vnext[0]
    address = first.get('address')
    port = first.get('port')
    users = first.get('users', [])
    if not users:
        return None
    user = users[0]
    uuid = user.get('id')
    if not uuid:
        return None
    encryption = user.get('encryption', 'none')
    flow = user.get('flow', '')
    stream = out.get('streamSettings', {})
    network = stream.get('network', 'tcp')
    security = stream.get('security', '')
    reality = stream.get('realitySettings', {})
    tls = stream.get('tlsSettings', {})
    ws = stream.get('wsSettings', {})
    grpc = stream.get('grpcSettings', {})
    http = stream.get('httpSettings', {})
    params = {}
    if encryption:
        params['encryption'] = encryption
    if network:
        params['type'] = network
    if flow:
        params['flow'] = flow
    if security == 'reality':
        params['security'] = 'reality'
        if 'serverName' in reality:
            params['sni'] = reality['serverName']
        if 'publicKey' in reality:
            params['pbk'] = reality['publicKey']
        if 'shortId' in reality:
            params['sid'] = reality['shortId']
        if 'fingerprint' in reality:
            params['fp'] = reality['fingerprint']
    elif security == 'tls':
        params['security'] = 'tls'
        if 'serverName' in tls:
            params['sni'] = tls['serverName']
        if 'allowInsecure' in tls:
            params['allowInsecure'] = '1' if tls['allowInsecure'] else '0'
        if 'fingerprint' in tls:
            params['fp'] = tls['fingerprint']
        if 'alpn' in tls:
            params['alpn'] = ','.join(tls['alpn'])
    if network == 'ws' and ws:
        if 'path' in ws:
            params['path'] = safe_quote(ws['path'])
        if 'headers' in ws and 'Host' in ws['headers']:
            params['host'] = ws['headers']['Host']
    elif network == 'grpc' and grpc:
        if 'serviceName' in grpc:
            params['serviceName'] = safe_quote(grpc['serviceName'])
    elif network in ('xhttp', 'splithttp') and 'xhttpSettings' in stream:
        xhttp = stream.get('xhttpSettings', {})
        if 'path' in xhttp:
            params['path'] = safe_quote(xhttp['path'])
        if 'host' in xhttp:
            params['host'] = xhttp['host']
    elif network in ('h2', 'http2') and http:
        if 'path' in http:
            params['path'] = safe_quote(http['path'])
        if 'host' in http:
            params['host'] = ','.join(http['host']) if isinstance(http['host'], list) else http['host']
    if params.get('security') == 'reality':
        if 'alpn' not in params:
            params['alpn'] = urllib.parse.quote('http/1.1')
    params = {k: v for k, v in params.items() if v not in (None, '')}
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    return f"vless://{uuid}@{address}:{port}?{query}{remark}"

def outbound_to_trojan_url(out: dict) -> Optional[str]:
    """Преобразует outbound Xray JSON (протокол trojan) в URL trojan://."""
    settings = out.get('settings', {})
    servers = settings.get('servers', [])
    if not servers:
        return None
    s = servers[0]
    address = s.get('address')
    port = s.get('port')
    password = s.get('password')
    if not all([address, port, password]):
        return None
    stream = out.get('streamSettings', {})
    security = stream.get('security', 'tls')
    tls = stream.get('tlsSettings', {})
    ws = stream.get('wsSettings', {})
    grpc = stream.get('grpcSettings', {})
    params = {}
    if security == 'tls':
        if 'serverName' in tls:
            params['sni'] = tls['serverName']
        if 'allowInsecure' in tls:
            params['allowInsecure'] = '1' if tls['allowInsecure'] else '0'
        if 'fingerprint' in tls:
            params['fp'] = tls['fingerprint']
        if 'alpn' in tls:
            params['alpn'] = ','.join(tls['alpn'])
    network = stream.get('network', 'tcp')
    if network != 'tcp':
        params['type'] = network
        if network == 'ws' and ws:
            if 'path' in ws:
                params['path'] = safe_quote(ws['path'])
            if 'headers' in ws and 'Host' in ws['headers']:
                params['host'] = ws['headers']['Host']
        elif network == 'grpc' and grpc:
            if 'serviceName' in grpc:
                params['serviceName'] = safe_quote(grpc['serviceName'])
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    base = f"trojan://{password}@{address}:{port}"
    if query:
        base += f"?{query}"
    return base + remark

def outbound_to_hysteria2_url(out: dict) -> Optional[str]:
    """Преобразует outbound Xray JSON (протокол hysteria2) в URL hy2://."""
    settings = out.get('settings', {})
    servers = settings.get('servers', [])
    if not servers:
        return None
    s = servers[0]
    address = s.get('address')
    port = s.get('port')
    auth = s.get('auth', '')
    if not address or not port:
        return None
    stream = out.get('streamSettings', {})
    security = stream.get('security', 'tls')
    tls = stream.get('tlsSettings', {})
    params = {}
    if security == 'tls':
        if 'serverName' in tls:
            params['sni'] = tls['serverName']
        if 'allowInsecure' in tls:
            params['insecure'] = '1' if tls['allowInsecure'] else '0'
        if 'alpn' in tls:
            params['alpn'] = ','.join(tls['alpn'])
    transport = stream.get('transport', {})
    if 'hopConfig' in transport:
        hop = transport['hopConfig']
        if hop.get('obfs') == 'salamander' and hop.get('password'):
            params['obfs-password'] = hop['password']
            params['obfs'] = 'salamander'
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    auth_part = f"{auth}@" if auth else ''
    return f"hy2://{auth_part}{address}:{port}?{query}{remark}"

def yaml_proxy_to_vless_url(proxy: dict) -> Optional[str]:
    """Преобразует прокси из YAML (Sing-box/Clash) в vless:// URL."""
    name = proxy.get('name', '')
    server = proxy.get('server')
    port = proxy.get('port')
    uuid = proxy.get('uuid')
    if not all([server, port, uuid]):
        return None
    params = {'encryption': 'none', 'type': proxy.get('network', 'tcp')}
    if proxy.get('flow'):
        params['flow'] = proxy['flow']
    tls = proxy.get('tls', False)
    reality_opts = proxy.get('reality-opts', {})
    if reality_opts:
        params['security'] = 'reality'
        if 'public-key' in reality_opts:
            params['pbk'] = reality_opts['public-key']
        if 'short-id' in reality_opts and reality_opts['short-id']:
            params['sid'] = reality_opts['short-id']
    elif tls:
        params['security'] = 'tls'
    sni = proxy.get('servername')
    if sni:
        params['sni'] = sni
    fp = proxy.get('client-fingerprint')
    if fp:
        params['fp'] = fp
    network = proxy.get('network', 'tcp')
    if network == 'grpc':
        grpc_opts = proxy.get('grpc-opts', {})
        if 'grpc-service-name' in grpc_opts:
            params['serviceName'] = grpc_opts['grpc-service-name']
    elif network in ('ws', 'websocket'):
        ws_opts = proxy.get('ws-opts', {})
        if 'path' in ws_opts:
            params['path'] = safe_quote(ws_opts['path'])
        if 'headers' in ws_opts and 'Host' in ws_opts['headers']:
            params['host'] = ws_opts['headers']['Host']
    if params.get('security') == 'reality':
        if 'alpn' not in params:
            params['alpn'] = urllib.parse.quote('http/1.1')
    params = {k: v for k, v in params.items() if v not in (None, '')}
    query = build_query(params)
    remark = f"#{safe_quote(name)}" if name else ''
    return f"vless://{uuid}@{server}:{port}?{query}{remark}"

def yaml_proxy_to_trojan_url(proxy: dict) -> Optional[str]:
    """Преобразует прокси из YAML в trojan:// URL."""
    name = proxy.get('name', '')
    server = proxy.get('server')
    port = proxy.get('port')
    password = proxy.get('password')
    if not all([server, port, password]):
        return None
    params = {}
    sni = proxy.get('servername')
    if sni:
        params['sni'] = sni
    tls = proxy.get('tls', False)
    if tls:
        params['security'] = 'tls'
    fp = proxy.get('client-fingerprint')
    if fp:
        params['fp'] = fp
    query = build_query(params)
    remark = f"#{safe_quote(name)}" if name else ''
    base = f"trojan://{password}@{server}:{port}"
    if query:
        base += f"?{query}"
    return base + remark

def yaml_proxy_to_hysteria2_url(proxy: dict) -> Optional[str]:
    """Преобразует прокси из YAML в hy2:// URL."""
    name = proxy.get('name', '')
    server = proxy.get('server')
    port = proxy.get('port')
    auth = proxy.get('auth', '')
    if not all([server, port]):
        return None
    params = {}
    sni = proxy.get('servername')
    if sni:
        params['sni'] = sni
    tls = proxy.get('tls', False)
    if tls:
        params['insecure'] = '0'
    query = build_query(params)
    remark = f"#{safe_quote(name)}" if name else ''
    auth_part = f"{auth}@" if auth else ''
    return f"hy2://{auth_part}{server}:{port}?{query}{remark}"

def convert_json_to_urls(content: str) -> List[str]:
    """Извлекает конфиги из JSON (Xray или список outbounds)."""
    urls = []
    try:
        decoder = json.JSONDecoder()
        idx = 0
        content = content.strip()
        while idx < len(content):
            try:
                obj, end = decoder.raw_decode(content, idx)
                idx = end
                while idx < len(content) and content[idx] in ' \t\n\r':
                    idx += 1
                outbounds = None
                if isinstance(obj, dict):
                    outbounds = obj.get('outbounds')
                    if outbounds is None and 'config' in obj:
                        outbounds = obj['config'].get('outbounds')
                elif isinstance(obj, list):
                    outbounds = obj
                if not outbounds or not isinstance(outbounds, list):
                    continue
                for out in outbounds:
                    if not isinstance(out, dict):
                        continue
                    protocol = out.get('protocol', '')
                    if protocol == 'vless':
                        url = outbound_to_vless_url(out)
                        if url and is_valid_config(url):
                            urls.append(url)
                    elif protocol == 'trojan':
                        url = outbound_to_trojan_url(out)
                        if url and is_valid_config(url):
                            urls.append(url)
                    elif protocol in ('hysteria2', 'hy2'):
                        url = outbound_to_hysteria2_url(out)
                        if url and is_valid_config(url):
                            urls.append(url)
            except json.JSONDecodeError:
                break
    except Exception:
        pass
    return urls

def convert_yaml_to_urls(content: str) -> List[str]:
    """Извлекает конфиги из YAML (обычно Sing-box/Clash)."""
    urls = []
    try:
        data = yaml.safe_load(content)
        if not data or not isinstance(data, dict):
            return []
        proxies = data.get('proxies', [])
        if not isinstance(proxies, list):
            return []
        for proxy in proxies:
            ptype = proxy.get('type')
            if ptype == 'vless':
                url = yaml_proxy_to_vless_url(proxy)
            elif ptype == 'trojan':
                url = yaml_proxy_to_trojan_url(proxy)
            elif ptype in ('hysteria2', 'hy2'):
                url = yaml_proxy_to_hysteria2_url(proxy)
            else:
                continue
            if url and is_valid_config(url):
                urls.append(url)
    except Exception:
        pass
    return urls

def decode_base64_content(content: str) -> Tuple[Optional[str], List[str]]:
    """Декодирует base64, возвращает (раскодированный_текст, список найденных конфигов)."""
    try:
        content = content.strip()
        if not BASE64_REGEX.match(content.replace('\n', '').replace('\r', '')):
            return None, []
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        matches = []
        matches.extend(VLESS_REGEX.findall(decoded))
        matches.extend(TROJAN_REGEX.findall(decoded))
        matches.extend(HY2_REGEX.findall(decoded))
        # Рекурсивная попытка, если внутри снова base64
        if len(decoded) > 100 and BASE64_REGEX.match(decoded.replace('\n', '').replace('\r', '')):
            deeper = decode_base64_content(decoded)
            if deeper[1]:
                matches.extend(deeper[1])
        return decoded, matches
    except:
        return None, []

async def decrypt_happ_url(happ_url: str) -> Optional[str]:
    """Расшифровывает Happ-ссылку, используя внешний модуль helpers.crypt.happdecrypt."""
    try:
        from helpers.crypt.happdecrypt import decrypt_and_extract_url
        return await decrypt_and_extract_url(happ_url)
    except Exception:
        return None

# ============================================================
# 7. TELEGRAM-ПАРСЕР
# ============================================================
# Класс для работы с Telegram через Telethon.
class TelegramFloodError(Exception):
    pass

class TelegramParser:
    def __init__(self, api_id: int, api_hash: str, session_name: str, config: dict):
        self.api_id = api_id
        self.api_hash = api_hash
        self.session_name = session_name
        self.config = config
        self.client: Optional[TelegramClient] = None
        self.connected = False
        self.retry_count = 0
        self.downloaded_ids = self._load_downloaded_ids()

    def _load_downloaded_ids(self) -> Set[str]:
        """Загружает ID ранее скачанных файлов, чтобы не качать повторно."""
        ids = set()
        if os.path.exists(DOWNLOADED_IDS_FILE):
            try:
                with open(DOWNLOADED_IDS_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        ids.add(line.strip())
            except:
                pass
        return ids

    def _save_downloaded_id(self, identifier: str):
        """Сохраняет ID скачанного файла."""
        with open(DOWNLOADED_IDS_FILE, 'a', encoding='utf-8') as f:
            f.write(identifier + '\n')
        self.downloaded_ids.add(identifier)

    async def connect_with_retry(self) -> bool:
        """Подключается к Telegram с повторами, используя MTProto прокси при наличии."""
        if not self.config["use_mtproto"] or TG_MTProto_SERVER is None:
            try:
                self.client = TelegramClient(self.session_name, self.api_id, self.api_hash)
                await asyncio.wait_for(self.client.start(), timeout=CONNECT_TIMEOUT)
                self.connected = True
                me = await self.client.get_me()
                print(f"Подключен без прокси как: {me.first_name}")
                return True
            except Exception as e:
                print(f"Ошибка подключения без прокси: {e}")
                return False

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self.client = TelegramClient(
                    self.session_name,
                    self.api_id,
                    self.api_hash,
                    connection=connection.ConnectionTcpMTProxyIntermediate,
                    proxy=(TG_MTProto_SERVER, TG_MTProto_PORT, TG_MTProto_SECRET)
                )
                await asyncio.wait_for(self.client.start(), timeout=CONNECT_TIMEOUT)
                self.connected = True
                me = await self.client.get_me()
                print(f"Подключен аккаунт: {me.first_name}")
                self.retry_count = 0
                return True
            except asyncio.TimeoutError:
                print(f"Таймаут подключения (попытка {attempt})")
                if attempt == MAX_RETRIES:
                    print("Пробую без прокси...")
                    try:
                        self.client = TelegramClient(self.session_name, self.api_id, self.api_hash)
                        await asyncio.wait_for(self.client.start(), timeout=CONNECT_TIMEOUT)
                        self.connected = True
                        me = await self.client.get_me()
                        print(f"Подключен без прокси как: {me.first_name}")
                        return True
                    except Exception as e2:
                        print(f"Ошибка без прокси: {e2}")
                        return False
                await asyncio.sleep(2)
            except Exception as e:
                print(f"Ошибка подключения: {e} (попытка {attempt})")
                if attempt == MAX_RETRIES:
                    return False
                await asyncio.sleep(2)
        return False

    async def disconnect(self):
        """Отключает клиент Telegram."""
        if self.client:
            try:
                await self.client.disconnect()
                await asyncio.sleep(0.5)
            except Exception as e:
                print(f"Ошибка при отключении: {e}")
            finally:
                self.connected = False
                self.client = None
                print("Отключено от Telegram")

    async def parse_channel(self, channel_link: str, channel_num: int, total_channels: int, limit: int) -> dict:
        """Парсит один Telegram-канал, извлекает конфиги, файлы, источники.
           Возвращает словарь с найденными данными и статистикой."""
        result = {
            'vless': set(),
            'trojan': set(),
            'hy2': set(),
            'sources': set(),
            'downloaded_files': [],
            'stats': {
                'messages_read': 0,
                'files_downloaded': 0,
                'base64_decoded': 0,
                'json_converted': 0,
                'yaml_converted': 0,
                'happ_decrypted': 0,
                'configs_found': 0,
                'sources_found': 0
            }
        }

        if not self.connected:
            return result

        # Извлекаем username из ссылки
        if 't.me/' in channel_link:
            username = channel_link.split('t.me/')[-1].split('/')[0].split('?')[0]
        else:
            username = channel_link.strip('/')

        print(f"\n[{channel_num}/{total_channels}] https://t.me/{username}")

        try:
            entity = await asyncio.wait_for(self.client.get_entity(username), timeout=MESSAGE_TIMEOUT)
        except FloodWaitError as e:
            print(f"FloodWait при получении entity: {e.seconds} сек")
            raise TelegramFloodError(f"FloodWait на канале {username}: {e.seconds} сек")
        except Exception as e:
            print(f"Не удалось получить entity: {e}")
            return result

        messages_read = 0
        last_error_line = False

        try:
            async for message in self.client.iter_messages(entity, limit=limit):
                messages_read += 1

                if message.text:
                    text = clean_text(message.text)

                    # Извлечение конфигов (учитываем настройки)
                    if self.config["save_vless_tg"]:
                        for v in VLESS_REGEX.findall(text):
                            result['vless'].add(v)
                    if self.config["save_trojan_tg"]:
                        for t in TROJAN_REGEX.findall(text):
                            result['trojan'].add(t)
                    if self.config["save_hy2_tg"]:
                        for h in HY2_REGEX.findall(text):
                            result['hy2'].add(h)

                    if self.config["save_sources_tg"]:
                        for url in URL_REGEX.findall(text):
                            if 't.me/' not in url and 'telegram.me/' not in url:
                                result['sources'].add(url)

                    # Декодирование base64
                    if self.config["decode_base64_tg"]:
                        b64_res = decode_base64_content(text)
                        if b64_res[1]:
                            result['stats']['base64_decoded'] += 1
                            for m in b64_res[1]:
                                if m.startswith("vless://") and self.config["save_vless_tg"]:
                                    result['vless'].add(m)
                                elif m.startswith("trojan://") and self.config["save_trojan_tg"]:
                                    result['trojan'].add(m)
                                elif m.startswith(("hysteria2://", "hy2://")) and self.config["save_hy2_tg"]:
                                    result['hy2'].add(m)

                    # Декодирование JSON
                    if self.config["decode_json_tg"] and text.strip().startswith(('{', '[')):
                        json_urls = convert_json_to_urls(text)
                        if json_urls:
                            result['stats']['json_converted'] += 1
                            for u in json_urls:
                                if u.startswith("vless://") and self.config["save_vless_tg"]:
                                    result['vless'].add(u)
                                elif u.startswith("trojan://") and self.config["save_trojan_tg"]:
                                    result['trojan'].add(u)
                                elif u.startswith(("hysteria2://", "hy2://")) and self.config["save_hy2_tg"]:
                                    result['hy2'].add(u)

                    # Декодирование YAML
                    if self.config["decode_yaml_tg"] and (text.strip().startswith('proxies:') or 'type: vless' in text.lower()):
                        yaml_urls = convert_yaml_to_urls(text)
                        if yaml_urls:
                            result['stats']['yaml_converted'] += 1
                            for u in yaml_urls:
                                if u.startswith("vless://") and self.config["save_vless_tg"]:
                                    result['vless'].add(u)
                                elif u.startswith("trojan://") and self.config["save_trojan_tg"]:
                                    result['trojan'].add(u)
                                elif u.startswith(("hysteria2://", "hy2://")) and self.config["save_hy2_tg"]:
                                    result['hy2'].add(u)

                    # Расшифровка happ://crypt
                    if self.config["decrypt_happ_tg"]:
                        for happ_match in HAPP_REGEX.findall(text):
                            decrypted = await decrypt_happ_url(happ_match)
                            if decrypted and self.config["save_sources_tg"]:
                                result['sources'].add(decrypted)
                                result['stats']['happ_decrypted'] += 1

                # Скачивание файлов
                if self.config["download_files_tg"] and message.media and hasattr(message.media, 'document'):
                    file_ext = self._get_file_extension(message.media)
                    if file_ext in ('.txt', '.json', '.yaml', '.yml'):
                        msg_id = f"{username}_{message.id}"
                        if msg_id not in self.downloaded_ids:
                            try:
                                filepath = await self._download_media(message, file_ext)
                                if filepath:
                                    result['downloaded_files'].append(filepath)
                                    result['stats']['files_downloaded'] += 1
                                    self._save_downloaded_id(msg_id)
                            except Exception as e:
                                if not last_error_line:
                                    print()
                                    last_error_line = True
                                print(f"  Ошибка скачивания: {e}")

                # Вывод прогресса
                stats_line = (f"Прочитано: {messages_read}/{limit} | Файлы: {result['stats']['files_downloaded']} | "
                              f"VLESS: {len(result['vless'])} | Trojan: {len(result['trojan'])} | Hysteria2: {len(result['hy2'])} | "
                              f"Base64: {result['stats']['base64_decoded']} | JSON: {result['stats']['json_converted']} | "
                              f"YAML: {result['stats']['yaml_converted']} | Crypt: {result['stats']['happ_decrypted']} | "
                              f"Всего: {len(result['vless'])+len(result['trojan'])+len(result['hy2'])} | "
                              f"Источников: {len(result['sources'])}")
                sys.stdout.write("\r" + stats_line)
                sys.stdout.flush()
                last_error_line = False

        except FloodWaitError as e:
            print()
            print(f"FloodWait в канале {username}: {e.seconds} сек")
            raise TelegramFloodError(f"FloodWait на канале {username}: {e.seconds} сек")
        except asyncio.TimeoutError:
            print()
            print("Таймаут канала (общий)")
        except Exception as e:
            print()
            print(f"Ошибка: {e}")
            if "server closed the connection" in str(e) and self.retry_count < MAX_RETRIES:
                self.retry_count += 1
                print("Перезапуск прокси...")
                self.connected = False
                await self.disconnect()
                await asyncio.sleep(1)
                if await self.connect_with_retry():
                    return await self.parse_channel(channel_link, channel_num, total_channels, limit)
        finally:
            result['stats']['messages_read'] = messages_read
            result['stats']['configs_found'] = len(result['vless']) + len(result['trojan']) + len(result['hy2'])
            result['stats']['sources_found'] = len(result['sources'])
            print()
        return result

    def _get_file_extension(self, media) -> Optional[str]:
        """Определяет расширение файла по mime-type или имени."""
        try:
            if not media.document:
                return None
            mime = media.document.mime_type.lower() if media.document.mime_type else ""
            for attr in media.document.attributes:
                if hasattr(attr, 'file_name'):
                    filename = attr.file_name
                    ext = os.path.splitext(filename)[1].lower()
                    if ext in ('.txt', '.json', '.yaml', '.yml'):
                        return ext
            if mime in ('text/plain', 'application/json', 'application/x-yaml', 'text/yaml'):
                if 'json' in mime:
                    return '.json'
                if 'yaml' in mime or 'yml' in mime:
                    return '.yaml'
                return '.txt'
        except:
            pass
        return None

    async def _download_media(self, message, ext: str) -> Optional[str]:
        """Скачивает медиа-файл из сообщения."""
        ensure_dir("temp")
        ensure_dir(TELEGRAM_DOWNLOAD_DIR)
        timestamp = int(time.time())
        filename = f"tg_{message.id}_{timestamp}{ext}"
        filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
        filepath = os.path.join(TELEGRAM_DOWNLOAD_DIR, filename)
        try:
            await message.download_media(file=filepath)
            return filepath
        except Exception as e:
            print(f"  Не удалось скачать: {e}")
            return None

    async def process_downloaded_files(self, file_paths: List[str]) -> dict:
        """Обрабатывает скачанные файлы, извлекая конфиги и источники."""
        result = {
            'vless': set(),
            'trojan': set(),
            'hy2': set(),
            'sources': set(),
            'stats': {
                'files_processed': 0,
                'base64_decoded': 0,
                'json_converted': 0,
                'yaml_converted': 0,
                'configs_found': 0,
                'sources_found': 0
            }
        }
        for filepath in file_paths:
            try:
                async with aiofiles.open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = await f.read()
                ext = os.path.splitext(filepath)[1].lower()
                if ext == '.json' and self.config["decode_json_tg"]:
                    urls = convert_json_to_urls(content)
                    if urls:
                        result['stats']['json_converted'] += 1
                        for u in urls:
                            if u.startswith("vless://") and self.config["save_vless_tg"]:
                                result['vless'].add(u)
                            elif u.startswith("trojan://") and self.config["save_trojan_tg"]:
                                result['trojan'].add(u)
                            elif u.startswith(("hysteria2://", "hy2://")) and self.config["save_hy2_tg"]:
                                result['hy2'].add(u)
                elif ext in ('.yaml', '.yml') and self.config["decode_yaml_tg"]:
                    urls = convert_yaml_to_urls(content)
                    if urls:
                        result['stats']['yaml_converted'] += 1
                        for u in urls:
                            if u.startswith("vless://") and self.config["save_vless_tg"]:
                                result['vless'].add(u)
                            elif u.startswith("trojan://") and self.config["save_trojan_tg"]:
                                result['trojan'].add(u)
                            elif u.startswith(("hysteria2://", "hy2://")) and self.config["save_hy2_tg"]:
                                result['hy2'].add(u)
                else:
                    # .txt или другие
                    if self.config["save_vless_tg"]:
                        for v in VLESS_REGEX.findall(content):
                            result['vless'].add(v)
                    if self.config["save_trojan_tg"]:
                        for t in TROJAN_REGEX.findall(content):
                            result['trojan'].add(t)
                    if self.config["save_hy2_tg"]:
                        for h in HY2_REGEX.findall(content):
                            result['hy2'].add(h)
                    if self.config["save_sources_tg"]:
                        for url in URL_REGEX.findall(content):
                            if 't.me/' not in url:
                                result['sources'].add(url)
                    if self.config["decode_base64_tg"]:
                        b64_res = decode_base64_content(content)
                        if b64_res[1]:
                            result['stats']['base64_decoded'] += 1
                            for m in b64_res[1]:
                                if m.startswith("vless://") and self.config["save_vless_tg"]:
                                    result['vless'].add(m)
                                elif m.startswith("trojan://") and self.config["save_trojan_tg"]:
                                    result['trojan'].add(m)
                                elif m.startswith(("hysteria2://", "hy2://")) and self.config["save_hy2_tg"]:
                                    result['hy2'].add(m)
                result['stats']['files_processed'] += 1
            except Exception as e:
                print(f"Ошибка файла {filepath}: {e}")
        result['stats']['configs_found'] = len(result['vless']) + len(result['trojan']) + len(result['hy2'])
        result['stats']['sources_found'] = len(result['sources'])
        return result

# ============================================================
# 8. HTTP-ЗАГРУЗЧИК
# ============================================================
# Функции для загрузки и обработки HTTP-источников.

def _http_get(url: str, timeout: int = None, headers: dict = None) -> Optional[str]:
    """Выполняет синхронный GET-запрос с таймаутом, возвращает текст ответа или None."""
    if timeout is None:
        timeout = TIMEOUT_NORMAL
    if headers is None:
        headers = {"User-Agent": USER_AGENT_DEFAULT}
    result = []

    def _fetch():
        try:
            r = _HTTP_SESSION.get(url, timeout=(TIMEOUT_CONNECT, timeout), headers=headers, verify=False)
            result.append(r.text if r.status_code == 200 else None)
        except Exception:
            result.append(None)

    t = threading.Thread(target=_fetch, daemon=True)
    t.start()
    t.join(timeout + TIMEOUT_CONNECT + 1)
    if not result:
        return None
    return result[0]

_GITHUB_RAW_RE = re.compile(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([a-f0-9]{40})(/.*)$", re.IGNORECASE)

def fix_github_url(url: str) -> str:
    """Пытается заменить коммит-хэш в ссылке raw.github... на 'main' или 'master'."""
    m = _GITHUB_RAW_RE.match(url)
    if not m:
        return url
    user, repo, _sha, path = m.group(1), m.group(2), m.group(3), m.group(4)
    for branch in ("main", "master"):
        fixed = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}{path}"
        ok = []
        def _check():
            try:
                r = requests.head(fixed, timeout=5, verify=False)
                ok.append(r.status_code == 200)
            except Exception:
                ok.append(False)
        t = threading.Thread(target=_check, daemon=True)
        t.start()
        t.join(6)
        if ok and ok[0]:
            return fixed
    return url

def fetch_with_happ_method(url: str) -> Optional[str]:
    """Загружает URL с использованием 'Happ' заголовков (обход блокировок)."""
    parsed = urllib.parse.urlparse(url)
    if 'hwid=' not in url:
        separator = '&' if parsed.query else '?'
        url_with_hwid = f"{url}{separator}hwid={HWID_STATIC}"
    else:
        url_with_hwid = url
    for try_url in [url_with_hwid, url]:
        for ua in HAPP_USER_AGENTS:
            try:
                headers = {
                    "User-Agent": ua,
                    "X-HWID": HWID_STATIC,
                    "Accept": "*/*",
                }
                content = _http_get(try_url, timeout=TIMEOUT_HAPP, headers=headers)
                if not content:
                    continue
                content = content.strip()
                if "<html" in content.lower():
                    continue
                if BASE64_REGEX.match(content.replace('\n', '').replace('\r', '')):
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    if decoded:
                        content = decoded
                return content
            except Exception:
                continue
    return None

def extract_configs_from_text(text: str, config: dict) -> Tuple[List[str], List[str], List[str], int, int, int]:
    """Извлекает из текста конфиги vless, trojan, hy2, учитывая настройки декодирования.
       Возвращает (vless_list, trojan_list, hy2_list, base64_count, json_count, yaml_count)."""
    vless_list = []
    trojan_list = []
    hy2_list = []
    base64_count = 0
    json_count = 0
    yaml_count = 0

    # Прямой поиск
    if config["save_vless_http"]:
        for v in VLESS_REGEX.findall(text):
            vless_list.append(v)
    if config["save_trojan_http"]:
        for t in TROJAN_REGEX.findall(text):
            trojan_list.append(t)
    if config["save_hy2_http"]:
        for h in HY2_REGEX.findall(text):
            hy2_list.append(h)

    # Base64
    if config["decode_base64_http"]:
        b64_res = decode_base64_content(text)
        if b64_res[1]:
            base64_count = 1
            for m in b64_res[1]:
                if m.startswith("vless://") and config["save_vless_http"]:
                    vless_list.append(m)
                elif m.startswith("trojan://") and config["save_trojan_http"]:
                    trojan_list.append(m)
                elif m.startswith(("hysteria2://", "hy2://")) and config["save_hy2_http"]:
                    hy2_list.append(m)

    # JSON
    if config["decode_json_http"] and text.strip().startswith(('{', '[')):
        json_urls = convert_json_to_urls(text)
        if json_urls:
            json_count = 1
            for u in json_urls:
                if u.startswith("vless://") and config["save_vless_http"]:
                    vless_list.append(u)
                elif u.startswith("trojan://") and config["save_trojan_http"]:
                    trojan_list.append(u)
                elif u.startswith(("hysteria2://", "hy2://")) and config["save_hy2_http"]:
                    hy2_list.append(u)

    # YAML
    if config["decode_yaml_http"] and ('proxies:' in text or 'type: vless' in text.lower()):
        yaml_urls = convert_yaml_to_urls(text)
        if yaml_urls:
            yaml_count = 1
            for u in yaml_urls:
                if u.startswith("vless://") and config["save_vless_http"]:
                    vless_list.append(u)
                elif u.startswith("trojan://") and config["save_trojan_http"]:
                    trojan_list.append(u)
                elif u.startswith(("hysteria2://", "hy2://")) and config["save_hy2_http"]:
                    hy2_list.append(u)

    return vless_list, trojan_list, hy2_list, base64_count, json_count, yaml_count

def _fetch_url_content(url: str, config: dict) -> str:
    """Загружает содержимое URL, при необходимости использует Happ-метод."""
    content = _http_get(url)
    if not content or len(content) < 50:
        if config.get("decrypt_happ_http"):
            try:
                c2 = fetch_with_happ_method(url)
                if c2:
                    content = c2
            except Exception:
                pass
    return content

def _process_source_with_content(url: str, content: str, stats: dict, stats_lock: threading.Lock, existing_norm: set, config: dict):
    """Обрабатывает один источник: извлекает конфиги, добавляет новые в stats."""
    if not content or len(content) < 10:
        with stats_lock:
            stats['failed'].append(url)
        return

    vless_list, trojan_list, hy2_list, b64_cnt, json_cnt, yaml_cnt = extract_configs_from_text(content, config)
    total_found = len(vless_list) + len(trojan_list) + len(hy2_list)
    if total_found == 0:
        with stats_lock:
            stats['failed'].append(url)
        return

    new_configs = []
    for cfg in vless_list + trojan_list + hy2_list:
        norm = normalize_config(cfg)
        if norm not in existing_norm:
            cfg_with_hash = ensure_hash_suffix(cfg)
            new_configs.append(cfg_with_hash)
            existing_norm.add(norm)

    with stats_lock:
        stats['processed'] += 1
        stats['vless_count'] += len(vless_list)
        stats['trojan_count'] += len(trojan_list)
        stats['hy2_count'] += len(hy2_list)
        stats['base64'] += b64_cnt
        stats['json'] += json_cnt
        stats['yaml'] += yaml_cnt
        stats['total_configs'] += total_found
        stats['new_configs_count'] += len(new_configs)
        stats['all_new_configs'].extend(new_configs)

def _progress_bar(current: int, total: int, prefix: str = "", suffix: str = "", bar_len: int = 20):
    """Выводит прогресс-бар в консоль."""
    pct = (current / total * 100) if total > 0 else 0
    filled = int(bar_len * current / total) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_len - filled)
    _safe_write(f"\r{prefix}|{bar}| {pct:.0f}% {current}/{total} {suffix}")

def _run_parallel(func, items, max_workers: int, desc: str = ""):
    """Запускает функцию func для каждого элемента items в пуле потоков с отображением прогресса."""
    total = len(items)
    done = 0
    start = time.time()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(func, item): item for item in items}
        while futures and not _stop_requested:
            before = done
            for f in list(futures.keys()):
                if f.done():
                    futures.pop(f)
                    done += 1
            if done != before:
                elapsed = time.time() - start
                speed = done / elapsed if elapsed > 0 else 0
                _progress_bar(done, total, desc, f"{speed:.0f}/сек {elapsed:.0f}с")
            if _stop_requested:
                for f in futures:
                    f.cancel()
                break
            time.sleep(0.1)
    _safe_write("\r" + " " * 80 + "\r")

def _display_progress_loop(stats: dict, total: int, stop_event: threading.Event):
    """Фоновый поток для отображения прогресса загрузки HTTP-источников."""
    while not stop_event.is_set():
        processed = stats['processed']
        v = stats['vless_count']
        t = stats['trojan_count']
        h = stats['hy2_count']
        subs = stats['base64'] + stats['json'] + stats['yaml']
        new_cfgs = stats['new_configs_count']
        happ = stats['happ_success']
        _progress_bar(processed, total, "Загрузка", f"VLESS:{v} Trojan:{t} HY2:{h} Sub:{subs} Happ:{happ} Новых:{new_cfgs}")
        for _ in range(6):
            if stop_event.is_set():
                return
            time.sleep(0.05)

def load_existing_normalized_configs() -> Set[str]:
    """Загружает уже имеющиеся конфиги из configs.txt (нормализованные) для исключения дубликатов."""
    norm_set = set()
    if os.path.exists(CONFIGS_FILE):
        try:
            with open(CONFIGS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        norm_set.add(normalize_config(url))
        except:
            pass
    return norm_set

async def save_new_urls(file_path: str, new_urls: Set[str], is_config: bool = True):
    """Добавляет новые URL (конфиги или источники) в файл, избегая дубликатов."""
    if not new_urls:
        return
    existing = set()
    if os.path.exists(file_path):
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                async for line in f:
                    url = line.strip()
                    if url:
                        if is_config:
                            existing.add(normalize_config(url))
                        else:
                            existing.add(normalize_source(url))
        except:
            pass
    to_add = []
    for url in new_urls:
        if is_config:
            url = ensure_hash_suffix(url)
        norm = normalize_config(url) if is_config else normalize_source(url)
        if norm not in existing:
            to_add.append(url)
            existing.add(norm)
    if to_add:
        async with aiofiles.open(file_path, 'a', encoding='utf-8') as f:
            for url in to_add:
                await f.write(url + '\n')
        print(f"  Добавлено в {file_path}: {len(to_add)}")

# ============================================================
# 9. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ ПРОВЕРКИ
# ============================================================
# Определение путей к файлам, используемым в процессе.
SOURCES_FILE = os.path.join(SOURCES_DIR, "sources.txt")
CONFIGS_FILE = os.path.join(TEMP_DIR, "configs.txt")
CLEAN_FILE = os.path.join(TEMP_DIR, "clean.txt")
WHITELIST_FILE = os.path.join(GENERIC_DIR, "whitelist.txt")
BLACKLIST_FILE = os.path.join(GENERIC_DIR, "blacklist.txt")
MY_CONFIGS_FILE = os.path.join(SOURCES_DIR, "my_configs.txt")
BLACKLIST_SOURCES_FILE = os.path.join(TEMP_DIR, "blacklist_sources.txt")
GARBAGE_FILE = os.path.join(TEMP_DIR, "garbage_conf.txt")
WL_FILTERED_FILE = os.path.join(TEMP_DIR, "wl_filtered.txt")
BL_FILTERED_FILE = os.path.join(TEMP_DIR, "bl_filtered.txt")

TG_SOURCES_FILE = os.path.join(SOURCES_DIR, "tg.txt")
TELEGRAM_DOWNLOAD_DIR = os.path.join(TEMP_DIR, "telegram_files")
DOWNLOADED_IDS_FILE = os.path.join(TEMP_DIR, "downloaded_ids.txt")
IP_LIST_FILE = os.path.join(SOURCES_DIR, "ip_list.txt")
SNI_LIST_FILE = os.path.join(SOURCES_DIR, "sni_list.txt")

# Константы для Telegram и сетевых операций
MESSAGES_LIMIT = 3000
MESSAGE_TIMEOUT = 15
CONNECT_TIMEOUT = 30
MAX_RETRIES = 3

THREADS = 50
TIMEOUT_NORMAL = 8
TIMEOUT_HAPP = 8
TIMEOUT_CONNECT = 5
USER_AGENT_DEFAULT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Глобальная сессия requests с пулом соединений
_HTTP_SESSION = requests.Session()
_HTTP_SESSION.mount("https://", requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=200))
_HTTP_SESSION.headers.update({"User-Agent": USER_AGENT_DEFAULT})

# Блокировка для потокобезопасного вывода
_STDOUT_LOCK = threading.Lock()

def _safe_print(*args, **kwargs):
    with _STDOUT_LOCK:
        print(*args, **kwargs)

def _safe_write(s: str):
    with _STDOUT_LOCK:
        sys.stdout.write(s)
        sys.stdout.flush()

# Константы для Happ
HWID_STATIC = "d060e73eb61d1ba7"
HAPP_USER_AGENTS = ["Happ/3.26.0/Android/17771400994551771562"]

# Пути к ядрам — определяются платформой
_SYSTEM = platform.system().lower()
_IS_WINDOWS = _SYSTEM == "windows"
_IS_MACOS = _SYSTEM == "darwin"

if _IS_WINDOWS:
    _PLATFORM = "windows"
    XRAY_BIN_NAME = "xray.exe"
    HY2_BIN_NAME = "hysteria2-windows-amd64.exe"
    HY2_DL_NAME = "hysteria-windows-amd64.exe"
elif _IS_MACOS:
    _PLATFORM = "macos"
    XRAY_BIN_NAME = "xray"
    HY2_BIN_NAME = "hysteria2-darwin-amd64"
    HY2_DL_NAME = "hysteria-darwin-amd64"
else:
    _PLATFORM = "linux"
    XRAY_BIN_NAME = "xray"
    HY2_BIN_NAME = "hysteria2-linux-amd64"
    HY2_DL_NAME = "hysteria-linux-amd64"

XRAY_PATH = os.path.join(CORES_DIR, XRAY_BIN_NAME)
HYSTERIA2_PATH = os.path.join(CORES_DIR, HY2_BIN_NAME)

XRAY_DOWNLOAD_URL = f"https://github.com/XTLS/Xray-core/releases/latest/download/Xray-{_PLATFORM}-64.zip"
HY2_DOWNLOAD_URL = f"https://github.com/apernet/hysteria/releases/latest/download/{HY2_DL_NAME}"

TEST_DOMAINS = ["https://www.gstatic.com/generate_204"]
CORE_STARTUP_TIMEOUT = 3.0
CORE_KILL_DELAY = 1.0

def _get_xray_inner_name() -> str:
    return "xray.exe" if _IS_WINDOWS else "xray"

def ensure_cores():
    """Скачивает и устанавливает ядра Xray и Hysteria2, если их нет."""
    _ensure_dirs()
    dl = False
    if not os.path.isfile(XRAY_PATH):
        print(f"[+] Xray-core не найден. Скачиваю ({_PLATFORM})...")
        _download_core(XRAY_DOWNLOAD_URL, CORES_DIR, archive=True, inner_name=_get_xray_inner_name(), output_name=XRAY_BIN_NAME)
        dl = True
    if not os.path.isfile(HYSTERIA2_PATH):
        print(f"[+] Hysteria2 не найден. Скачиваю...")
        _download_core(HY2_DOWNLOAD_URL, HYSTERIA2_PATH)
        dl = True
    if dl:
        print("[+] Ядра успешно загружены.")
    if not _IS_WINDOWS:
        for p in (XRAY_PATH, HYSTERIA2_PATH):
            try: os.chmod(p, 0o755)
            except: pass

def _download_core(url: str, dest: str, archive: bool = False, inner_name: str = None, output_name: str = None, retries: int = 3):
    """Скачивает ядро (из ZIP или напрямую) с отображением прогресса."""
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            print(f"  Загрузка: {url}")
            resp = requests.get(url, stream=True, timeout=30, headers={"User-Agent": USER_AGENT_DEFAULT}, allow_redirects=True)
            resp.raise_for_status()
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            bar_len = 30
            if archive:
                zip_path = os.path.join(TEMP_DIR, "_core_dl.zip")
                with open(zip_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            _print_progress(downloaded, total, bar_len)
                print()
                with zipfile.ZipFile(zip_path, "r") as zf:
                    found = False
                    for name in zf.namelist():
                        if os.path.basename(name) == inner_name:
                            with zf.open(name) as src, open(os.path.join(CORES_DIR, output_name), "wb") as dst:
                                dst.write(src.read())
                            found = True
                            break
                    if not found:
                        raise RuntimeError(f"Файл '{inner_name}' не найден в архиве. Содержимое: {zf.namelist()}")
                os.remove(zip_path)
            else:
                with open(dest, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            _print_progress(downloaded, total, bar_len)
                print()
            return
        except Exception as e:
            last_err = e
            print(f"\n  Попытка {attempt}/{retries} не удалась: {e}")
            if attempt < retries:
                time.sleep(2)
    raise RuntimeError(f"Не удалось скачать {url}: {last_err}")

def _print_progress(downloaded: int, total: int, bar_len: int = 30):
    if total > 0:
        pct = downloaded / total
        filled = int(bar_len * pct)
        bar = "█" * filled + "░" * (bar_len - filled)
        _safe_write(f"\r  |{bar}| {pct:.1%} ({downloaded//1024}KB/{total//1024}KB)")
    else:
        _safe_write(f"\r  Скачано: {downloaded//1024}KB")

# ============================================================
# 10. ФИЛЬТРАЦИЯ ПО IP И SNI
# ============================================================
# Функция, которая разделяет конфиги на белый и чёрный списки на основе IP (первые два октета)
# и SNI (из параметров sni или host).
def filter_by_ip_and_sni(config):
    OUTPUT_WL = WL_FILTERED_FILE
    OUTPUT_BL = BL_FILTERED_FILE

    HOST_REGEX = re.compile(r"://(?:[^@]+@)?([^:/?#]+)")
    SNI_PARAM_REGEX = re.compile(r"[?&](?:sni|host)=([^&#]+)", re.IGNORECASE)

    def extract_host(config_str: str) -> Optional[str]:
        match = HOST_REGEX.search(config_str)
        return match.group(1) if match else None

    def extract_sni(config_str: str) -> Optional[str]:
        match = SNI_PARAM_REGEX.search(config_str)
        if match:
            return urllib.parse.unquote(match.group(1))
        return None

    def get_ip_first_two_octets(host: str) -> Optional[str]:
        parts = host.split('.')
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return f"{parts[0]}.{parts[1]}"
        return None

    def load_ip_whitelist(file_path: str) -> Set[str]:
        ip_set = set()
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('.')
                        if len(parts) >= 2:
                            ip_set.add(f"{parts[0]}.{parts[1]}")
        except FileNotFoundError:
            print(f"Файл {file_path} не найден. IP-фильтрация пропущена.")
        return ip_set

    def load_sni_whitelist(file_path: str) -> Set[str]:
        sni_set = set()
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        sni_set.add(line)
        except FileNotFoundError:
            print(f"Файл {file_path} не найден. SNI-фильтрация пропущена.")
        return sni_set

    ip_whitelist = load_ip_whitelist(IP_LIST_FILE) if config["filter_ip"] else set()
    sni_whitelist = load_sni_whitelist(SNI_LIST_FILE) if config["filter_sni"] else set()

    if not config["filter_ip"] and not config["filter_sni"]:
        print("IP и SNI фильтрация отключены. Все конфиги идут в чёрный список.")
        if os.path.exists(CLEAN_FILE):
            shutil.copy(CLEAN_FILE, OUTPUT_BL)
            open(OUTPUT_WL, 'w').close()
            print(f"Создан {OUTPUT_BL} из {CLEAN_FILE}, {OUTPUT_WL} пуст.")
        else:
            print(f"Файл {CLEAN_FILE} не найден.")
        return

    print(f"Загружено IP-октетов: {len(ip_whitelist)}")
    print(f"Загружено SNI: {len(sni_whitelist)}")

    if not os.path.exists(CLEAN_FILE):
        print(f"Файл {CLEAN_FILE} не найден. Фильтрация пропущена.")
        return

    with open(CLEAN_FILE, 'r', encoding='utf-8') as f:
        configs = [line.strip() for line in f if line.strip()]

    print(f"Всего конфигов для фильтрации: {len(configs)}")

    ip_matched = []
    sni_matched = []
    others = []

    for cfg in configs:
        host = extract_host(cfg)
        ip_key = None
        if host:
            ip_key = get_ip_first_two_octets(host)
        if config["filter_ip"] and ip_key and ip_key in ip_whitelist:
            ip_matched.append(cfg)
            continue
        sni = extract_sni(cfg)
        if config["filter_sni"] and sni and sni in sni_whitelist:
            sni_matched.append(cfg)
            continue
        others.append(cfg)

    with open(OUTPUT_WL, 'w', encoding='utf-8') as f:
        for cfg in ip_matched:
            f.write(cfg + '\n')
        for cfg in sni_matched:
            f.write(cfg + '\n')

    if config["filter_others"]:
        with open(OUTPUT_BL, 'w', encoding='utf-8') as f:
            for cfg in others:
                f.write(cfg + '\n')
    else:
        open(OUTPUT_BL, 'w').close()
        print("Сохранение остальных конфигов отключено (bl_filtered.txt очищен).")

    print(f"Результаты фильтрации:")
    print(f"  IP-совпадения: {len(ip_matched)}")
    print(f"  SNI-совпадения: {len(sni_matched)}")
    print(f"  Остальные: {len(others)}")
    print(f"  Белый список сохранён в {OUTPUT_WL}")
    print(f"  Чёрный список сохранён в {OUTPUT_BL}")

# ============================================================
# 11. ПРОВЕРКА КОНФИГОВ (основная функция)
# ============================================================
# В этом блоке реализована проверка работоспособности конфигов через запуск
# локальных ядер (Xray, Hysteria2) и отправку тестовых запросов.

def get_free_port():
    """Находит свободный порт в системе."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def flag_emoji(country_code):
    """Возвращает эмодзи флага по двухбуквенному коду страны."""
    if not country_code or len(country_code) != 2:
        return "🌐"
    return ''.join(chr(127397 + ord(c)) for c in country_code.upper())

def is_port_in_use(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except:
        return False

def wait_for_core_start(port, max_wait):
    """Ожидает, пока порт не станет доступен (ядро запустилось)."""
    start = time.time()
    while time.time() - start < max_wait:
        if is_port_in_use(port):
            return True
        time.sleep(0.1)
    return False

def run_core_with_log(config_path, log_prefix):
    """Запускает Xray с указанным конфигом в скрытом окне (Windows)."""
    if os.name == 'nt':
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        proc = subprocess.Popen(
            [XRAY_PATH, "run", "-c", config_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            startupinfo=startupinfo, text=True, bufsize=1
        )
    else:
        proc = subprocess.Popen(
            [XRAY_PATH, "run", "-c", config_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )
    return proc

def kill_core(proc):
    """Завершает процесс ядра и все его дочерние процессы."""
    if not proc:
        return
    try:
        import psutil
        parent = psutil.Process(proc.pid)
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except:
                pass
        parent.kill()
    except ImportError:
        proc.terminate()
        try:
            proc.wait(timeout=1.0)
        except:
            proc.kill()
    except:
        proc.kill()

def clean_url(url):
    """Очищает URL от невидимых символов и HTML-сущностей."""
    url = url.strip()
    url = url.replace('\ufeff', '').replace('\u200b', '')
    url = url.replace('\n', '').replace('\r', '')
    import html
    url = html.unescape(url)
    url = urllib.parse.unquote(url)
    url = html.unescape(url)
    url = urllib.parse.unquote(url)
    return url

def is_valid_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except:
        return False

def parse_alpn(alpn_str):
    if not alpn_str:
        return None
    parts = [p.strip() for p in alpn_str.split(',') if p.strip()]
    return parts if parts else None

def build_stream_settings(conf):
    """Строит streamSettings для Xray outbound на основе распарсенных данных."""
    net_type = conf.get("type", "tcp").lower()
    if net_type == "raw":
        net_type = "tcp"
    security = conf.get("security", "none").lower()
    stream = {"network": net_type, "security": security}
    if security == "tls":
        tls_settings = {
            "serverName": conf.get("sni") or conf.get("host") or "",
            "allowInsecure": conf.get("allowInsecure", True),
            "fingerprint": conf.get("fp", "chrome")
        }
        alpn = parse_alpn(conf.get("alpn"))
        if alpn:
            tls_settings["alpn"] = alpn
        stream["tlsSettings"] = tls_settings
    elif security == "reality":
        pbk = conf.get("pbk", "")
        if not pbk:
            return None
        reality_settings = {
            "show": False,
            "publicKey": pbk,
            "shortId": conf.get("sid", ""),
            "serverName": conf.get("sni") or conf.get("host") or "",
            "fingerprint": conf.get("fp", "chrome"),
            "spiderX": "/"
        }
        alpn = parse_alpn(conf.get("alpn"))
        if alpn:
            reality_settings["alpn"] = alpn
        stream["realitySettings"] = reality_settings
    if net_type in ("ws", "websocket"):
        stream["wsSettings"] = {"path": conf.get("path", "/"), "headers": {"Host": conf.get("host", "")}}
    elif net_type == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": conf.get("path", "/"), "host": conf.get("host", "")}
    elif net_type == "xhttp":
        stream["xhttpSettings"] = {"path": conf.get("path", "/"), "host": conf.get("host", "")}
    elif net_type == "h2":
        stream["h2Settings"] = {"path": conf.get("path", "/"), "host": [conf.get("host", "")]}
    elif net_type == "grpc":
        stream["grpcSettings"] = {"serviceName": conf.get("serviceName", "")}
    elif net_type == "kcp":
        stream["kcpSettings"] = {"header": {"type": conf.get("headerType", "none")}}
    elif net_type == "quic":
        stream["quicSettings"] = {"security": conf.get("quicSecurity", "none"), "key": conf.get("key", ""), "header": {"type": conf.get("headerType", "none")}}
    return stream

# --- Парсеры URL-конфигов (vless, trojan, hy2) ---
# Эти функции разбирают URL-строки в структурированные словари.
def parse_vless(url):
    try:
        url = clean_url(url)
        if not url.startswith("vless://"):
            return None
        main_part = url
        tag = "vless"
        if '#' in url:
            parts = url.split('#', 1)
            main_part = parts[0]
            tag = urllib.parse.unquote(parts[1]).strip()
        match = re.search(r'vless://([^@]+)@([^:]+):(\d+)', main_part)
        if not match:
            return None
        uuid = match.group(1).strip()
        address = match.group(2).strip()
        port = int(match.group(3))
        params = {}
        if '?' in main_part:
            query = main_part.split('?', 1)[1]
            params = urllib.parse.parse_qs(query)
        def get_p(key, default=""):
            val = params.get(key, [default])
            v = val[0].strip()
            return v if v else default
        net_type = get_p("type", "tcp").lower()
        if net_type == "raw":
            net_type = "tcp"
        if net_type not in ("tcp", "ws", "websocket", "httpupgrade", "xhttp", "grpc", "h2", "kcp", "quic"):
            net_type = "tcp"
        security = get_p("security", "none").lower()
        if security not in ("tls", "reality", "none"):
            security = "none"
        pbk = get_p("pbk", "")
        sid = get_p("sid", "")
        if pbk and security == "tls":
            security = "reality"
        allow_insecure = get_p("allowInsecure", "true").lower() in ("true", "1", "yes")
        return {
            "protocol": "vless", "uuid": uuid, "address": address, "port": port,
            "type": net_type, "security": security,
            "path": urllib.parse.unquote(get_p("path", "")), "host": get_p("host", ""),
            "sni": get_p("sni", ""), "fp": get_p("fp", "chrome"), "alpn": get_p("alpn", ""),
            "serviceName": get_p("serviceName", ""), "flow": get_p("flow", ""),
            "headerType": get_p("headerType", ""), "quicSecurity": get_p("quicSecurity", ""),
            "key": get_p("key", ""), "pbk": pbk, "sid": sid, "allowInsecure": allow_insecure, "tag": tag
        }
    except Exception:
        return None

def parse_trojan(url):
    try:
        url = url.strip().replace('\ufeff', '').replace('\u200b', '')
        if not url.startswith("trojan://"):
            return None
        url_protected = url.replace('%23', '___HASH___')
        if '#' in url_protected:
            url_clean, tag = url_protected.split('#', 1)
            tag = urllib.parse.unquote(tag).strip().replace('___HASH___', '#')
        else:
            url_clean = url_protected
            tag = "trojan"
        parsed = urllib.parse.urlparse(url_clean)
        query_params = urllib.parse.parse_qs(parsed.query)
        raw_password = parsed.username or "trojan"
        password = urllib.parse.unquote(raw_password)
        password = password.replace('___HASH___', '#')
        if not parsed.hostname or not parsed.port:
            return None
        def get_q(key, default=""):
            val = query_params.get(key, [default])
            v = val[0].strip() if val[0] else default
            return urllib.parse.unquote(v)
        net_type = get_q("type", "tcp").lower()
        if net_type not in ("tcp", "ws", "websocket", "httpupgrade", "xhttp", "grpc", "h2", "kcp", "quic"):
            net_type = "tcp"
        security = get_q("security", "tls").lower()
        if security not in ("tls", "none"):
            security = "tls"
        allow_insecure = get_q("allowInsecure", "true").lower() in ("true", "1", "yes")
        return {
            "protocol": "trojan", "password": password, "address": parsed.hostname,
            "port": int(parsed.port), "type": net_type, "security": security,
            "path": get_q("path", ""), "host": get_q("host", ""), "sni": get_q("sni", ""),
            "fp": get_q("fp", "chrome"), "alpn": get_q("alpn", ""),
            "serviceName": get_q("serviceName", ""), "headerType": get_q("headerType", ""),
            "quicSecurity": get_q("quicSecurity", ""), "key": get_q("key", ""),
            "allowInsecure": allow_insecure, "tag": tag
        }
    except Exception:
        return None

def parse_hy2(url):
    try:
        url = url.strip().replace('\ufeff', '').replace('\u200b', '')
        if not url.startswith(("hysteria2://", "hy2://")):
            return None
        url_protected = url.replace('%23', '___HASH___')
        if '#' in url_protected:
            url_clean, tag = url_protected.split('#', 1)
            tag = urllib.parse.unquote(tag).strip().replace('___HASH___', '#')
        else:
            url_clean = url_protected
            tag = "hy2"
        parsed = urllib.parse.urlparse(url_clean)
        query_params = urllib.parse.parse_qs(parsed.query)
        netloc = parsed.netloc
        auth = ""
        host = parsed.hostname
        port = parsed.port or 443
        if '@' in netloc:
            auth_part, host_part = netloc.split('@', 1)
            auth = urllib.parse.unquote(auth_part)
            if ':' in host_part:
                host, port_str = host_part.split(':', 1)
                port = int(port_str)
            else:
                host = host_part
        elif host and ':' in netloc:
            port = int(parsed.port) if parsed.port else 443
        def get_q(key, default=""):
            val = query_params.get(key, [default])
            v = val[0].strip() if val[0] else default
            return urllib.parse.unquote(v)
        return {
            "protocol": "hysteria2", "auth": auth, "address": host,
            "port": int(port), "sni": get_q("sni", host),
            "insecure": get_q("insecure", "true").lower() in ("true", "1", "yes"),
            "alpn": get_q("alpn", "h3"),
            "obfs": get_q("obfs", ""), "obfs-password": get_q("obfs-password", ""),
            "upmbps": get_q("upmbps", ""), "downmbps": get_q("downmbps", ""),
            "tag": tag
        }
    except Exception:
        return None

def config_url_to_parsed(url: str) -> Optional[dict]:
    """Универсальная функция: парсит URL в зависимости от протокола."""
    if url.startswith("vless://"):
        return parse_vless(url)
    if url.startswith("trojan://"):
        return parse_trojan(url)
    if url.startswith(("hysteria2://", "hy2://")):
        return parse_hy2(url)
    return None

# --- Конвертеры в форматы Clash, Xray, Sing-box ---
def parsed_to_clash_proxy(p: dict) -> Optional[dict]:
    """Преобразует распарсенный словарь в прокси для Clash."""
    proto = p.get("protocol")
    name = p.get("tag", proto)
    if proto == "vless":
        proxy = {
            "name": name, "type": "vless",
            "server": p["address"], "port": p["port"],
            "uuid": p["uuid"], "udp": True,
            "encryption": "none",
            "tls": p.get("security") in ("tls", "reality"),
            "servername": p.get("sni", p.get("address", "")),
            "client-fingerprint": p.get("fp", "chrome"),
        }
        if p.get("flow"):
            proxy["flow"] = p["flow"]
        else:
            proxy["flow"] = "xtls-rprx-vision"
        net = p.get("type", "tcp")
        if net in ("ws", "websocket"):
            proxy["network"] = "ws"
            path = p.get("path", "")
            host = p.get("host", "")
            if path or host:
                proxy["ws-opts"] = {}
                if path:
                    proxy["ws-opts"]["path"] = path
                if host:
                    proxy["ws-opts"]["headers"] = {"Host": host}
        elif net == "grpc":
            proxy["network"] = "grpc"
            if p.get("serviceName"):
                proxy.setdefault("grpc-opts", {})["grpc-service-name"] = p["serviceName"]
        elif net not in ("tcp",):
            proxy["network"] = net
        if p.get("security") == "reality":
            proxy["reality-opts"] = {}
            if p.get("pbk"):
                proxy["reality-opts"]["public-key"] = p["pbk"]
            if p.get("sid"):
                proxy["reality-opts"]["short-id"] = p["sid"]
        return proxy
    if proto == "trojan":
        proxy = {
            "name": name, "type": "trojan",
            "server": p["address"], "port": p["port"],
            "password": p["password"], "udp": True,
            "tls": p.get("security") == "tls",
            "servername": p.get("sni", p.get("address", "")),
        }
        if p.get("fp"):
            proxy["client-fingerprint"] = p["fp"]
        net = p.get("type", "tcp")
        if net in ("ws", "websocket"):
            proxy["network"] = "ws"
            path = p.get("path", "")
            host = p.get("host", "")
            if path or host:
                proxy["ws-opts"] = {}
                if path:
                    proxy["ws-opts"]["path"] = path
                if host:
                    proxy["ws-opts"]["headers"] = {"Host": host}
        elif net == "grpc":
            proxy["network"] = "grpc"
            if p.get("serviceName"):
                proxy.setdefault("grpc-opts", {})["grpc-service-name"] = p["serviceName"]
        elif net not in ("tcp",):
            proxy["network"] = net
        return proxy
    if proto == "hysteria2":
        proxy = {
            "name": name, "type": "hysteria2",
            "server": p["address"], "port": p["port"],
            "password": p.get("auth", ""),
            "udp": True,
        }
        if p.get("sni"):
            proxy["sni"] = p["sni"]
        if p.get("insecure"):
            proxy["skip-cert-verify"] = True
        if p.get("obfs") == "salamander" and p.get("obfs-password"):
            proxy["obfs"] = "salamander"
            proxy["obfs-password"] = p["obfs-password"]
        if p.get("alpn") and p["alpn"] != "h3":
            proxy["alpn"] = [a.strip() for a in p["alpn"].split(",")]
        if p.get("upmbps"):
            proxy["up"] = str(p["upmbps"])
        if p.get("downmbps"):
            proxy["down"] = str(p["downmbps"])
        return proxy
    return None

def parsed_to_singbox_outbound(p: dict) -> Optional[dict]:
    """Преобразует распарсенный словарь в outbound для Sing-box."""
    proto = p.get("protocol")
    tag = p.get("tag", proto)
    if proto == "vless":
        ob = {
            "type": "vless", "tag": tag,
            "server": p["address"], "server_port": p["port"],
            "uuid": p["uuid"],
            "tls": {"enabled": False},
        }
        if p.get("flow"):
            ob["flow"] = p["flow"]
        net = p.get("type", "tcp")
        if net in ("ws", "websocket"):
            ob["transport"] = {"type": "ws"}
            if p.get("path"):
                ob["transport"]["path"] = p["path"]
            if p.get("host"):
                ob["transport"]["headers"] = {"Host": p["host"]}
        elif net == "grpc":
            ob["transport"] = {"type": "grpc"}
            if p.get("serviceName"):
                ob["transport"]["service_name"] = p["serviceName"]
        if p.get("security") in ("tls", "reality"):
            ob["tls"]["enabled"] = True
            if p.get("sni"):
                ob["tls"]["server_name"] = p["sni"]
            if p.get("fp"):
                ob["tls"]["utls"] = {"enabled": True, "fingerprint": p["fp"]}
            if p.get("alpn"):
                ob["tls"]["alpn"] = [a.strip() for a in p["alpn"].split(",")]
            ob["tls"]["insecure"] = p.get("allowInsecure", False)
        if p.get("security") == "reality":
            ob["tls"]["reality"] = {"enabled": True}
            if p.get("pbk"):
                ob["tls"]["reality"]["public_key"] = p["pbk"]
            if p.get("sid"):
                ob["tls"]["reality"]["short_id"] = p["sid"]
        return ob
    if proto == "trojan":
        ob = {
            "type": "trojan", "tag": tag,
            "server": p["address"], "server_port": p["port"],
            "password": p["password"],
            "tls": {"enabled": True},
        }
        if p.get("sni"):
            ob["tls"]["server_name"] = p["sni"]
        if p.get("fp"):
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": p["fp"]}
        if p.get("alpn"):
            ob["tls"]["alpn"] = [a.strip() for a in p["alpn"].split(",")]
        ob["tls"]["insecure"] = p.get("allowInsecure", False)
        net = p.get("type", "tcp")
        if net in ("ws", "websocket"):
            ob["transport"] = {"type": "ws"}
            if p.get("path"):
                ob["transport"]["path"] = p["path"]
            if p.get("host"):
                ob["transport"]["headers"] = {"Host": p["host"]}
        elif net == "grpc":
            ob["transport"] = {"type": "grpc"}
            if p.get("serviceName"):
                ob["transport"]["service_name"] = p["serviceName"]
        return ob
    if proto == "hysteria2":
        ob = {
            "type": "hysteria2", "tag": tag,
            "server": p["address"], "server_port": p["port"],
            "password": p.get("auth", ""),
            "tls": {"enabled": True, "insecure": p.get("insecure", True)},
        }
        if p.get("sni"):
            ob["tls"]["server_name"] = p["sni"]
        if p.get("alpn") and p["alpn"] != "h3":
            ob["tls"]["alpn"] = [a.strip() for a in p["alpn"].split(",")]
        if p.get("obfs") == "salamander" and p.get("obfs-password"):
            ob["obfs"] = {"type": "salamander", "password": p["obfs-password"]}
        if p.get("upmbps"):
            ob["up_mbps"] = int(p["upmbps"])
        if p.get("downmbps"):
            ob["down_mbps"] = int(p["downmbps"])
        return ob
    return None

def generate_proxy_name(p: dict, idx: int) -> str:
    """Генерирует читаемое имя для прокси на основе его данных."""
    tag = p.get("tag", "").strip()
    proto = p.get("protocol", "unk")
    addr = p.get("address", "unknown")
    if tag and tag.lower() not in ("vless", "trojan", "hy2", "hysteria2"):
        return f"{tag} #{idx:03d}"
    return f"{proto.upper()}-{addr}-{idx:03d}"

def generate_all_formats(whitelist_path: str, blacklist_path: str, config: dict = None):
    """Генерирует файлы Clash, Xray, Sing-box для whitelist и blacklist."""
    for label, src in [("whitelist", whitelist_path), ("blacklist", blacklist_path)]:
        if not os.path.exists(src):
            print(f"  [{label}] файл не найден: {src}")
            continue
        with open(src, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip()]
        if not urls:
            print(f"  [{label}] файл пуст, пропускаем")
            continue
        print(f"\n  Конвертация {label} ({len(urls)} конфигов)")
        parsed_list = []
        failed = 0
        for url in urls:
            p = config_url_to_parsed(url)
            if p:
                parsed_list.append(p)
            else:
                failed += 1
        if failed:
            print(f"  [{label}] не удалось распарсить: {failed}")
        if not parsed_list:
            print(f"  [{label}] ни один конфиг не распарсился, пропускаем")
            continue
        for idx, p in enumerate(parsed_list):
            p["tag"] = generate_proxy_name(p, idx + 1)

        clash_proxies = []
        singbox_outbounds = []
        xray_outbounds = []
        for p in parsed_list:
            try:
                cp = parsed_to_clash_proxy(p)
                if cp:
                    clash_proxies.append(cp)
            except Exception:
                pass
            try:
                so = parsed_to_singbox_outbound(p)
                if so:
                    singbox_outbounds.append(so)
            except Exception:
                pass
            try:
                xo = get_outbound_structure_for_format(p)
                if xo:
                    xray_outbounds.append(xo)
            except Exception:
                pass

        if not config or config.get("save_clash", True):
            _save_clash(label, clash_proxies)
        if not config or config.get("save_xray", True):
            _save_xray(label, xray_outbounds)
        if not config or config.get("save_singbox", True):
            _save_singbox(label, singbox_outbounds)

def get_outbound_structure_for_format(p: dict) -> Optional[dict]:
    """Строит outbound для Xray JSON из распарсенного словаря."""
    proto = p.get("protocol")
    tag = p.get("tag", proto)
    if proto == "vless":
        outbound = {
            "tag": tag, "protocol": "vless",
            "settings": {"vnext": [{"address": p["address"], "port": p["port"], "users": [{"id": p["uuid"], "encryption": "none", "flow": p.get("flow", "")}]}]}
        }
        stream = build_stream_settings(p)
        if stream:
            outbound["streamSettings"] = stream
        return outbound
    if proto == "trojan":
        outbound = {
            "tag": tag, "protocol": "trojan",
            "settings": {"servers": [{"address": p["address"], "port": p["port"], "password": p["password"]}]}
        }
        stream = build_stream_settings(p)
        if stream:
            outbound["streamSettings"] = stream
        return outbound
    if proto == "hysteria2":
        conf = {
            "server": f"{p['address']}:{p['port']}",
            "auth": p.get("auth", ""),
            "tls": {"sni": p.get("sni", p["address"]), "insecure": p.get("insecure", True)},
            "socks5": {"listen": "127.0.0.1:1080"},
        }
        if p.get("alpn") and p["alpn"] != "h3":
            conf["tls"]["alpn"] = [a.strip() for a in p["alpn"].split(",")]
        if p.get("obfs") == "salamander" and p.get("obfs-password"):
            conf["transport"] = {"udp": {"obfs": {"type": "salamander", "password": p["obfs-password"]}}}
        if p.get("upmbps") or p.get("downmbps"):
            conf["bandwidth"] = {}
            if p.get("upmbps"):
                conf["bandwidth"]["up"] = f"{p['upmbps']} mbps"
            if p.get("downmbps"):
                conf["bandwidth"]["down"] = f"{p['downmbps']} mbps"
        return {"tag": tag, "protocol": "hysteria2", "settings": conf, "type": "hysteria2"}
    return None

class _SafeYamlDumper(yaml.Dumper):
    pass

def _safe_str_representer(dumper, data):
    if any(c in data for c in '[]{}#&*!|>\'"%@`,'):
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

_SafeYamlDumper.add_representer(str, _safe_str_representer)

def _hex_escape(s: str) -> str:
    return '"' + ''.join(f'\\x{ord(c):02x}' for c in s) + '"'

def _yaml_val(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        if any(c in v for c in '[]{}#&*!|>\'"%@`,\n'):
            q = "'"
            escaped = v.replace("'", "''")
            return f"'{escaped}'"
        return v
    return str(v)

def _format_clash_proxy_yaml(p: dict) -> str:
    """Форматирует один прокси для Clash YAML с экранированием."""
    lines = []
    name_raw = p.get("name", "")
    if any(c in name_raw for c in '[]{}#&*!|>\'"%@`,'):
        q = "'"
        escaped = name_raw.replace("'", "''")
        lines.append(f"- name: '{escaped}'")
    else:
        lines.append(f"- name: {name_raw}")
    lines.append(f"  type: {p.get('type', '')}")
    lines.append(f"  server: {_hex_escape(p.get('server', ''))}")
    lines.append(f"  port: {p['port']}")
    if p.get("uuid"):
        lines.append(f"  uuid: {_hex_escape(p['uuid'])}")
    if p.get("password"):
        lines.append(f"  password: {_yaml_val(p['password'])}")
    lines.append(f"  udp: {_yaml_val(p.get('udp', True))}")
    if p.get("encryption"):
        lines.append(f"  encryption: {_yaml_val(p['encryption'])}")
    if p.get("network"):
        lines.append(f"  network: {_yaml_val(p['network'])}")
    lines.append(f"  tls: {_yaml_val(p.get('tls', True))}")
    if p.get("servername"):
        lines.append(f"  servername: {_hex_escape(p['servername'])}")
    if p.get("client-fingerprint"):
        lines.append(f"  client-fingerprint: {_yaml_val(p['client-fingerprint'])}")
    if p.get("reality-opts"):
        lines.append("  reality-opts:")
        ro = p["reality-opts"]
        if ro.get("public-key"):
            lines.append(f"    public-key: {_yaml_val(ro['public-key'])}")
        if ro.get("short-id"):
            lines.append(f"    short-id: {_yaml_val(ro['short-id'])}")
    if p.get("flow"):
        lines.append(f"  flow: {_yaml_val(p['flow'])}")
    if p.get("ws-opts"):
        lines.append("  ws-opts:")
        wo = p["ws-opts"]
        if wo.get("path"):
            lines.append(f"    path: {_yaml_val(wo['path'])}")
        if wo.get("headers"):
            lines.append("    headers:")
            for k, v in wo["headers"].items():
                lines.append(f"      {k}: {_yaml_val(v)}")
    if p.get("grpc-opts"):
        lines.append("  grpc-opts:")
        go = p["grpc-opts"]
        if go.get("grpc-service-name"):
            lines.append(f"    grpc-service-name: {_yaml_val(go['grpc-service-name'])}")
    if p.get("sni"):
        lines.append(f"  sni: {_yaml_val(p['sni'])}")
    if p.get("skip-cert-verify"):
        lines.append("  skip-cert-verify: true")
    if p.get("obfs"):
        lines.append(f"  obfs: {_yaml_val(p['obfs'])}")
        if p.get("obfs-password"):
            lines.append(f"  obfs-password: {_yaml_val(p['obfs-password'])}")
    if p.get("alpn"):
        alpn_list = p["alpn"] if isinstance(p["alpn"], list) else [p["alpn"]]
        lines.append(f"  alpn: [{', '.join(alpn_list)}]")
    if p.get("up"):
        lines.append(f"  up: {_yaml_val(p['up'])}")
    if p.get("down"):
        lines.append(f"  down: {_yaml_val(p['down'])}")
    return '\n'.join(lines)

def _save_clash(label: str, proxies: list):
    """Сохраняет Clash YAML файл."""
    if not proxies:
        return
    count = len(proxies)
    path = os.path.join(CLASH_DIR, f"{label}.yaml")
    lines = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "proxies:",
    ]
    proxy_names = []
    raw_names = []
    for p in proxies:
        lines.append(_format_clash_proxy_yaml(p))
        name = p.get("name", "")
        raw_names.append(name)
        if any(c in name for c in '[]{}#&*!|>\'%@`,'):
            proxy_names.append(f"'{name}'")
        else:
            proxy_names.append(name)
    lines.append("")
    lines.append("proxy-groups:")
    lines.append(f"  - name: \"ВЫБОР СЕРВЕРА\"")
    lines.append("    type: select")
    lines.append("    proxies:")
    for n in proxy_names:
        lines.append(f"      - {n}")
    selected_raw = raw_names[0] if raw_names else "DIRECT"
    lines.append("")
    lines.append("rules:")
    if "'" in selected_raw:
        lines.append(f'  - "MATCH,{selected_raw}"')
    else:
        lines.append(f"  - 'MATCH,{selected_raw}'")
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f"    {label} -> {path} ({count} proxies)")

def _save_xray(label: str, outbounds: list):
    """Сохраняет Xray JSON файл."""
    if not outbounds:
        return
    os.makedirs(XRAY_DIR, exist_ok=True)
    path = os.path.join(XRAY_DIR, f"{label}.json")
    multi = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"port": 1080, "listen": "127.0.0.1", "protocol": "socks", "tag": "socks-in"}],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs"}
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(multi, f, indent=2, ensure_ascii=False)
    print(f"    {label} -> {path} ({len(outbounds)} outbounds)")

def _save_singbox(label: str, outbounds: list):
    """Сохраняет Sing-box JSON файл."""
    if not outbounds:
        return
    path = os.path.join(SINGBOX_DIR, f"{label}.json")
    data = {"outbounds": outbounds}
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"    {label} -> {path} ({len(outbounds)} outbounds)")

def get_outbound_structure(proxy_url, tag):
    """Строит outbound для Xray из URL-конфига."""
    if proxy_url.startswith("vless://"):
        conf = parse_vless(proxy_url)
    elif proxy_url.startswith("trojan://"):
        conf = parse_trojan(proxy_url)
    else:
        return None
    if not conf or not conf.get("address"):
        return None
    if not is_valid_port(conf.get("port")):
        return None
    proto = conf["protocol"]
    outbound = {"tag": tag}
    if proto == "vless":
        outbound["protocol"] = "vless"
        outbound["settings"] = {"vnext": [{"address": conf["address"], "port": conf["port"], "users": [{"id": conf["uuid"], "encryption": "none", "flow": conf.get("flow", "")}]}]}
        stream = build_stream_settings(conf)
        if stream:
            outbound["streamSettings"] = stream
    elif proto == "trojan":
        outbound["protocol"] = "trojan"
        outbound["settings"] = {"servers": [{"address": conf["address"], "port": conf["port"], "password": conf["password"]}]}
        stream = build_stream_settings(conf)
        if stream:
            outbound["streamSettings"] = stream
    else:
        return None
    return outbound

def create_config_for_proxy(proxy_url, local_port, work_dir):
    """Создаёт временный Xray конфиг для проверки одного прокси."""
    in_tag = f"in_{local_port}"
    out_tag = f"out_{local_port}"
    out_struct = get_outbound_structure(proxy_url, out_tag)
    if not out_struct:
        return None, "Не удалось построить outbound"
    inbound = {"port": local_port, "listen": "127.0.0.1", "protocol": "socks", "tag": in_tag, "settings": {"udp": False}}
    routing = {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag}]}
    config = {"log": {"loglevel": "warning"}, "inbounds": [inbound], "outbounds": [out_struct], "routing": routing}
    config_path = os.path.join(work_dir, f"config_{local_port}.json")
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)
    return config_path, None

def check_connection(local_port, test_domains, timeout):
    """Проверяет доступность интернета через SOCKS5 прокси."""
    for test_domain in test_domains:
        proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}
        try:
            start = time.time()
            resp = requests.get(test_domain, proxies=proxies, timeout=timeout, verify=False)
            elapsed = time.time() - start
            if resp.status_code < 400:
                return round(elapsed * 1000), None
        except Exception:
            continue
    return False, "Не удалось получить успешный ответ"

def check_xray_proxy(proxy_url, work_dir, timeout):
    """Проверяет прокси через Xray, возвращает (url, пинг) или (None, ошибка)."""
    MAX_RETRIES = 3
    for attempt in range(1, MAX_RETRIES + 1):
        local_port = get_free_port()
        config_path, err = create_config_for_proxy(proxy_url, local_port, work_dir)
        if not config_path:
            return None, err
        proc = run_core_with_log(config_path, f"[{local_port}]")
        if not proc:
            continue
        core_started = wait_for_core_start(local_port, CORE_STARTUP_TIMEOUT)
        if not core_started:
            kill_core(proc)
            try: os.remove(config_path)
            except: pass
            continue
        ping_ms, error = check_connection(local_port, TEST_DOMAINS, timeout)
        kill_core(proc)
        time.sleep(CORE_KILL_DELAY)
        try: os.remove(config_path)
        except: pass
        if ping_ms:
            return proxy_url, ping_ms
        else:
            return None, error
    return None, "Xray не запустился"

def check_hysteria2_proxy(proxy_url, temp_dir, timeout):
    """Проверяет Hysteria2 прокси через собственный клиент."""
    from urllib.parse import urlparse, parse_qs
    try:
        parsed = urlparse(proxy_url)
        if parsed.scheme not in ('hysteria2', 'hy2'):
            return None, "Неверная схема"
        netloc = parsed.netloc
        auth = None
        if '@' in netloc:
            auth_part, netloc = netloc.split('@', 1)
            if ':' in auth_part:
                user, pwd = auth_part.split(':', 1)
                auth = {'username': urllib.parse.unquote(user), 'password': urllib.parse.unquote(pwd)}
            else:
                auth = urllib.parse.unquote(auth_part)
        if ':' in netloc:
            host, port_str = netloc.split(':', 1)
            try:
                port = int(port_str)
            except:
                port = 443
        else:
            host, port = netloc, 443
        params = {k.lower(): v[0] for k, v in parse_qs(parsed.query).items()}
        if isinstance(auth, str) and '%' in auth:
            auth = urllib.parse.unquote(auth)
        insecure_default = params.get('insecure', 'true').lower() in ('true', '1', 'yes')
        socks_port = get_free_port()
        config = {
            'server': f"{host}:{port}",
            'auth': auth if auth is not None else "auto",
            'tls': {
                'sni': params.get('sni', host),
                'insecure': insecure_default
            },
            'socks5': {'listen': f'127.0.0.1:{socks_port}'},
            'quic': {
                'initStreamReceiveWindow': 8388608,
                'maxStreamReceiveWindow': 8388608,
                'initConnReceiveWindow': 20971520,
                'maxConnReceiveWindow': 20971520,
                'maxIdleTimeout': '30s',
                'maxIncomingStreams': 1024
            }
        }
        alpn = params.get('alpn', 'h3')
        config['tls']['alpn'] = [a.strip() for a in alpn.split(',')]
        obfs_pass = params.get('obfs-password')
        if obfs_pass:
            config.setdefault('transport', {}).setdefault('udp', {})['obfs'] = {
                'type': 'salamander',
                'password': obfs_pass
            }
        up = params.get('upmbps')
        down = params.get('downmbps')
        if up or down:
            config['bandwidth'] = {}
            if up:
                config['bandwidth']['up'] = f"{up} mbps"
            if down:
                config['bandwidth']['down'] = f"{down} mbps"
        config_file = os.path.join(temp_dir, f"hy2_{random.randint(10000, 99999)}.yaml")
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        if not os.path.exists(HYSTERIA2_PATH):
            return None, f"Клиент не найден: {HYSTERIA2_PATH}"
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
        process = None
        try:
            cmd = [HYSTERIA2_PATH, 'client', '-c', config_file]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo, text=True)
            time.sleep(5)
            if process.poll() is not None:
                cmd2 = [HYSTERIA2_PATH, '-c', config_file]
                process = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo, text=True)
                time.sleep(5)
                if process.poll() is not None:
                    return None, "Клиент не запустился"
            port_ready = False
            for _ in range(40):
                time.sleep(0.3)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex(('127.0.0.1', socks_port)) == 0:
                    s.close()
                    port_ready = True
                    break
                s.close()
            if not port_ready:
                return None, f"Порт {socks_port} не открылся"
            for test_url in TEST_DOMAINS:
                proxies = {'http': f'socks5://127.0.0.1:{socks_port}', 'https': f'socks5://127.0.0.1:{socks_port}'}
                try:
                    start = time.time()
                    r = requests.get(test_url, proxies=proxies, timeout=timeout, verify=False)
                    elapsed = time.time() - start
                    if r.status_code < 400:
                        return proxy_url, int(elapsed * 1000)
                except Exception:
                    continue
            return None, "Нет ответа"
        finally:
            if process:
                process.terminate()
                time.sleep(0.5)
                if process.poll() is None:
                    process.kill()
            try:
                os.remove(config_file)
            except:
                pass
    except Exception as e:
        return None, str(e)

def get_country_via_xray(proxy_url, work_dir):
    """Определяет страну через Xray прокси, запрашивая ipwho.is или ip-api.com."""
    local_port = get_free_port()
    config_path, err = create_config_for_proxy(proxy_url, local_port, work_dir)
    if not config_path:
        return None
    proc = run_core_with_log(config_path, f"[country-{local_port}]")
    if not proc:
        return None
    core_started = wait_for_core_start(local_port, CORE_STARTUP_TIMEOUT)
    if not core_started:
        kill_core(proc)
        return None
    time.sleep(0.3)
    proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}
    apis = [("https://ipwho.is?lang=ru", "ipwho.is"), ("http://ip-api.com/json/?fields=country,countryCode&lang=ru", "ip-api.com")]
    result = None
    for attempt in range(1, 3):
        for api_url, name in apis:
            try:
                resp = requests.get(api_url, proxies=proxies, timeout=5, verify=False)
                if resp.status_code == 200:
                    data = resp.json()
                    if name == "ipwho.is" and data.get('success'):
                        country = data.get('country', '').strip()
                        code = data.get('country_code', '').strip()
                        if country and code:
                            result = (country, code)
                            break
                    elif name == "ip-api.com" and data.get('status') == 'success':
                        country = data.get('country', '').strip()
                        code = data.get('countryCode', '').strip()
                        if country and code:
                            result = (country, code)
                            break
                time.sleep(0.2)
            except Exception:
                continue
        if result:
            break
        if attempt == 1:
            time.sleep(0.5)
    kill_core(proc)
    try: os.remove(config_path)
    except: pass
    return result

def get_country_via_hysteria2(proxy_url, temp_dir):
    """Определяет страну через Hysteria2 прокси."""
    try:
        parsed = urlparse(proxy_url)
        if parsed.scheme not in ('hysteria2', 'hy2'):
            return None
        netloc = parsed.netloc
        auth = None
        if '@' in netloc:
            auth_part, netloc = netloc.split('@', 1)
            if ':' in auth_part:
                user, pwd = auth_part.split(':', 1)
                auth = {'username': urllib.parse.unquote(user), 'password': urllib.parse.unquote(pwd)}
            else:
                auth = urllib.parse.unquote(auth_part)
        if ':' in netloc:
            host, port_str = netloc.split(':', 1)
            try:
                port = int(port_str)
            except:
                port = 443
        else:
            host, port = netloc, 443
        params = {k.lower(): v[0] for k, v in parse_qs(parsed.query).items()}
        if isinstance(auth, str) and '%' in auth:
            auth = urllib.parse.unquote(auth)
        insecure_default = params.get('insecure', 'true').lower() in ('true', '1', 'yes')
        socks_port = get_free_port()
        config = {
            'server': f"{host}:{port}",
            'auth': auth if auth is not None else "auto",
            'tls': {
                'sni': params.get('sni', host),
                'insecure': insecure_default
            },
            'socks5': {'listen': f'127.0.0.1:{socks_port}'},
            'quic': {
                'initStreamReceiveWindow': 8388608,
                'maxStreamReceiveWindow': 8388608,
                'initConnReceiveWindow': 20971520,
                'maxConnReceiveWindow': 20971520,
                'maxIdleTimeout': '30s',
                'maxIncomingStreams': 1024
            }
        }
        alpn = params.get('alpn', 'h3')
        config['tls']['alpn'] = [a.strip() for a in alpn.split(',')]
        obfs_pass = params.get('obfs-password')
        if obfs_pass:
            config.setdefault('transport', {}).setdefault('udp', {})['obfs'] = {
                'type': 'salamander',
                'password': obfs_pass
            }
        up = params.get('upmbps')
        down = params.get('downmbps')
        if up or down:
            config['bandwidth'] = {}
            if up:
                config['bandwidth']['up'] = f"{up} mbps"
            if down:
                config['bandwidth']['down'] = f"{down} mbps"
        config_file = os.path.join(temp_dir, f"hy2_country_{random.randint(10000, 99999)}.yaml")
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        if not os.path.exists(HYSTERIA2_PATH):
            return None
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
        process = None
        try:
            cmd = [HYSTERIA2_PATH, 'client', '-c', config_file]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo, text=True)
            time.sleep(4)
            if process.poll() is not None:
                cmd2 = [HYSTERIA2_PATH, '-c', config_file]
                process = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo, text=True)
                time.sleep(4)
                if process.poll() is not None:
                    return None
            port_ready = False
            for _ in range(30):
                time.sleep(0.2)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex(('127.0.0.1', socks_port)) == 0:
                    s.close()
                    port_ready = True
                    break
                s.close()
            if not port_ready:
                return None
            proxies = {'http': f'socks5://127.0.0.1:{socks_port}', 'https': f'socks5://127.0.0.1:{socks_port}'}
            apis = [("https://ipwho.is?lang=ru", "ipwho.is"), ("http://ip-api.com/json/?fields=country,countryCode&lang=ru", "ip-api.com")]
            result = None
            for attempt in range(1, 3):
                for api_url, name in apis:
                    try:
                        resp = requests.get(api_url, proxies=proxies, timeout=5, verify=False)
                        if resp.status_code == 200:
                            data = resp.json()
                            if name == "ipwho.is" and data.get('success'):
                                country = data.get('country', '').strip()
                                code = data.get('country_code', '').strip()
                                if country and code:
                                    result = (country, code)
                                    break
                            elif name == "ip-api.com" and data.get('status') == 'success':
                                country = data.get('country', '').strip()
                                code = data.get('countryCode', '').strip()
                                if country and code:
                                    result = (country, code)
                                    break
                        time.sleep(0.2)
                    except Exception:
                        continue
                if result:
                    break
                if attempt == 1:
                    time.sleep(0.5)
            return result
        finally:
            if process:
                process.terminate()
                time.sleep(0.3)
                if process.poll() is None:
                    process.kill()
            try:
                os.remove(config_file)
            except:
                pass
    except Exception:
        return None

def is_config_secure(url: str) -> bool:
    """Проверяет, является ли конфиг безопасным (TLS/Reality)."""
    if url.startswith("vless://") or url.startswith("trojan://"):
        if "security=reality" in url or "security=tls" in url:
            return True
        return False
    elif url.startswith(("hysteria2://", "hy2://")):
        if "insecure=false" in url:
            return True
        return False
    return False

def update_url_tag(url: str, country_info: Optional[Tuple[str, str]], encode_names: bool) -> str:
    """Обновляет тег (#) URL, добавляя флаг и страну."""
    if country_info is None:
        new_tag_raw = "🌐 Неизвестно [#РКП]"
    else:
        country_ru, country_code = country_info
        flag = flag_emoji(country_code)
        new_tag_raw = f"{flag} {country_ru} [#РКП]"
    if encode_names:
        encoded_tag = urllib.parse.quote(new_tag_raw, safe='')
    else:
        encoded_tag = new_tag_raw
    base_url = url.split('#')[0]
    return f"{base_url}#{encoded_tag}"

def _download_maxmind_db():
    """Скачивает базу MaxMind GeoLite2-Country, если её нет."""
    if os.path.exists(MAXMIND_DB_PATH):
        return MAXMIND_DB_PATH
    print(f"Скачивание MaxMind GeoLite2-Country базы данных...")
    try:
        resp = requests.get(MAXMIND_DB_URL, timeout=120, stream=True)
        if resp.status_code == 200:
            total_size = int(resp.headers.get('content-length', 0))
            downloaded = 0
            with open(MAXMIND_DB_PATH, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        pct = downloaded * 100 // total_size
                        sys.stdout.write(f"\r  Загрузка MaxMind DB: {pct}% ({downloaded}/{total_size})")
                        sys.stdout.flush()
            sys.stdout.write('\n')
            print(f"База данных MaxMind сохранена: {MAXMIND_DB_PATH}")
            return MAXMIND_DB_PATH
        else:
            print(f"Ошибка загрузки MaxMind DB: HTTP {resp.status_code}")
    except Exception as e:
        print(f"Ошибка загрузки MaxMind DB: {e}")
    return None

def get_country_via_maxmind(url):
    """Определяет страну по IP через локальную MaxMind DB."""
    if not HAS_MAXMIND:
        print("Библиотека maxminddb не установлена (pip install maxminddb)")
        return None
    db_path = _download_maxmind_db()
    if not db_path:
        return None
    global _maxmind_reader
    try:
        if _maxmind_reader is None:
            _maxmind_reader = maxminddb.open_database(db_path)
        hp = parse_host_port(url)
        if not hp:
            return None
        ip = hp[0]
        result = _maxmind_reader.get(ip)
        if result and 'country' in result:
            country = result['country']
            code = country.get('iso_code', '')
            names = country.get('names', {})
            name = names.get('ru', names.get('en', ''))
            if code and name:
                return (name, code)
    except Exception:
        pass
    return None

def process_single_country(url, temp_dir, work_dir, encode_names: bool, use_maxmind: bool = False):
    """Обрабатывает один конфиг: определяет страну и обновляет тег."""
    if use_maxmind:
        res = get_country_via_maxmind(url)
    elif url.startswith(("hysteria2://", "hy2://")):
        res = get_country_via_hysteria2(url, temp_dir)
    else:
        res = get_country_via_xray(url, work_dir)
    return update_url_tag(url, res, encode_names)

def tcp_check_host(host: str, port: int, timeout: float = 3.0) -> bool:
    """Быстрая TCP-проверка: доступен ли host:port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False

def parse_host_port(url: str) -> Optional[Tuple[str, int]]:
    """Извлекает host и port из URL конфига."""
    m = re.search(r'@([^:]+):(\d+)', url)
    if m:
        return (m.group(1), int(m.group(2)))
    m = re.search(r'//([^@]+@)?([^:]+):(\d+)', url)
    if m:
        return (m.group(2), int(m.group(3)))
    return None

def get_protocol_name(url):
    if url.startswith("vless://"):
        return "VLESS"
    if url.startswith("trojan://"):
        return "TROJAN"
    if url.startswith(("hysteria2://", "hy2://")):
        return "HY2"
    return "UNKNOWN"

# ============================================================
# 12. ОСНОВНАЯ ФУНКЦИЯ ПРОВЕРКИ
# ============================================================
# check_and_rename_configs — выполняет полную проверку списка конфигов,
# сохраняет рабочие в whitelist, нерабочие в garbage, определяет страны.
def check_and_rename_configs(input_file: str, output_file: str, config):
    print("\n" + "="*60)
    print(f"Проверка конфигов: {input_file} -> {output_file}")
    print("="*60)

    if not os.path.exists(input_file):
        print(f"Файл {input_file} не найден. Пропускаем.")
        return

    # Загружаем мусорный список
    garbage_norm = set()
    if config["save_garbage"] and os.path.exists(GARBAGE_FILE):
        with open(GARBAGE_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                cfg = line.strip()
                if cfg:
                    norm = normalize_config(cfg)
                    if norm:
                        garbage_norm.add(norm)
        print(f"Загружено {len(garbage_norm)} мусорных конфигов (будут пропущены)")

    if config.get("tcp_check", True):
        print("TCP pre-filter: включён (быстрый host:port check)")
    if config.get("check_via_xray", True):
        if not os.path.exists(XRAY_PATH):
            print(f"Предупреждение: Xray не найден ({XRAY_PATH})")
    else:
        print("Xray проверка отключена — только TCP + Hysteria2")
    if not os.path.exists(HYSTERIA2_PATH):
        print(f"Предупреждение: Hysteria2 не найден ({HYSTERIA2_PATH})")

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    urls = []
    skipped_garbage = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if not (line.startswith("vless://") or line.startswith("trojan://") or line.startswith(("hysteria2://", "hy2://"))):
            continue
        norm = normalize_config(line)
        if config["save_garbage"] and norm in garbage_norm:
            skipped_garbage += 1
            continue
        urls.append(line)

    total = len(urls)
    if skipped_garbage:
        print(f"Пропущено мусорных конфигов: {skipped_garbage} (из {skipped_garbage + total})")
    if not total:
        print("Нет новых конфигов для проверки (все в мусоре).")
        return

    temp_dir = tempfile.mkdtemp(prefix="checker_")
    timeout = config["check_timeout"]
    max_workers = config["check_threads"]
    print(f"Таймаут: {timeout} сек, потоков: {max_workers}")
    print(f"Проверяем {total} конфигов")

    shared = {"checked": 0, "alive": 0}
    alive_by_proto = defaultdict(int)
    start_time = time.time()
    lock = threading.Lock()
    results = []

    stop_event = threading.Event()
    stats_thread = threading.Thread(
        target=_print_stats_loop,
        args=(total, stop_event, shared, alive_by_proto, start_time, lock),
        daemon=True
    )
    stats_thread.start()

    def worker(url):
        proxy_url = ping = None
        do_tcp = config.get("tcp_check", True)
        do_xray = config.get("check_via_xray", True)
        if do_tcp:
            hp = parse_host_port(url)
            if hp:
                if not tcp_check_host(hp[0], hp[1], min(timeout, 3)):
                    with lock:
                        shared["checked"] += 1
                    return
        if url.startswith(("hysteria2://", "hy2://")):
            proxy_url, ping = check_hysteria2_proxy(url, temp_dir, timeout)
        elif do_xray:
            proxy_url, ping = check_xray_proxy(url, temp_dir, timeout)
        if not proxy_url and not url.startswith(("hysteria2://", "hy2://")) and not do_xray:
            proxy_url = url
            ping = 0
        with lock:
            shared["checked"] += 1
            if proxy_url:
                results.append((proxy_url, ping))
                shared["alive"] += 1
                alive_by_proto[get_protocol_name(url)] += 1

    _run_parallel(worker, urls, max_workers, "Проверка")

    stop_event.set()
    stats_thread.join(timeout=2)

    with lock:
        elapsed = time.time() - start_time
        proto_str = ' | '.join([f"{proto}: {count}" for proto, count in alive_by_proto.items() if count > 0])
        c, a = shared["checked"], shared["alive"]
        speed = a / elapsed if elapsed > 0 else 0
        print(f"Итог проверки: проверено {c}/{total} | Работает: {a} | {speed:.1f}/сек")
        if proto_str:
            print(proto_str)

    # Добавление нерабочих в garbage
    if config["save_garbage"]:
        working_urls_set = {url for url, _ in results}
        failed_urls = [url for url in urls if url not in working_urls_set]
        if failed_urls:
            existing_garbage_norm = set()
            if os.path.exists(GARBAGE_FILE):
                with open(GARBAGE_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        cfg = line.strip()
                        if cfg:
                            norm = normalize_config(cfg)
                            if norm:
                                existing_garbage_norm.add(norm)
            new_garbage = []
            for url in failed_urls:
                norm = normalize_config(url)
                if norm not in existing_garbage_norm:
                    new_garbage.append(url)
                    existing_garbage_norm.add(norm)
            if new_garbage:
                with open(GARBAGE_FILE, 'a', encoding='utf-8') as f:
                    for url in new_garbage:
                        f.write(url + '\n')
                print(f"Добавлено в garbage_conf.txt: {len(new_garbage)} нерабочих конфигов")

    # Определение стран и переименование
    working_urls = [url for url, _ in results]
    if working_urls and config["determine_country"]:
        print(f"\nОпределение стран для {len(working_urls)} рабочих конфигов...")
        updated_urls = [None] * len(working_urls)

        def process_country(idx_url):
            idx, url = idx_url
            try:
                new_url = process_single_country(url, temp_dir, temp_dir, config["encode_names"], config.get("use_maxmind_country", False))
                updated_urls[idx] = new_url
            except Exception:
                updated_urls[idx] = update_url_tag(url, None, config["encode_names"])

        _run_parallel(process_country, list(enumerate(working_urls)), min(20, len(working_urls)), "Страны")
        sys.stdout.write('\n')

        # Сортировка: сначала безопасные, потом небезопасные (security=none)
        safe = []
        unsafe = []
        for new_url in updated_urls:
            if new_url:
                if is_config_secure(new_url):
                    safe.append(new_url)
                else:
                    unsafe.append(new_url)
        sorted_urls = safe + unsafe

        with open(output_file, 'w', encoding='utf-8') as f:
            for new_url in sorted_urls:
                if new_url:
                    f.write(new_url + '\n')
        print(f"Определение стран завершено. Обновлённые конфиги сохранены в {output_file}")
        print(f"  Безопасные: {len(safe)}, Небезопасные (⚠️): {len(unsafe)}")
    elif working_urls:
        with open(output_file, 'w', encoding='utf-8') as f:
            for url in working_urls:
                f.write(url + '\n')
        print(f"Сохранено {len(working_urls)} конфигов без определения страны.")
    else:
        Path(output_file).touch()
        print("Нет рабочих конфигов, выходной файл пуст.")

    try:
        shutil.rmtree(temp_dir)
    except:
        pass

def _print_stats_loop(total_urls, stop_event, shared, alive_by_proto, start_time, lock):
    """Фоновый поток для отображения прогресса проверки."""
    while not stop_event.is_set():
        time.sleep(1)
        with lock:
            c, a = shared["checked"], shared["alive"]
            elapsed = time.time() - start_time
            speed = c / elapsed if elapsed > 0 else 0
            proto_str = ' | '.join([f"{proto}: {count}" for proto, count in alive_by_proto.items() if count > 0])
            _progress_bar(c, total_urls, "Проверка", f"Работает:{a} {speed:.1f}/сек {proto_str}")
    print()

# ============================================================
# 13. ОСНОВНОЙ ЦИКЛ ПАРСЕРА
# ============================================================
# Эти функции управляют последовательностью выполнения всех этапов.
async def prepend_whitelist_blacklist(config):
    """Добавляет конфиги из whitelist и blacklist в начало configs.txt."""
    print("\n" + "="*60)
    print("Импорт whitelist/blacklist в configs.txt")
    print("="*60)
    files_to_import = []
    if config["import_whitelist"] and os.path.exists(WHITELIST_FILE):
        files_to_import.append(WHITELIST_FILE)
    if config["import_blacklist"] and os.path.exists(BLACKLIST_FILE):
        files_to_import.append(BLACKLIST_FILE)
    if not files_to_import:
        print("Нет файлов для импорта (отключено или файлы отсутствуют).")
        return

    priority_configs = []
    for fname in files_to_import:
        try:
            with open(fname, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    cfg = line.strip()
                    if cfg and is_valid_config(cfg):
                        priority_configs.append(ensure_hash_suffix(cfg))
        except Exception as e:
            print(f"Ошибка чтения {fname}: {e}")

    if not priority_configs:
        print("Нет конфигов в whitelist/blacklist для импорта.")
        return

    priority_norm = {normalize_config(cfg) for cfg in priority_configs}
    old_lines = []
    if os.path.exists(CONFIGS_FILE):
        try:
            with open(CONFIGS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                old_lines = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Ошибка чтения {CONFIGS_FILE}: {e}")
    filtered_old = []
    for line in old_lines:
        norm = normalize_config(line)
        if norm not in priority_norm:
            filtered_old.append(line)
    try:
        async with aiofiles.open(CONFIGS_FILE, 'w', encoding='utf-8') as f:
            for cfg in priority_configs:
                await f.write(cfg + '\n')
            for line in filtered_old:
                await f.write(line + '\n')
        print(f"Импортировано {len(priority_configs)} конфигов в начало {CONFIGS_FILE}.")
    except Exception as e:
        print(f"Ошибка записи в {CONFIGS_FILE}: {e}")

async def telegram_work(config):
    """Запускает парсинг Telegram-каналов, указанных в tg.txt."""
    print("\n" + "="*60)
    print("Запуск Telegram-парсера")
    print("="*60)

    if not CONFIG_LOADED:
        print("config.py не загружен. Telegram-парсинг пропущен.")
        return

    if API_ID is None or API_HASH is None:
        print("API_ID или API_HASH не заданы. Telegram-парсинг пропущен.")
        return

    if not os.path.exists(TG_SOURCES_FILE):
        print(f"Файл {TG_SOURCES_FILE} не найден. Telegram-парсинг пропущен.")
        return

    with open(TG_SOURCES_FILE, 'r', encoding='utf-8') as f:
        tg_links = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not tg_links:
        print("Нет ссылок в tg.txt")
        return

    print(f"Источников для обработки: {len(tg_links)}")
    print(f"Чтение последних {config['tg_messages_limit']} сообщений")

    parser = TelegramParser(API_ID, API_HASH, SESSION_NAME, config)
    connected = await parser.connect_with_retry()
    if not connected:
        print("Не удалось подключиться к Telegram")
        return

    total_stats = {
        'channels': 0,
        'messages_read': 0,
        'files_downloaded': 0,
        'base64_decoded': 0,
        'json_converted': 0,
        'yaml_converted': 0,
        'happ_decrypted': 0,
        'vless': set(),
        'trojan': set(),
        'hy2': set(),
        'sources': set(),
        'downloaded_files': []
    }

    try:
        for idx, link in enumerate(tg_links, 1):
            try:
                channel_result = await parser.parse_channel(link, idx, len(tg_links), limit=config['tg_messages_limit'])
            except TelegramFloodError as e:
                print(f"Остановка парсера из-за FloodWait: {e}")
                break

            total_stats['channels'] += 1
            total_stats['messages_read'] += channel_result['stats']['messages_read']
            total_stats['files_downloaded'] += channel_result['stats']['files_downloaded']
            total_stats['base64_decoded'] += channel_result['stats']['base64_decoded']
            total_stats['json_converted'] += channel_result['stats']['json_converted']
            total_stats['yaml_converted'] += channel_result['stats']['yaml_converted']
            total_stats['happ_decrypted'] += channel_result['stats']['happ_decrypted']
            total_stats['vless'].update(channel_result['vless'])
            total_stats['trojan'].update(channel_result['trojan'])
            total_stats['hy2'].update(channel_result['hy2'])
            total_stats['sources'].update(channel_result['sources'])
            total_stats['downloaded_files'].extend(channel_result['downloaded_files'])
            await asyncio.sleep(1)

        if total_stats['downloaded_files']:
            print("\nОбработка скачанных файлов...")
            file_result = await parser.process_downloaded_files(total_stats['downloaded_files'])
            total_stats['vless'].update(file_result['vless'])
            total_stats['trojan'].update(file_result['trojan'])
            total_stats['hy2'].update(file_result['hy2'])
            total_stats['sources'].update(file_result['sources'])
            total_stats['base64_decoded'] += file_result['stats']['base64_decoded']
            total_stats['json_converted'] += file_result['stats']['json_converted']
            total_stats['yaml_converted'] += file_result['stats']['yaml_converted']

        all_configs = set()
        if config["save_vless_tg"]:
            all_configs.update(total_stats['vless'])
        if config["save_trojan_tg"]:
            all_configs.update(total_stats['trojan'])
        if config["save_hy2_tg"]:
            all_configs.update(total_stats['hy2'])
        await save_new_urls(CONFIGS_FILE, all_configs, is_config=True)
        if config["save_sources_tg"]:
            await save_new_urls(SOURCES_FILE, total_stats['sources'], is_config=False)

        print("\nTelegram парсинг завершён.")
        print(f"Обработано каналов: {total_stats['channels']}")
        print(f"Прочитано сообщений: {total_stats['messages_read']}")
        print(f"Скачано файлов: {total_stats['files_downloaded']}")
        print(f"VLESS: {len(total_stats['vless'])} | Trojan: {len(total_stats['trojan'])} | HY2: {len(total_stats['hy2'])}")
        print(f"Найдено источников: {len(total_stats['sources'])}")
    except Exception as e:
        print(f"Ошибка в Telegram-парсинге: {e}")
    finally:
        await parser.disconnect()
        await asyncio.sleep(1)

def load_http_sources(config):
    """Загружает и обрабатывает источники из sources.txt (HTTP) без жёсткой предфильтрации."""
    print("\n" + "="*60)
    print("Загрузка HTTP-источников (multithread)")
    print("="*60)

    blacklist = set()
    if config["save_failed_sources"] and os.path.exists(BLACKLIST_SOURCES_FILE):
        try:
            with open(BLACKLIST_SOURCES_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    url = line.strip()
                    if url and not line.startswith('#'):
                        blacklist.add(url)
        except:
            pass
    print(f"  Загружено {len(blacklist)} источников в чёрном списке (будут пропущены)")

    verb = config.get("verbose", True)
    if verb:
        print(f"  Чтение {SOURCES_FILE}...")
    if not os.path.exists(SOURCES_FILE):
        print(f"  Файл {SOURCES_FILE} не найден.")
        return

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        all_sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    if verb:
        print(f"  Прочитано строк: {len(all_sources)}")

    sources = [url for url in all_sources if url not in blacklist]
    if not sources:
        print("  Нет источников для обработки.")
        return
    if verb:
        print(f"  После чёрного списка: {len(sources)}")

    # Исправление GitHub ссылок
    if config.get("fix_github_urls"):
        if verb:
            print(f"  Исправление GitHub ссылок...")
        _fix_results = []
        _fix_lock = threading.Lock()
        def _fix_one(url):
            new_url = fix_github_url(url)
            with _fix_lock:
                _fix_results.append((url, new_url))
        _run_parallel(_fix_one, sources, min(50, len(sources)), "GitHub")
        fixed = 0
        for orig, new in _fix_results:
            if new != orig:
                idx = sources.index(orig)
                sources[idx] = new
                fixed += 1
        if fixed:
            print(f"  Исправлено GitHub ссылок: {fixed}")

    print(f"  Загрузка и обработка ({len(sources)} источников)...")

    # Загружаем уже существующие конфиги для дедупликации
    existing_norm = load_existing_normalized_configs()
    if verb:
        print(f"  Уже есть конфигов: {len(existing_norm)}")

    # Мои конфиги
    my_configs = []
    if os.path.exists(MY_CONFIGS_FILE):
        with open(MY_CONFIGS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                cfg = line.strip()
                if cfg and is_valid_config(cfg):
                    cfg = ensure_hash_suffix(cfg)
                    my_configs.append(cfg)
        for cfg in my_configs:
            existing_norm.add(normalize_config(cfg))
        print(f"  Мои конфиги: {len(my_configs)}")

    # Статистика
    stats = {
        'processed': 0,
        'vless_count': 0,
        'trojan_count': 0,
        'hy2_count': 0,
        'base64': 0,
        'json': 0,
        'yaml': 0,
        'total_configs': 0,
        'new_configs_count': 0,
        'all_new_configs': [],
        'failed': [],
        'happ_success': 0,
    }
    stats_lock = threading.Lock()
    stop_event = threading.Event()

    total_sources = len(sources)
    threads = config.get("http_threads", 50)

    # Запускаем поток вывода прогресса
    progress_thread = threading.Thread(
        target=_display_progress_loop,
        args=(stats, total_sources, stop_event),
        daemon=True
    )
    progress_thread.start()

    def worker(url):
        """Загружает источник, извлекает конфиги, добавляет новые."""
        # Попытка обычной загрузки
        content = _http_get(url)
        used_happ = False

        # Если не загрузилось или слишком коротко, пробуем Happ (если включено)
        if (not content or len(content) < 10) and config.get("decrypt_happ_http"):
            happ_content = fetch_with_happ_method(url)
            if happ_content and len(happ_content) >= 10:
                content = happ_content
                used_happ = True
                with stats_lock:
                    stats['happ_success'] += 1

        # Если всё равно нет содержимого, считаем неудачей
        if not content or len(content) < 10:
            with stats_lock:
                stats['failed'].append(url)
                stats['processed'] += 1
            return

        # Извлекаем конфиги
        vless_list, trojan_list, hy2_list, b64_cnt, json_cnt, yaml_cnt = extract_configs_from_text(content, config)
        total_found = len(vless_list) + len(trojan_list) + len(hy2_list)

        if total_found == 0:
            # Нет конфигов – добавляем в чёрный список источников
            with stats_lock:
                stats['failed'].append(url)
                stats['processed'] += 1
            return

        # Собираем новые конфиги (с дедупликацией)
        new_configs = []
        for cfg in vless_list + trojan_list + hy2_list:
            norm = normalize_config(cfg)
            if norm not in existing_norm:
                cfg_with_hash = ensure_hash_suffix(cfg)
                new_configs.append(cfg_with_hash)
                existing_norm.add(norm)

        # Обновляем статистику
        with stats_lock:
            stats['processed'] += 1
            stats['vless_count'] += len(vless_list)
            stats['trojan_count'] += len(trojan_list)
            stats['hy2_count'] += len(hy2_list)
            stats['base64'] += b64_cnt
            stats['json'] += json_cnt
            stats['yaml'] += yaml_cnt
            stats['total_configs'] += total_found
            stats['new_configs_count'] += len(new_configs)
            stats['all_new_configs'].extend(new_configs)

    # Запускаем параллельную обработку
    _run_parallel(worker, sources, threads, "Разбор")

    # Останавливаем поток прогресса
    stop_event.set()
    progress_thread.join(timeout=2)
    print("Загрузка HTTP-источников завершена.")

    # Сохраняем неудачные источники в чёрный список
    if stats['failed'] and config["save_failed_sources"]:
        with open(BLACKLIST_SOURCES_FILE, 'a', encoding='utf-8') as f:
            for bad_url in stats['failed']:
                f.write(bad_url + '\n')
        print(f"  Добавлено в чёрный список: {len(stats['failed'])}")

    # Запись новых конфигов в configs.txt
    new_configs = stats['all_new_configs']
    if new_configs:
        filtered = []
        for cfg in new_configs:
            if cfg.startswith("vless://") and config["save_vless_http"]:
                filtered.append(cfg)
            elif cfg.startswith("trojan://") and config["save_trojan_http"]:
                filtered.append(cfg)
            elif cfg.startswith(("hysteria2://", "hy2://")) and config["save_hy2_http"]:
                filtered.append(cfg)
        if filtered:
            with open(CONFIGS_FILE, 'a', encoding='utf-8') as f:
                for cfg in filtered:
                    f.write(cfg + '\n')
            print(f"  Добавлено новых конфигов: {len(filtered)}")

    # Добавляем мои конфиги (если ещё не добавлены)
    if my_configs:
        my_new = []
        for cfg in my_configs:
            norm = normalize_config(cfg)
            if norm not in existing_norm:
                my_new.append(cfg)
                existing_norm.add(norm)
        if my_new:
            with open(CONFIGS_FILE, 'a', encoding='utf-8') as f:
                for cfg in my_new:
                    f.write(cfg + '\n')
            print(f"  Добавлено своих конфигов: {len(my_new)}")

    # Итоговая статистика
    p = stats['processed']
    print(f"\n  Обработано: {p}/{total_sources}")
    print(f"  Конфигов всего: {stats['total_configs']} (VLESS: {stats['vless_count']}, Trojan: {stats['trojan_count']}, HY2: {stats['hy2_count']})")
    print(f"  Декодировано: {stats['base64']+stats['json']+stats['yaml']} | Happ: {stats['happ_success']}")
    print(f"  Новых добавлено: {stats['new_configs_count']}")

def sort_configs_by_protocol():
    """Сортирует конфиги в configs.txt по протоколу: vless, trojan, остальные."""
    if not os.path.exists(CONFIGS_FILE):
        print(f"Файл {CONFIGS_FILE} не найден, сортировка пропущена.")
        return
    with open(CONFIGS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]
    vless = []
    trojan = []
    other = []
    for line in lines:
        if line.startswith("vless://"):
            vless.append(line)
        elif line.startswith("trojan://"):
            trojan.append(line)
        else:
            other.append(line)
    sorted_lines = vless + trojan + other
    with open(CONFIGS_FILE, 'w', encoding='utf-8') as f:
        for line in sorted_lines:
            f.write(line + '\n')
    print(f"configs.txt отсортирован: VLESS={len(vless)}, Trojan={len(trojan)}, Остальные={len(other)}")

def _sort_priority(configs: list) -> list:
    """Сортирует конфиги: сначала xhttp, затем grpc, затем tcp, остальные."""
    xhttp = []
    grpc = []
    tcp = []
    other = []
    for c in configs:
        has_xhttp = "type=xhttp" in c or "type=splithttp" in c
        has_grpc = "type=grpc" in c or "serviceName=" in c
        if has_xhttp:
            xhttp.append(c)
        elif has_grpc:
            grpc.append(c)
        elif c.startswith(("vless://", "trojan://", "hysteria2://", "hy2://")):
            tcp.append(c)
        else:
            other.append(c)
    return xhttp + grpc + tcp + other

def _split_secure_insecure(configs: list):
    """Разделяет конфиги на безопасные (TLS/Reality) и небезопасные."""
    secure = []
    insecure = []
    for c in configs:
        if "security=tls" in c or "security=reality" in c or "insecure=0" in c or "insecure=false" in c:
            secure.append(c)
        else:
            insecure.append(c)
    return secure, insecure

def sort_whitelist_file(filepath: str, config: dict):
    """Применяет сортировку к файлу whitelist или blacklist."""
    if not os.path.exists(filepath):
        return
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]
    do_p = config.get("sort_grpc_xhttp_top")
    do_s = config.get("sort_unsafe_bottom")
    if do_p and do_s:
        secure, insecure = _split_secure_insecure(lines)
        secure = _sort_priority(secure)
        insecure = _sort_priority(insecure)
        lines = secure + insecure
    elif do_p:
        lines = _sort_priority(lines)
    elif do_s:
        secure, insecure = _split_secure_insecure(lines)
        lines = secure + insecure
    with open(filepath, 'w', encoding='utf-8') as f:
        for line in lines:
            f.write(line + '\n')
    print(f"  Отсортирован {filepath} ({len(lines)} конфигов)")

async def run_parser(config):
    """Основная функция одного цикла парсинга."""
    _ensure_dirs()
    print_header("ЗАПУСК ПАРСЕРА")
    print("Начинаем выполнение цикла...")

    # 1. Импорт whitelist/blacklist
    if config["import_whitelist"] or config["import_blacklist"]:
        await prepend_whitelist_blacklist(config)
    else:
        print("Импорт whitelist/blacklist отключён настройками.")

    if _stop_requested: return

    # 2. Telegram
    if config["use_telegram"]:
        if not HAS_TELEGRAM:
            print("Telegram-парсинг отключён (не установлена библиотека telethon).")
        elif not os.path.exists("config.py"):
            print("config.py не найден. Telegram-парсинг пропущен.")
        else:
            await telegram_work(config)
    else:
        print("Telegram-парсинг отключён настройками.")

    if _stop_requested: return

    # 3. HTTP-загрузка
    if config["load_sources"]:
        load_http_sources(config)
    else:
        print("Загрузка HTTP-источников отключена настройками.")

    if _stop_requested: return

    # 4. Дедупликация
    if config["use_dedup"]:
        print("\n" + "="*60)
        print("Дедупликация конфигов")
        print("="*60)
        unique_count = deduplicate_configs(CONFIGS_FILE, CLEAN_FILE)
        print(f"В clean.txt сохранено {unique_count} уникальных конфигов.")
    else:
        print("Дедупликация отключена настройками. Используем configs.txt как есть.")
        if os.path.exists(CONFIGS_FILE):
            shutil.copy(CONFIGS_FILE, CLEAN_FILE)
            print(f"Скопирован {CONFIGS_FILE} в {CLEAN_FILE} для дальнейшей обработки.")
        else:
            print("configs.txt не найден.")
            return

    # 5. Фильтрация
    if config["filter_ip"] or config["filter_sni"] or config["filter_others"]:
        print("\n" + "="*60)
        print("Фильтрация конфигов по IP/SNI")
        print("="*60)
        if not os.path.exists(CLEAN_FILE):
            print(f"Файл {CLEAN_FILE} не найден. Фильтрация пропущена.")
        else:
            filter_by_ip_and_sni(config)
    else:
        print("Фильтрация отключена настройками. Все конфиги идут в чёрный список.")
        if os.path.exists(CLEAN_FILE):
            shutil.copy(CLEAN_FILE, BL_FILTERED_FILE)
            open(WL_FILTERED_FILE, 'w').close()
            print("Создан bl_filtered.txt из clean.txt, wl_filtered.txt пуст.")
        else:
            print("clean.txt не найден.")
            return

    if _stop_requested: return

    # 6. Проверка белого списка
    if config["check_whitelist"] and os.path.exists(WL_FILTERED_FILE):
        check_and_rename_configs(WL_FILTERED_FILE, WHITELIST_FILE, config)
    else:
        print("Проверка белого списка отключена или файл wl_filtered.txt отсутствует.")
        if os.path.exists(WHITELIST_FILE):
            os.remove(WHITELIST_FILE)

    if _stop_requested: return

    # 7. Проверка чёрного списка
    if config["check_blacklist"] and os.path.exists(BL_FILTERED_FILE):
        check_and_rename_configs(BL_FILTERED_FILE, BLACKLIST_FILE, config)
    else:
        print("Проверка чёрного списка отключена или файл bl_filtered.txt отсутствует.")
        if os.path.exists(BLACKLIST_FILE):
            os.remove(BLACKLIST_FILE)

    # 8. Сортировка финальных конфигов
    if os.path.exists(WHITELIST_FILE) and not _stop_requested:
        sort_whitelist_file(WHITELIST_FILE, config)
    if os.path.exists(BLACKLIST_FILE) and not _stop_requested:
        sort_whitelist_file(BLACKLIST_FILE, config)
    if os.path.exists(CONFIGS_FILE) and not _stop_requested:
        sort_configs_by_protocol()

    # 9. Конвертация в форматы (всегда пытаемся, если whitelist существует)
    want_clash = config.get("save_clash", True)
    want_xray = config.get("save_xray", True)
    want_singbox = config.get("save_singbox", True)
    if any((want_clash, want_xray, want_singbox)):
        if os.path.exists(WHITELIST_FILE):
            print("\n" + "="*60)
            print("Конвертация конфигов в форматы Clash / Xray / Sing-box")
            print("="*60)
            generate_all_formats(WHITELIST_FILE, BLACKLIST_FILE, config)
        else:
            print(f"\n[!] whitelist не найден ({WHITELIST_FILE}) — конвертация пропущена")

    # 10. Завершение: одиночный цикл или остановка
    if _stop_requested:
        return
    if config.get("single_cycle"):
        print("\n[Одиночный цикл] Завершён.")
        return
    rest_minutes = config["rest_time"]
    if rest_minutes > 0:
        print(f"\nЦикл завершён. Ожидание {rest_minutes} минут...")
        for _ in range(rest_minutes):
            if _stop_requested: return
            await asyncio.sleep(60)
    else:
        print("\nЦикл завершён. Продолжаем без отдыха (настройка 0).")

async def run_parser_loop(config):
    """Бесконечный цикл выполнения парсера с учётом пауз."""
    while not _stop_requested:
        await run_parser(config)
        if _stop_requested: break
        rest = config["rest_time"]
        if rest > 0:
            print(f"Ожидание {rest} минут перед следующим циклом...")
            for _ in range(rest):
                if _stop_requested: return
                await asyncio.sleep(60)
        else:
            print("Продолжаем без отдыха.")

# ============================================================
# 14. ИНСТРУМЕНТЫ
# ============================================================
# Набор вспомогательных утилит для обслуживания парсера.
IP_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/ipwhitelist.txt"
DOMAIN_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"

def show_tools_menu(config):
    while True:
        clear_screen()
        print_header("ИНСТРУМЕНТЫ")
        print("1. Фильтрация источников")
        print("2. Очистить temp файлы")
        print("3. Очистить всё кроме garbage pool")
        print("4. Обновить ядра Xray/Hysteria2")
        print("5. Скачать новый IP whitelist")
        print("6. Скачать новый domain whitelist")
        print("7. Назад в главное меню")
        print("="*60)
        choice = input("Выберите пункт (1-7): ").strip()
        if choice == '1':
            tool_filter_sources()
        elif choice == '2':
            tool_clear_temp()
        elif choice == '3':
            tool_clear_except_garbage()
        elif choice == '4':
            tool_update_cores()
        elif choice == '5':
            tool_download_ip_whitelist()
        elif choice == '6':
            tool_download_domain_whitelist()
        elif choice == '7':
            break
        else:
            print("Неверный ввод.")
        input("Нажмите Enter...")

def tool_filter_sources():
    """Проверяет источники из sources.txt, оставляя только рабочие (с конфигами)."""
    src = SOURCES_FILE
    if not os.path.exists(src):
        print(f"Файл источников {src} не найден.")
        return
    with open(src, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    total = len(urls)
    if not total:
        print("Нет источников для фильтрации.")
        return
    threads = min(50, total)
    print(f"Источников: {total}, потоков: {threads}")
    cfg_re = re.compile(r"(?:vless|trojan|hysteria2|hy2|hysteria)://", re.IGNORECASE)
    b64_re = re.compile(r'^[A-Za-z0-9+/]+=*$')

    def has_configs(text):
        if cfg_re.search(text):
            return True
        t = text.replace('\n', '').replace('\r', '')
        if b64_re.match(t):
            try:
                decoded = base64.b64decode(t).decode('utf-8', errors='ignore')
                if cfg_re.search(decoded):
                    return True
            except Exception:
                pass
        return False

    lock = threading.Lock()
    working = []
    done_count = [0]
    start = time.time()

    def check_url(url):
        try:
            r = requests.get(url, timeout=(5, 8), verify=False, headers={"User-Agent": USER_AGENT_DEFAULT})
            if r.status_code == 200 and has_configs(r.text):
                with lock:
                    working.append(url)
        except Exception:
            pass
        finally:
            with lock:
                done_count[0] += 1

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(check_url, u) for u in urls]
        while any(not f.done() for f in futures):
            elapsed = time.time() - start
            done = done_count[0]
            speed = done / elapsed if elapsed > 0 else 0
            pct = done / total * 100 if total > 0 else 0
            filled = int(20 * done / total) if total > 0 else 0
            bar = "█" * filled + "░" * (20 - filled)
            sys.stdout.write(f"\r|{bar}| {pct:.0f}% [{done}/{total}] Найдено: {len(working)} | {speed:.0f}/сек")
            sys.stdout.flush()
            time.sleep(0.1)
    print()
    elapsed = time.time() - start
    date_str = time.strftime("%Y%m%d_%H%M")
    backup = os.path.join(BACKUPS_DIR, f"sources_backup_{date_str}.txt")
    shutil.copy2(src, backup)
    print(f"Бэкап оригинала: {backup}")
    with open(src, 'w', encoding='utf-8') as f:
        for u in working:
            f.write(u + '\n')
    print(f"Сохранено {len(working)}/{total} рабочих источников в {src}")
    print(f"Затрачено: {elapsed:.1f}с")

def tool_clear_temp():
    """Очищает временную папку, сохраняя только garbage_conf.txt и downloaded_ids.txt."""
    keep = {"garbage_conf.txt", "downloaded_ids.txt"}
    removed = 0
    for item in os.listdir(TEMP_DIR):
        if item in keep:
            continue
        path = os.path.join(TEMP_DIR, item)
        try:
            if os.path.isfile(path) or os.path.islink(path):
                os.remove(path)
                removed += 1
            elif os.path.isdir(path):
                shutil.rmtree(path)
                removed += 1
        except Exception as e:
            print(f"  Ошибка удаления {item}: {e}")
    os.makedirs(os.path.join(TEMP_DIR, "telegram_files"), exist_ok=True)
    print(f"Очищено temp файлов/папок: {removed} (сохранены: garbage_conf.txt, downloaded_ids.txt)")

def tool_clear_except_garbage():
    """Удаляет все основные файлы конфигов (whitelist, blacklist, clean, filtered и т.д.), оставляя только garbage."""
    files_to_clear = [
        WHITELIST_FILE,
        BLACKLIST_FILE,
        os.path.join(CLASH_DIR, "whitelist.yaml"),
        os.path.join(CLASH_DIR, "blacklist.yaml"),
        os.path.join(XRAY_DIR, "whitelist.json"),
        os.path.join(XRAY_DIR, "blacklist.json"),
        os.path.join(SINGBOX_DIR, "whitelist.json"),
        os.path.join(SINGBOX_DIR, "blacklist.json"),
        CONFIGS_FILE,
        CLEAN_FILE,
        WL_FILTERED_FILE,
        BL_FILTERED_FILE,
        BLACKLIST_SOURCES_FILE,
    ]
    removed = 0
    for fp in files_to_clear:
        if os.path.exists(fp):
            try:
                os.remove(fp)
                removed += 1
                print(f"  Удалён: {fp}")
            except Exception as e:
                print(f"  Ошибка удаления {fp}: {e}")
    keep = {"garbage_conf.txt", "downloaded_ids.txt", "GeoLite2-Country.mmdb"}
    for item in os.listdir(TEMP_DIR):
        if item in keep:
            continue
        path = os.path.join(TEMP_DIR, item)
        try:
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        except Exception:
            pass
    os.makedirs(os.path.join(TEMP_DIR, "telegram_files"), exist_ok=True)
    print(f"Очищено конфигов и файлов: {removed}. Сохранён garbage pool.")

def tool_update_cores():
    """Принудительно перескачивает и устанавливает ядра."""
    print("Принудительное обновление ядер...")
    for p in (XRAY_PATH, HYSTERIA2_PATH):
        if os.path.exists(p):
            try:
                os.remove(p)
                print(f"  Удалён старый: {p}")
            except Exception as e:
                print(f"  Ошибка удаления {p}: {e}")
    try:
        ensure_cores()
        print("Ядра успешно обновлены.")
    except RuntimeError as e:
        print(f"[!] Ошибка обновления ядер: {e}")

def tool_download_whitelist(url, dest, label):
    """Скачивает whitelist (IP или domain) по URL и сохраняет в файл."""
    print(f"Скачивание {label} whitelist...")
    try:
        resp = requests.get(url, timeout=60, headers={"User-Agent": USER_AGENT_DEFAULT})
        if resp.status_code == 200:
            with open(dest, 'w', encoding='utf-8') as f:
                f.write(resp.text)
            lines = resp.text.strip().split('\n')
            print(f"{label} whitelist сохранён: {dest} ({len(lines)} строк)")
        else:
            print(f"Ошибка загрузки: HTTP {resp.status_code}")
    except Exception as e:
        print(f"Ошибка загрузки {label}: {e}")

def tool_download_ip_whitelist():
    tool_download_whitelist(IP_WHITELIST_URL, IP_LIST_FILE, "IP")

def tool_download_domain_whitelist():
    tool_download_whitelist(DOMAIN_WHITELIST_URL, SNI_LIST_FILE, "Domain")

# ============================================================
# 15. ЗАПУСК
# ============================================================
def main():
    """Точка входа в программу. Загружает настройки, запускает меню."""
    config = load_config()
    try:
        ensure_cores()
    except RuntimeError as e:
        print(f"[!] {e}")
        print("[!] Парсер не сможет проверять конфиги без ядер.")
        input("Нажмите Enter для продолжения...")
    _ensure_dirs()
    while True:
        if _stop_requested: break
        clear_screen()
        choice = show_main_menu()
        if choice == '1':
            cycles = config["cycles"]
            if cycles == 0:
                print("Запуск парсера в бесконечном режиме...")
                asyncio.run(run_parser_loop(config))
            else:
                for i in range(cycles):
                    if _stop_requested: break
                    print(f"Запуск цикла {i+1}/{cycles}...")
                    asyncio.run(run_parser(config))
                    if i < cycles - 1 and not _stop_requested:
                        rest = config["rest_time"]
                        if rest > 0:
                            print(f"Ожидание {rest} минут перед следующим циклом...")
                            time.sleep(rest * 60)
                print("Все циклы выполнены.")
            input("Нажмите Enter для возврата в меню...")
        elif choice == '2':
            print("Одиночный тестовый цикл...")
            config["single_cycle"] = True
            asyncio.run(run_parser(config))
            config["single_cycle"] = False
            input("Нажмите Enter для возврата в меню...")
        elif choice == '3':
            show_settings_menu(config)
        elif choice == '4':
            show_tools_menu(config)
        elif choice == '5':
            print("Выход.")
            break
        else:
            print("Неверный ввод.")
            input("Нажмите Enter...")

if __name__ == "__main__":
    main()
