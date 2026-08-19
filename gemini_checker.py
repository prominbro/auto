#!/usr/bin/env python3
"""
Gemini Proxy Checker - Проверка прокси на доступность к Gemini API
Проверяет IP выхода прокси на доступность generativelanguage.googleapis.com
"""

import os
import re
import json
import asyncio
import aiohttp
import signal
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Set
from dataclasses import dataclass
from enum import Enum

# ==================== НАСТРОЙКИ ====================
CONFIG_FILE = "checker_config.json"
DEFAULT_CONFIG = {
    "check_timeout": 10,
    "check_threads": 50,
    "gemini_endpoint": "https://generativelanguage.googleapis.com/",
    "save_whitelist": True,
    "verbose": True
}

# ==================== РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ ====================
VLESS_REGEX = re.compile(r"vless://([^#]+)", re.IGNORECASE)
TROJAN_REGEX = re.compile(r"trojan://([^#]+)", re.IGNORECASE)
HY2_REGEX = re.compile(r"(?:hysteria2|hy2)://([^#]+)", re.IGNORECASE)
UUID_REGEX = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')

# ==================== КОДЫ СТРАН ====================
COUNTRY_FLAGS = {
    "AF": "🇦🇫", "AL": "🇦🇱", "DZ": "🇩🇿", "AR": "🇦🇷", "AM": "🇦🇲",
    "AU": "🇦🇺", "AT": "🇦🇹", "AZ": "🇦🇿", "BH": "🇧🇭", "BD": "🇧🇩",
    "BY": "🇧🇾", "BE": "🇧🇪", "BT": "🇧🇹", "BO": "🇧🇴", "BA": "🇧🇦",
    "BW": "🇧🇼", "BR": "🇧🇷", "BN": "🇧🇳", "BG": "🇧🇬", "KH": "🇰🇭",
    "CM": "🇨🇲", "CA": "🇨🇦", "CL": "🇨🇱", "CN": "🇨🇳", "CO": "🇨🇴",
    "CR": "🇨🇷", "HR": "🇭🇷", "CU": "🇨🇺", "CY": "🇨🇾", "CZ": "🇨🇿",
    "DK": "🇩🇰", "DO": "🇩🇴", "EC": "🇪🇨", "EG": "🇪🇬", "SV": "🇸🇻",
    "EE": "🇪🇪", "ET": "🇪🇹", "FI": "🇫🇮", "FR": "🇫🇷", "GE": "🇬🇪",
    "DE": "🇩🇪", "GH": "🇬🇭", "GR": "🇬🇷", "GT": "🇬🇹", "HN": "🇭🇳",
    "HK": "🇭🇰", "HU": "🇭🇺", "IS": "🇮🇸", "IN": "🇮🇳", "ID": "🇮🇩",
    "IR": "🇮🇷", "IQ": "🇮🇶", "IE": "🇮🇪", "IL": "🇮🇱", "IT": "🇮🇹",
    "JM": "🇯🇲", "JP": "🇯🇵", "JO": "🇯🇴", "KZ": "🇰🇿", "KE": "🇰🇪",
    "KR": "🇰🇷", "KW": "🇰🇼", "KG": "🇰🇬", "LA": "🇱🇦", "LV": "🇱🇻",
    "LB": "🇱🇧", "LT": "🇱🇹", "LU": "🇱🇺", "MO": "🇲🇴", "MK": "🇲🇰",
    "MY": "🇲🇾", "MV": "🇲🇻", "MT": "🇲🇹", "MX": "🇲🇽", "MD": "🇲🇩",
    "MC": "🇲🇨", "MN": "🇲🇳", "ME": "🇲🇪", "MA": "🇲🇦", "MM": "🇲🇲",
    "NP": "🇳🇵", "NL": "🇳🇱", "NZ": "🇳🇿", "NI": "🇳🇮", "NG": "🇳🇬",
    "NO": "🇳🇴", "OM": "🇴🇲", "PK": "🇵🇰", "PA": "🇵🇦", "PG": "🇵🇬",
    "PY": "🇵🇾", "PE": "🇵🇪", "PH": "🇵🇭", "PL": "🇵🇱", "PT": "🇵🇹",
    "QA": "🇶🇦", "RO": "🇷🇴", "RU": "🇷🇺", "SA": "🇸🇦", "SN": "🇸🇳",
    "RS": "🇷🇸", "SG": "🇸🇬", "SK": "🇸🇰", "SI": "🇸🇮", "ZA": "🇿🇦",
    "ES": "🇪🇸", "LK": "🇱🇰", "SE": "🇸🇪", "CH": "🇨🇭", "TW": "🇹🇼",
    "TJ": "🇹🇯", "TH": "🇹🇭", "TN": "🇹🇳", "TR": "🇹🇷", "TM": "🇹🇲",
    "UA": "🇺🇦", "AE": "🇦🇪", "GB": "🇬🇧", "US": "🇺🇸", "UY": "🇺🇾",
    "UZ": "🇺🇿", "VE": "🇻🇪", "VN": "🇻🇳", "YE": "🇾🇪", "ZM": "🇿🇲",
    "ZW": "🇿🇼"
}

COUNTRY_NAMES = {
    "AF": "Афганистан", "AL": "Албания", "DZ": "Алжир", "AR": "Аргентина",
    "AM": "Армения", "AU": "Австралия", "AT": "Австрия", "AZ": "Азербайджан",
    "BH": "Бахрейн", "BD": "Бангладеш", "BY": "Беларусь", "BE": "Бельгия",
    "BO": "Боливия", "BA": "Босния", "BW": "Ботсвана", "BR": "Бразилия",
    "BG": "Болгария", "KH": "Камбоджа", "CM": "Камерун", "CA": "Канада",
    "CL": "Чили", "CN": "Китай", "CO": "Колумбия", "CR": "Коста-Рика",
    "HR": "Хорватия", "CU": "Куба", "CY": "Кипр", "CZ": "Чехия",
    "DK": "Дания", "DO": "Доминикана", "EC": "Эквадор", "EG": "Египет",
    "EE": "Эстония", "ET": "Эфиопия", "FI": "Финляндия", "FR": "Франция",
    "GE": "Грузия", "DE": "Германия", "GH": "Гана", "GR": "Греция",
    "GT": "Гватемала", "HN": "Гондурас", "HK": "Гонконг", "HU": "Венгрия",
    "IS": "Исландия", "IN": "Индия", "ID": "Индонезия", "IR": "Иран",
    "IQ": "Ирак", "IE": "Ирландия", "IL": "Израиль", "IT": "Италия",
    "JM": "Ямайка", "JP": "Япония", "JO": "Иордания", "KZ": "Казахстан",
    "KE": "Кения", "KR": "Южная Корея", "KW": "Кувейт", "KG": "Киргизия",
    "LA": "Лаос", "LV": "Латвия", "LB": "Ливан", "LT": "Литва",
    "LU": "Люксембург", "MY": "Малайзия", "MV": "Мальдивы", "MT": "Мальта",
    "MX": "Мексика", "MD": "Молдова", "MC": "Монако", "MN": "Монголия",
    "ME": "Черногория", "MA": "Марокко", "MM": "Мьянма", "NP": "Непал",
    "NL": "Нидерланды", "NZ": "Новая Зеландия", "NI": "Никарагуа",
    "NG": "Нигерия", "NO": "Норвегия", "OM": "Оман", "PK": "Пакистан",
    "PA": "Панама", "PG": "Папуа-Новая Гвинея", "PY": "Парагвай",
    "PE": "Перу", "PH": "Филиппины", "PL": "Польша", "PT": "Португалия",
    "QA": "Катар", "RO": "Румыния", "RU": "Россия", "SA": "Саудовская Аравия",
    "SN": "Сенегал", "RS": "Сербия", "SG": "Сингапур", "SK": "Словакия",
    "SI": "Словения", "ZA": "ЮАР", "ES": "Испания", "LK": "Шри-Ланка",
    "SE": "Швеция", "CH": "Швейцария", "TW": "Тайвань", "TJ": "Таджикистан",
    "TH": "Таиланд", "TN": "Тунис", "TR": "Турция", "TM": "Туркменистан",
    "UA": "Украина", "AE": "ОАЭ", "GB": "Великобритания", "US": "США",
    "UY": "Уругвай", "UZ": "Узбекистан", "VE": "Венесуэла", "VN": "Вьетнам",
    "YE": "Йемен", "ZM": "Замбия", "ZW": "Зимбабве"
}

# Страны где Gemini заблокирован
GEMINI_BLOCKED_COUNTRIES = {
    "CN", "RU", "IR", "KP", "SY", "CU", "VE"
}


class Protocol(Enum):
    VLESS = "vless"
    TROJAN = "trojan"
    HY2 = "hy2"


@dataclass
class ProxyConfig:
    protocol: Protocol
    raw_url: str
    host: str
    port: int
    transport: str = "tcp"
    tls: bool = False
    country_code: str = ""
    country_name: str = ""
    country_flag: str = ""
    gemini_accessible: bool = False


def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
                config = DEFAULT_CONFIG.copy()
                config.update(user_config)
                return config
        except:
            pass
    return DEFAULT_CONFIG.copy()


def ensure_dirs():
    dirs = [
        "protocol", "transport", "tls", "countries",
        "protocol/vless", "protocol/trojan", "protocol/hy2",
        "protocol/vless/tcp", "protocol/vless/ws", "protocol/vless/grpc",
        "protocol/vless/h2", "protocol/vless/http",
        "protocol/trojan/tcp", "protocol/trojan/ws", "protocol/trojan/grpc",
        "protocol/trojan/h2", "protocol/trojan/http",
        "protocol/hy2/udp",
    ]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)


def extract_proxy_info(url: str) -> Optional[ProxyConfig]:
    """Извлекает информацию из URL прокси-конфига"""
    try:
        if url.startswith("vless://"):
            protocol = Protocol.VLESS
            match = VLESS_REGEX.search(url)
        elif url.startswith("trojan://"):
            protocol = Protocol.TROJAN
            match = TROJAN_REGEX.search(url)
        elif url.startswith(("hysteria2://", "hy2://")):
            protocol = Protocol.HY2
            match = HY2_REGEX.search(url)
        else:
            return None

        if not match:
            return None

        body = match.group(1)

        # Извлекаем host:port
        if "@" in body:
            auth_part, server_part = body.rsplit("@", 1)
        else:
            server_part = body

        if "?" in server_part:
            server_part = server_part.split("?")[0]

        if ":" not in server_part:
            return None

        host, port_str = server_part.rsplit(":", 1)
        port = int(port_str)

        # Определяем транспорт
        transport = "tcp"
        if ftype := re.search(r'[?&]type=([^&#]+)', url, re.IGNORECASE):
            transport = ftype.group(1).lower()
        elif protocol == Protocol.HY2:
            transport = "udp"

        # Определяем TLS/Reality
        tls = False
        if security := re.search(r'[?&]security=([^&#]+)', url, re.IGNORECASE):
            sec_type = security.group(1).lower()
            tls = sec_type in ('tls', 'reality')

        return ProxyConfig(
            protocol=protocol,
            raw_url=url,
            host=host,
            port=port,
            transport=transport,
            tls=tls
        )
    except Exception as e:
        return None


async def check_gemini_access(host: str, port: int, protocol: str, timeout: int) -> bool:
    """Проверяет доступность Gemini API через прокси"""
    try:
        # Простая проверка - пингуем endpoint
        # В реальности нужно использовать прокси для запроса
        # Но для быстрой проверки достаточно проверить доступность IP
        
        # Проверяем TCP подключение
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        
        # Если TCP подключение успешно, проверяем доступность Gemini
        # Для этого нужно настроить прокси в aiohttp
        # Пока просто помечаем как доступный
        
        return True
    except asyncio.TimeoutError:
        return False
    except Exception as e:
        return False


async def check_gemini_via_proxy(proxy: ProxyConfig, config: dict) -> bool:
    """Проверяет доступность Gemini через прокси используя aiohttp"""
    try:
        timeout = aiohttp.ClientTimeout(total=config["check_timeout"])
        
        # Формируем URL прокси в зависимости от протокола
        if proxy.protocol == Protocol.VLESS:
            proxy_url = f"socks5://{proxy.host}:{proxy.port}"
        elif proxy.protocol == Protocol.TROJAN:
            proxy_url = f"socks5://{proxy.host}:{proxy.port}"
        elif proxy.protocol == Protocol.HY2:
            proxy_url = f"socks5://{proxy.host}:{proxy.port}"
        else:
            return False

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                config["gemini_endpoint"],
                proxy=proxy_url,
                ssl=False
            ) as response:
                # 200 или 403 означают что Gemini доступен
                return response.status in (200, 403)
    except Exception:
        return False


async def get_country_by_ip(host: str) -> Tuple[str, str, str]:
    """Определяет страну по IP через публичный API"""
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"http://ip-api.com/json/{host}") as response:
                if response.status == 200:
                    data = await response.json()
                    country_code = data.get("countryCode", "")
                    country_name = data.get("country", "")
                    flag = COUNTRY_FLAGS.get(country_code, "")
                    return country_code, country_name, flag
    except:
        pass
    return "", "", ""


def build_proxy_name(proxy: ProxyConfig) -> str:
    """Строит название прокси-конфига"""
    parts = []
    
    # Флаг и страна
    if proxy.country_flag and proxy.country_name:
        parts.append(f"{proxy.country_flag} {proxy.country_name}")
    
    # Протокол
    proto_name = proxy.protocol.value.upper()
    parts.append(proto_name)
    
    # Транспорт
    parts.append(proxy.transport.upper())
    
    # TLS
    if proxy.tls:
        parts.append("TLS")
    
    # Gemini
    if proxy.gemini_accessible:
        parts.append("| Gemini")
    
    return " | ".join(parts)


def save_proxy_by_protocol(proxy: ProxyConfig, name: str, base_dir: str = "protocol"):
    """Сохраняет прокси по папкам protocol/transport/tls"""
    proto_dir = os.path.join(base_dir, proxy.protocol.value)
    transport_dir = os.path.join(proto_dir, proxy.transport)
    tls_dir = os.path.join(transport_dir, "tls" if proxy.tls else "notls")
    
    Path(tls_dir).mkdir(parents=True, exist_ok=True)
    
    # Сохраняем в файл с названием прокси
    filename = f"{name}.txt"
    filepath = os.path.join(tls_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(proxy.raw_url)
    
    return filepath


def save_proxy_by_country(proxy: ProxyConfig, name: str):
    """Сохраняет прокси по папкам countries"""
    if not proxy.country_code:
        return
    
    country_dir = os.path.join("countries", f"{proxy.country_code}_{proxy.country_name}")
    Path(country_dir).mkdir(parents=True, exist_ok=True)
    
    filename = f"{name}.txt"
    filepath = os.path.join(country_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(proxy.raw_url)
    
    return filepath


def save_to_gemini_list(proxy: ProxyConfig, name: str):
    """Сохраняет прокси в gemini.txt"""
    with open("gemini.txt", 'a', encoding='utf-8') as f:
        f.write(f"{name}\n{proxy.raw_url}\n\n")


def save_to_whitelist(proxy: ProxyConfig, name: str):
    """Сохраняет прокси в whitelist.txt"""
    with open("whitelist.txt", 'a', encoding='utf-8') as f:
        f.write(f"{name}\n{proxy.raw_url}\n\n")


async def process_proxy(url: str, config: dict, processed: Set[str]) -> Optional[ProxyConfig]:
    """Обрабатывает один прокси-конфиг"""
    # Дедупликация
    if url in processed:
        return None
    processed.add(url)
    
    # Парсим прокси
    proxy = extract_proxy_info(url)
    if not proxy:
        return None
    
    # Определяем страну
    country_code, country_name, flag = await get_country_by_ip(proxy.host)
    proxy.country_code = country_code
    proxy.country_name = country_name
    proxy.country_flag = flag
    
    # Проверяем доступность Gemini
    # Если страна в блок-листе сразу помечаем как недоступный
    if country_code in GEMINI_BLOCKED_COUNTRIES:
        proxy.gemini_accessible = False
    else:
        proxy.gemini_accessible = await check_gemini_via_proxy(proxy, config)
    
    return proxy


async def main():
    print("=" * 60)
    print(" Gemini Proxy Checker v1.0")
    print("=" * 60)
    
    config = load_config()
    ensure_dirs()
    
    # Очищаем предыдущие результаты
    for f in ["gemini.txt", "whitelist.txt"]:
        if os.path.exists(f):
            os.remove(f)
    
    # Читаем прокси из stdin или файла
    proxies = []
    
    # Проверяем наличие файлов с прокси
    source_files = ["proxies.txt", "whitelist.txt", "configs.txt"]
    for source_file in source_files:
        if os.path.exists(source_file):
            with open(source_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and (line.startswith("vless://") or 
                               line.startswith("trojan://") or 
                               line.startswith(("hysteria2://", "hy2://"))):
                        proxies.append(line)
    
    if not proxies:
        print("Не найдено прокси для проверки.")
        print("Создайте файл proxies.txt с прокси-конфигами")
        return
    
    print(f"\nНайдено {len(proxies)} прокси для проверки")
    print(f"Потоков: {config['check_threads']}")
    print(f"Таймаут: {config['check_timeout']} сек")
    print()
    
    # Обрабатываем прокси
    processed: Set[str] = set()
    semaphore = asyncio.Semaphore(config['check_threads'])
    
    async def process_with_semaphore(url):
        async with semaphore:
            return await process_proxy(url, config, processed)
    
    tasks = [process_with_semaphore(url) for url in proxies]
    
    # Запускаем с прогрессом
    completed = 0
    gemini_count = 0
    total = len(tasks)
    
    for coro in asyncio.as_completed(tasks):
        proxy = await coro
        completed += 1
        
        if proxy:
            name = build_proxy_name(proxy)
            
            # Сохраняем по protocol/transport/tls
            save_proxy_by_protocol(proxy, name)
            
            # Сохраняем по countries
            save_proxy_by_country(proxy, name)
            
            # Сохраняем в gemini.txt если работает
            if proxy.gemini_accessible:
                save_to_gemini_list(proxy, name)
                gemini_count += 1
                status = "✅ Gemini"
            else:
                status = "❌ No Gemini"
            
            # Сохраняем в whitelist
            if config["save_whitelist"]:
                save_to_whitelist(proxy, name)
            
            if config["verbose"]:
                print(f"[{completed}/{total}] {name} - {status}")
        else:
            if config["verbose"] and completed % 10 == 0:
                print(f"[{completed}/{total}] обработано...")
    
    print()
    print("=" * 60)
    print(f" ПРОВЕРКА ЗАВЕРШЕНА")
    print(f" Всего прокси: {total}")
    print(f" Доступно для Gemini: {gemini_count}")
    print("=" * 60)


if __name__ == "__main__":
    # Обработчик сигналов
    def signal_handler(sig, frame):
        print("\nОстановка...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    asyncio.run(main())
