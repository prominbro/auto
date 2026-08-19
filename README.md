# Gemini Proxy Checker

Проверка прокси-конфигов на доступность к Gemini API.

## Установка

```bash
pip install -r requirements.txt
```

## Использование

1. Создайте файл `proxies.txt` с вашими прокси-конфигами
2. Запустите проверку:

```bash
python3 gemini_checker.py
```

## Структура папок

```
/project/
├── protocol/           # По протоколам
│   ├── vless/
│   │   ├── tcp/
│   │   │   ├── tls/
│   │   │   └── notls/
│   │   └── ws/
│   ├── trojan/
│   └── hy2/
├── countries/          # По странам
├── gemini.txt          # Все ключи с Gemini доступом
└── whitelist.txt       # Белый список
```

## Формат прокси

Поддерживаются форматы:
- `vless://uuid@host:port?params#name`
- `trojan://password@host:port?params#name`
- `hy2://auth@host:port?params#name`

## Настройки

Файл `checker_config.json`:

```json
{
    "check_timeout": 10,
    "check_threads": 50,
    "gemini_endpoint": "https://generativelanguage.googleapis.com/",
    "save_whitelist": true,
    "verbose": true
}
```
