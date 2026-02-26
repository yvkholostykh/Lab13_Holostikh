"""
VirusTotal API Client
Скрипт для получения статуса сканирования файла через VirusTotal API.

КАК ЗАПУСТИТЬ:
1. Установите API‑ключ в переменную окружения VT_API_KEY:
   - Windows: set VT_API_KEY="Ваш API ключ"
   - Linux/Mac: export VT_API_KEY=""Ваш API ключ""
2. Запустите скрипт: python virustotal_api.py
3. Введите хеш файла (MD5/SHA1/SHA256) при запросе

ТРЕБУЕМЫЕ БИБЛИОТЕКИ:
- requests (установите через pip install requests)
- json (встроен в Python)
"""

import os
import json
import requests

# Константы
VT_API_URL = "https://www.virustotal.com/api/v3/files/"
OUTPUT_FILE = "virustotal_response.json"

def get_api_key():
    """
    Возвращает жёстко заданный API‑ключ (только для тестирования).
    В продакшене используйте переменные окружения.
    """
    return ""Ваш API ключ""
    """
    Получает API‑ключ из переменной окружения VT_API_KEY.
    Возвращает: API‑ключ или None, если не найден.
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("ОШИБКА: API‑ключ не найден в переменной окружения VT_API_KEY")
        print("Установите переменную с вашим ключом:")
        print("export VT_API_KEY='"Ваш API ключ"'")
        return None
    return api_key

def make_api_request(file_hash, api_key):
    """
    Выполняет запрос к VirusTotal API для проверки файла.

    Параметры:
    - file_hash: хеш файла для проверки (MD5, SHA1 или SHA256)
    - api_key: API‑ключ VirusTotal

    Возвращает: JSON‑ответ от API или None при ошибке.
    """
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    url = f"{VT_API_URL}{file_hash}"

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            print("✓ Успешный запрос к API")
            return response.json()
        elif response.status_code == 404:
            print("Файл с таким хешем не найден в базе VirusTotal")
            return None
        else:
            print(f"Ошибка API: код {response.status_code}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Ошибка соединения: {e}")
        return None

def save_json_response(data, filename):
    """
    Сохраняет JSON‑ответ в файл.

    Параметры:
    - data: JSON‑данные для сохранения
    - filename: имя файла для записи
    """
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print(f"✓ JSON‑ответ сохранён в файл: {filename}")

def display_scan_status(data):
    """
    Выводит основные данные о статусе сканирования.

    Параметр:
    - data: JSON‑ответ от API
    """
    if not data:
        return

    print("\n" + "="*50)
    print("РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
    print("="*50)

    # Извлекаем основные данные
    file_data = data.get("data", {})
    attributes = file_data.get("attributes", {})

    # Статус сканирования
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    print(f"Статус: {file_data.get('type', 'N/A')}")
    print(f"Обнаружено вредоносных: {last_analysis_stats.get('malicious', 0)}")
    print(f"Подозрительных: {last_analysis_stats.get('suspicious', 0)}")
    print(f"Безопасных: {last_analysis_stats.get('harmless', 0)}")
    print(f"Не определено: {last_analysis_stats.get('undetected', 0)}")

    # Информация о файле
    print(f"\nИнформация о файле:")
    print(f"Размер: {attributes.get('size', 'N/A')} байт")
    print(f"Тип файла: {attributes.get('type_description', 'N/A')}")
    print(f"Имя файла: {attributes.get('names', ['N/A'])[0]}")

    # Правила фильтрации (если есть)
    rules = attributes.get("rules", {})
    if rules:
        print(f"\nПравила фильтрации:")
        for rule_name, rule_data in rules.items():
            print(f"  {rule_name}: {rule_data}")
    else:
        print(f"\nПравила фильтрации: не найдены")

def main():
    """
    Основная функция скрипта.
    """
    print("VirusTotal API Scanner")
    print("-" * 30)

    # Получаем API‑ключ
    api_key = get_api_key()
    if not api_key:
        return

    # Запрашиваем хеш файла у пользователя
    file_hash = input("Введите хеш файла для проверки (MD5/SHA1/SHA256): ").strip()
    if not file_hash:
        print("Ошибка: хеш не может быть пустым")
        return

    print(f"Проверяем файл с хешем: {file_hash}")

    # Выполняем запрос к API
    response_data = make_api_request(file_hash, api_key)

    if response_data:
        # Сохраняем полный JSON в файл
        save_json_response(response_data, OUTPUT_FILE)

        # Выводим основные результаты
        display_scan_status(response_data)
    else:
        print("Не удалось получить данные от API")

if __name__ == "__main__":
    main()
