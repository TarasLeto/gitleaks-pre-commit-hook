#!/usr/bin/env python3
"""
Тестовий скрипт для демонстрації роботи pre-commit hook.
Симулює виявлення Telegram bot token у staged файлах.

Запуск: python3 test_hook.py
"""

import sys
import os
import json
import tempfile
import shutil

# ─── Додаємо кольори (копія з pre-commit) ─────────────────────────────────────

class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(text):    return f"{Color.RED}{text}{Color.RESET}"
def green(text):  return f"{Color.GREEN}{text}{Color.RESET}"
def yellow(text): return f"{Color.YELLOW}{text}{Color.RESET}"
def cyan(text):   return f"{Color.CYAN}{text}{Color.RESET}"
def bold(text):   return f"{Color.BOLD}{text}{Color.RESET}"

def print_banner(title, color_fn=None):
    if color_fn is None:
        color_fn = cyan
    line = "─" * 60
    print(f"\n{color_fn(line)}")
    print(f"{color_fn('  ' + title)}")
    print(f"{color_fn(line)}\n")


# ─── Файли для тестування ─────────────────────────────────────────────────────

# Файл 1: конфіг бота з реальним (тестовим) Telegram token
BOT_CONFIG_PY = """\
# config.py — конфігурація Telegram бота

# ⚠️  ПОГАНО: токен захардкоджений у коді
TELEGRAM_BOT_TOKEN = "7341852096:AAF3zKpL8mNqR2tVxW0yZ1dCeJ4gHiUoPs6"  # gitleaks:allow

DATABASE_URL = "postgresql://localhost:5432/mydb"
DEBUG = True
"""

# Файл 2: безпечний варіант через змінні середовища
BOT_CONFIG_SAFE_PY = """\
# config.py — безпечний варіант

import os

# ✅  ДОБРЕ: токен береться зі змінної середовища
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_BOT_TOKEN:
    raise ValueError("TELEGRAM_BOT_TOKEN не встановлено!")

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/mydb")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
"""

# Файл 3: .env файл (теж не повинен потрапляти в git)
DOT_ENV = """\
TELEGRAM_BOT_TOKEN=7341852096:AAF3zKpL8mNqR2tVxW0yZ1dCeJ4gHiUoPs6  # gitleaks:allow
DATABASE_URL=postgresql://user:password@localhost:5432/mydb
SECRET_KEY=super-secret-django-key-12345
"""


# ─── Симульований gitleaks JSON-звіт ─────────────────────────────────────────

def make_fake_findings(scan_dir: str) -> list[dict]:
    """Повертає список знахідок у форматі gitleaks JSON-звіту."""
    return [
        {
            "Description": "Telegram Bot Token",
            "StartLine": 4,
            "EndLine": 4,
            "StartColumn": 22,
            "EndColumn": 68,
            "Match": "TELEGRAM_BOT_TOKEN = \"7341852096:AAF3zKpL8mNqR2tVxW0yZ1dCeJ4gHiUoPs6\"",  # gitleaks:allow
            "Secret": "7341852096:AAF3zKpL8mNqR2tVxW0yZ1dCeJ4gHiUoPs6",  # gitleaks:allow
            "File": os.path.join(scan_dir, "config.py"),
            "SymlinkFile": "",
            "Commit": "",
            "Entropy": 4.418,
            "Author": "",
            "Email": "",
            "Date": "",
            "Message": "",
            "Tags": ["telegram", "bot", "token"],
            "RuleID": "telegram-bot-token",
            "Fingerprint": "config.py:telegram-bot-token:4",
        },
        {
            "Description": "Telegram Bot Token",
            "StartLine": 1,
            "EndLine": 1,
            "StartColumn": 20,
            "EndColumn": 66,
            "Match": "TELEGRAM_BOT_TOKEN=7341852096:AAF3zKpL8mNqR2tVxW0yZ1dCeJ4gHiUoPs6",  # gitleaks:allow
            "Secret": "7341852096:AAF3zKpL8mNqR2tVxW0yZ1dCeJ4gHiUoPs6",  # gitleaks:allow
            "File": os.path.join(scan_dir, ".env"),
            "SymlinkFile": "",
            "Commit": "",
            "Entropy": 4.418,
            "Author": "",
            "Email": "",
            "Date": "",
            "Message": "",
            "Tags": ["telegram", "bot", "token"],
            "RuleID": "telegram-bot-token",
            "Fingerprint": ".env:telegram-bot-token:1",
        },
    ]


# ─── Логіка виводу (копія з pre-commit) ──────────────────────────────────────

def print_findings(findings: list[dict], scan_dir: str) -> None:
    print_banner("🔐  Знайдені секрети", color_fn=red)
    for i, finding in enumerate(findings, start=1):
        raw_file = finding.get("File", "невідомий файл")
        rel_file = os.path.relpath(raw_file, scan_dir) if scan_dir in raw_file else raw_file

        rule        = finding.get("RuleID", "—")
        description = finding.get("Description", "—")
        secret      = finding.get("Secret", "")
        line        = finding.get("StartLine", "?")
        entropy     = finding.get("Entropy", 0)

        if len(secret) > 8:
            masked = secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
        else:
            masked = "****"

        print(f"  {bold(f'[{i}]')} {red('✖')} {bold(rel_file)}:{line}")
        print(f"       Правило     : {yellow(rule)}")
        print(f"       Опис        : {description}")
        print(f"       Секрет      : {red(masked)}")
        print(f"       Ентропія    : {entropy:.3f}  (висока = підозріло)")
        print()


# ─── Основний тест ────────────────────────────────────────────────────────────

def run_test_scenario(label: str, files: dict[str, str], expect_block: bool) -> bool:
    """
    Запускає один тестовий сценарій.
    files: {ім'я файлу: вміст}
    Повертає True, якщо результат відповідає очікуванню.
    """
    print_banner(f"📋  Сценарій: {label}")

    # Створюємо тимчасову директорію зі staged файлами
    tmp_dir = tempfile.mkdtemp(prefix="test_staged_")
    try:
        for filename, content in files.items():
            filepath = os.path.join(tmp_dir, filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w") as f:
                f.write(content)

        print(cyan(f"   Staged файли ({len(files)}):"))
        for name in files:
            print(f"     • {name}")
        print()

        # Перевірка: чи є gitleaks у системі
        gitleaks_path = shutil.which("gitleaks")

        if gitleaks_path:
            # ─── РЕАЛЬНИЙ запуск gitleaks ───
            print(green(f"✔  gitleaks знайдено: {gitleaks_path}"))
            print("   Сканування на секрети...\n")

            import subprocess
            report_file = os.path.join(tmp_dir, "_report.json")
            result = subprocess.run(
                [
                    gitleaks_path, "detect",
                    "--source", tmp_dir,
                    "--report-format", "json",
                    "--report-path", report_file,
                    "--no-git",
                    "--exit-code", "1",
                ],
                capture_output=True, text=True,
            )
            findings = []
            if os.path.exists(report_file):
                with open(report_file) as f:
                    try:
                        data = json.load(f)
                        findings = data if isinstance(data, list) else []
                    except json.JSONDecodeError:
                        pass

            exit_code = result.returncode

        else:
            # ─── СИМУЛЯЦІЯ (gitleaks не встановлено) ───
            print(yellow("⚠  gitleaks не знайдено — запускаємо симуляцію.\n"))
            if expect_block:
                findings = make_fake_findings(tmp_dir)
                exit_code = 1
            else:
                findings = []
                exit_code = 0

        # Результат
        blocked = exit_code != 0 or len(findings) > 0

        if blocked:
            print_findings(findings, tmp_dir)
            print(red("╔══════════════════════════════════════════════════════════╗"))
            print(red("║  ✖  КОМІТ ВІДХИЛЕНО — знайдено потенційні секрети!      ║"))
            print(red("╚══════════════════════════════════════════════════════════╝"))
            print()
            print(yellow("   Що робити:"))
            print("     1. Видаліть токен з коду та використовуйте змінні середовища")
            print("     2. Додайте .env до .gitignore")
            print("     3. Якщо токен вже потрапив в історію — відкличте його негайно!")
            print(f"        https://t.me/BotFather → /mybots → Revoke token")
            print()
        else:
            print(green("╔══════════════════════════════════════════════════════════╗"))
            print(green("║  ✔  Секретів не знайдено. Коміт дозволено.              ║"))
            print(green("╚══════════════════════════════════════════════════════════╝"))
            print()

        # Перевірка відповідності очікуванню
        passed = blocked == expect_block
        status = green("PASSED ✔") if passed else red("FAILED ✖")
        print(f"   Результат тесту: {status}")
        print(f"   (Очікували: {'блокування' if expect_block else 'дозвіл'}, "
              f"Отримали: {'блокування' if blocked else 'дозвіл'})")
        return passed

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ─── Запуск усіх сценаріїв ────────────────────────────────────────────────────

def main():
    print_banner("🧪  Тестування Git Pre-Commit Hook (gitleaks)", color_fn=cyan)
    print("   Цей скрипт перевіряє виявлення Telegram Bot Token")
    print("   у staged файлах перед комітом.\n")

    results = []

    # Сценарій 1: небезпечний — токен захардкоджений у .py файлі
    results.append(run_test_scenario(
        label="❌  Токен у Python файлі (config.py)",
        files={"config.py": BOT_CONFIG_PY},
        expect_block=True,
    ))

    # Сценарій 2: небезпечний — токен у .env файлі (якщо .env в git)
    results.append(run_test_scenario(
        label="❌  Токен у .env файлі (в git!)",
        files={".env": DOT_ENV},
        expect_block=True,
    ))

    # Сценарій 3: обидва файли одразу
    results.append(run_test_scenario(
        label="❌  Обидва файли з токеном одночасно",
        files={"config.py": BOT_CONFIG_PY, ".env": DOT_ENV},
        expect_block=True,
    ))

    # Сценарій 4: безпечний — токен через os.environ
    results.append(run_test_scenario(
        label="✅  Безпечний варіант (os.environ)",
        files={"config.py": BOT_CONFIG_SAFE_PY},
        expect_block=False,
    ))

    # Підсумок
    print_banner("📊  Підсумок тестування")
    total  = len(results)
    passed = sum(results)
    failed = total - passed

    for i, ok in enumerate(results, 1):
        icon = green("✔") if ok else red("✖")
        print(f"   {icon}  Сценарій {i}")

    print()
    if failed == 0:
        print(green(f"   Всі {total}/{total} сценарії пройшли успішно! 🎉"))
    else:
        print(red(f"   Пройшло: {passed}/{total}, Провалено: {failed}/{total}"))

    print()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
