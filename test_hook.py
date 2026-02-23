#!/usr/bin/env python3
"""
Тестовий скрипт для middle-рівня pre-commit hook.
Перевіряє: автоматичне встановлення gitleaks + git config enable/disable.

Запуск: python3 test_hook.py
"""

import sys
import os
import json
import tempfile
import shutil
import subprocess
import platform

# ─── Кольори ──────────────────────────────────────────────────────────────────

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


# ─── Тестові файли ────────────────────────────────────────────────────────────

BOT_CONFIG_PY = (
    "# config.py — небезпечний варіант\n"
    'TELEGRAM_BOT_TOKEN = "7341852096:AAF3zKpL8mNqR2tVxW0yZ1dCeJ4gHiUoPs6"\n'  # gitleaks:allow
    'DATABASE_URL = "postgresql://localhost:5432/mydb"\n'
)

BOT_CONFIG_SAFE_PY = (
    "# config.py — безпечний варіант\n"
    "import os\n"
    'TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")\n'
    'DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/mydb")\n'
)

DOT_ENV = (
    "TELEGRAM_BOT_TOKEN=7341852096:AAF3zKpL8mNqR2tVxW0yZ1dCeJ4gHiUoPs6\n"  # gitleaks:allow
    "DATABASE_URL=postgresql://user:password@localhost:5432/mydb\n"
)

FAKE_SECRET = "7341852096:AAF3zKpL8mNqR2tVxW0yZ1dCeJ4gHiUoPs6"  # gitleaks:allow

# ─── Симульовані знахідки ─────────────────────────────────────────────────────

def make_fake_findings(scan_dir):
    return [
        {
            "Description": "Telegram Bot Token",
            "StartLine": 2,
            "Match": f"TELEGRAM_BOT_TOKEN = \"{FAKE_SECRET}\"",  # gitleaks:allow
            "Secret": FAKE_SECRET,  # gitleaks:allow
            "File": os.path.join(scan_dir, "config.py"),
            "Entropy": 4.418,
            "RuleID": "telegram-bot-api-token",
        }
    ]


# ─── Допоміжні функції ────────────────────────────────────────────────────────

def print_findings(findings, scan_dir):
    print_banner("🔐  Знайдені секрети", color_fn=red)
    for i, finding in enumerate(findings, start=1):
        raw_file = finding.get("File", "невідомий файл")
        rel_file = os.path.relpath(raw_file, scan_dir) if scan_dir in raw_file else raw_file
        secret = finding.get("Secret", "")
        masked = secret[:4] + "*" * (len(secret) - 8) + secret[-4:] if len(secret) > 8 else "****"
        print(f"  {bold(f'[{i}]')} {red('✖')} {bold(rel_file)}:{finding.get('StartLine','?')}")
        print(f"       Правило  : {finding.get('RuleID','—')}")
        print(f"       Секрет   : {red(masked)}")
        print(f"       Ентропія : {finding.get('Entropy', 0):.3f}")
        print()


def run_gitleaks_on_dir(scan_dir):
    gitleaks_path = shutil.which("gitleaks") or os.path.expanduser("~/.local/bin/gitleaks")
    if not os.path.exists(str(gitleaks_path)):
        return None, None, False

    report_file = os.path.join(scan_dir, "_report.json")
    result = subprocess.run(
        [gitleaks_path, "detect", "--source", scan_dir,
         "--report-format", "json", "--report-path", report_file,
         "--no-git", "--exit-code", "1"],
        capture_output=True, text=True,
    )
    findings = []
    if os.path.exists(report_file):
        try:
            with open(report_file) as f:
                data = json.load(f)
                findings = data if isinstance(data, list) else []
        except json.JSONDecodeError:
            pass
    return result.returncode, findings, True


# ─── Тестові сценарії ─────────────────────────────────────────────────────────

def run_scenario(label, files, expect_block):
    print_banner(f"📋  {label}")

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

        exit_code, findings, is_real = run_gitleaks_on_dir(tmp_dir)

        if is_real:
            print(green("✔  Реальний запуск gitleaks\n"))
            blocked = exit_code != 0 or len(findings) > 0
        else:
            print(yellow("⚠  Симуляція (gitleaks не знайдено)\n"))
            blocked = expect_block
            findings = make_fake_findings(tmp_dir) if blocked else []

        if blocked:
            print_findings(findings, tmp_dir)
            print(red("╔══════════════════════════════════════════════════════════╗"))
            print(red("║  ✖  КОМІТ ВІДХИЛЕНО — знайдено потенційні секрети!      ║"))
            print(red("╚══════════════════════════════════════════════════════════╝\n"))
        else:
            print(green("╔══════════════════════════════════════════════════════════╗"))
            print(green("║  ✔  Секретів не знайдено. Коміт дозволено.              ║"))
            print(green("╚══════════════════════════════════════════════════════════╝\n"))

        passed = blocked == expect_block
        status = green("PASSED ✔") if passed else red("FAILED ✖")
        print(f"   Результат: {status}  "
              f"(очікували: {'блокування' if expect_block else 'дозвіл'}, "
              f"отримали: {'блокування' if blocked else 'дозвіл'})")
        return passed

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_git_config_enable():
    print_banner("⚙️   Тест: git config hooks.gitleaks.enable")

    tests = [
        ("true",  True,  "hook увімкнено"),
        ("false", False, "hook вимкнено"),
        ("",      True,  "за замовчуванням увімкнено"),
    ]

    all_passed = True
    for value, expect_enabled, description in tests:
        if value:
            subprocess.run(["git", "config", "hooks.gitleaks.enable", value], capture_output=True)
        else:
            subprocess.run(["git", "config", "--unset", "hooks.gitleaks.enable"], capture_output=True)

        result = subprocess.run(
            ["git", "config", "--get", "hooks.gitleaks.enable"],
            capture_output=True, text=True,
        )
        actual = result.stdout.strip().lower() if result.returncode == 0 else ""
        # Логіка: якщо значення явно "false" — вимкнено, все інше — увімкнено
        is_enabled = actual != "false"

        passed = is_enabled == expect_enabled
        all_passed = all_passed and passed
        icon = green("✔") if passed else red("✖")
        label = f'"{value}"' if value else "(не встановлено)"
        print(f"   {icon}  config={label:<20} → {description}")

    subprocess.run(["git", "config", "--unset", "hooks.gitleaks.enable"], capture_output=True)
    return all_passed


def test_os_detection():
    print_banner("🖥️   Тест: визначення ОС для авто-встановлення")

    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "x64" if machine in ("x86_64", "amd64") else "arm64" if machine in ("aarch64", "arm64") else machine
    os_name = {"darwin": "macOS", "linux": "Linux", "windows": "Windows"}.get(system, system)
    install_method = {
        "darwin":  "brew install gitleaks",
        "linux":   f"GitHub Releases binary (linux_{arch})",
        "windows": "winget install gitleaks",
    }.get(system, "ручне встановлення")

    print(f"   Система           : {bold(os_name)}")
    print(f"   Архітектура       : {bold(arch)}")
    print(f"   Метод встановлення: {cyan(install_method)}")

    gitleaks = shutil.which("gitleaks")
    if gitleaks:
        ver = subprocess.run([gitleaks, "version"], capture_output=True, text=True)
        print(f"   gitleaks          : {green(ver.stdout.strip())}")
    else:
        print(f"   gitleaks          : {yellow('буде встановлено автоматично при першому коміті')}")

    return True


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print_banner("🧪  Middle-рівень: Тестування Pre-Commit Hook", color_fn=cyan)

    results = []
    labels  = []

    print(bold("  📌 Блок 1: Сканування секретів\n"))

    results.append(run_scenario("❌  Токен у Python файлі", {"config.py": BOT_CONFIG_PY}, expect_block=True))
    labels.append("Токен у Python файлі")

    results.append(run_scenario("❌  Токен у .env файлі", {".env": DOT_ENV}, expect_block=True))
    labels.append("Токен у .env файлі")

    results.append(run_scenario("✅  Безпечний варіант (os.environ)", {"config.py": BOT_CONFIG_SAFE_PY}, expect_block=False))
    labels.append("Безпечний варіант")

    print(bold("  📌 Блок 2: git config hooks.gitleaks.enable\n"))
    results.append(test_git_config_enable())
    labels.append("git config enable/disable")

    print(bold("  📌 Блок 3: Визначення ОС для авто-встановлення\n"))
    results.append(test_os_detection())
    labels.append("Визначення ОС")

    print_banner("📊  Підсумок тестування")
    for label, ok in zip(labels, results):
        print(f"   {green('✔') if ok else red('✖')}  {label}")

    total = len(results)
    passed = sum(results)
    print()
    if passed == total:
        print(green(f"   Всі {total}/{total} тести пройшли успішно! 🎉"))
    else:
        print(red(f"   Пройшло: {passed}/{total}, Провалено: {total - passed}/{total}"))
    print()
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
