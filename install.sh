#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# Gitleaks Pre-Commit Hook — Інсталятор
# Рівень: Senior
#
# Використання (один рядок):
#   curl -sSL https://raw.githubusercontent.com/TarasLeto/gitleaks-pre-commit-hook/main/install.sh | sh
#
# Що робить:
#   1. Перевіряє що ви у git репозиторії
#   2. Визначає ОС і встановлює gitleaks якщо потрібно
#   3. Завантажує pre-commit hook
#   4. Встановлює hook у .git/hooks/
#   5. Вмикає hook через git config
# ─────────────────────────────────────────────────────────────────────────────

set -e  # зупинити при будь-якій помилці

# ─── Кольори ─────────────────────────────────────────────────────────────────

RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

red()    { printf "${RED}%s${RESET}\n" "$1"; }
green()  { printf "${GREEN}%s${RESET}\n" "$1"; }
yellow() { printf "${YELLOW}%s${RESET}\n" "$1"; }
cyan()   { printf "${CYAN}%s${RESET}\n" "$1"; }
bold()   { printf "${BOLD}%s${RESET}\n" "$1"; }

# ─── Конфігурація ────────────────────────────────────────────────────────────

GITLEAKS_VERSION="8.18.4"
REPO_RAW="https://raw.githubusercontent.com/TarasLeto/gitleaks-pre-commit-hook/main"
HOOK_URL="${REPO_RAW}/pre-commit"

# ─── Банер ───────────────────────────────────────────────────────────────────

printf "\n${CYAN}────────────────────────────────────────────────────────────${RESET}\n"
printf "${CYAN}  🔐  Gitleaks Pre-Commit Hook — Інсталятор  [senior]${RESET}\n"
printf "${CYAN}────────────────────────────────────────────────────────────${RESET}\n\n"

# ─── Крок 1: Перевірка git репозиторію ───────────────────────────────────────

printf "  ${BOLD}[1/4]${RESET} Перевірка git репозиторію...\n"

if ! git rev-parse --git-dir > /dev/null 2>&1; then
    red "  ✖  Не знайдено git репозиторій!"
    yellow "     Запустіть інсталятор з кореневої папки вашого проекту."
    yellow "     Або спочатку: git init"
    exit 1
fi

GIT_ROOT=$(git rev-parse --show-toplevel)
HOOKS_DIR="${GIT_ROOT}/.git/hooks"
mkdir -p "${HOOKS_DIR}"

green "  ✔  Git репозиторій знайдено: ${GIT_ROOT}"

# ─── Крок 2: Визначення ОС та встановлення gitleaks ──────────────────────────

printf "\n  ${BOLD}[2/4]${RESET} Перевірка gitleaks...\n"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Нормалізуємо архітектуру
case "${ARCH}" in
    x86_64|amd64) ARCH="x64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l) ARCH="armv7" ;;
esac

if command -v gitleaks > /dev/null 2>&1; then
    GITLEAKS_VERSION_INSTALLED=$(gitleaks version 2>/dev/null || echo "невідомо")
    green "  ✔  gitleaks вже встановлено: ${GITLEAKS_VERSION_INSTALLED}"
else
    yellow "  ⚠  gitleaks не знайдено — встановлюємо автоматично..."
    printf "     ОС: %s | Архітектура: %s\n" "${OS}" "${ARCH}"

    case "${OS}" in
        darwin)
            if command -v brew > /dev/null 2>&1; then
                printf "     Встановлення через Homebrew...\n"
                brew install gitleaks
            else
                red "  ✖  Homebrew не знайдено. Встановіть з https://brew.sh"
                exit 1
            fi
            ;;

        linux)
            FILENAME="gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz"
            DOWNLOAD_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${FILENAME}"
            INSTALL_DIR="${HOME}/.local/bin"
            mkdir -p "${INSTALL_DIR}"

            printf "     Завантаження ${FILENAME}...\n"

            if command -v curl > /dev/null 2>&1; then
                curl -sSL "${DOWNLOAD_URL}" | tar -xz -C /tmp gitleaks
            elif command -v wget > /dev/null 2>&1; then
                wget -qO- "${DOWNLOAD_URL}" | tar -xz -C /tmp gitleaks
            else
                red "  ✖  Потрібен curl або wget"
                exit 1
            fi

            mv /tmp/gitleaks "${INSTALL_DIR}/gitleaks"
            chmod +x "${INSTALL_DIR}/gitleaks"

            # Перевіряємо PATH
            case ":${PATH}:" in
                *":${INSTALL_DIR}:"*) ;;
                *)
                    yellow "     ⚠  Додайте до ~/.bashrc або ~/.zshrc:"
                    yellow "        export PATH=\"\$PATH:${INSTALL_DIR}\""
                    ;;
            esac

            green "  ✔  gitleaks встановлено: ${INSTALL_DIR}/gitleaks"
            ;;

        *)
            red "  ✖  Непідтримувана ОС: ${OS}"
            yellow "     Встановіть gitleaks вручну:"
            yellow "     https://github.com/gitleaks/gitleaks/releases"
            exit 1
            ;;
    esac
fi

# ─── Крок 3: Завантаження та встановлення hook ───────────────────────────────

printf "\n  ${BOLD}[3/4]${RESET} Встановлення pre-commit hook...\n"

HOOK_PATH="${HOOKS_DIR}/pre-commit"

# Backup якщо вже існує
if [ -f "${HOOK_PATH}" ]; then
    BACKUP="${HOOK_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
    yellow "  ⚠  Знайдено існуючий hook — збережено як backup:"
    yellow "     ${BACKUP}"
    cp "${HOOK_PATH}" "${BACKUP}"
fi

# Завантажуємо hook
printf "     Завантаження hook з GitHub...\n"

if command -v curl > /dev/null 2>&1; then
    curl -sSL "${HOOK_URL}" -o "${HOOK_PATH}"
elif command -v wget > /dev/null 2>&1; then
    wget -qO "${HOOK_PATH}" "${HOOK_URL}"
else
    red "  ✖  Потрібен curl або wget"
    exit 1
fi

chmod +x "${HOOK_PATH}"
green "  ✔  Hook встановлено: ${HOOK_PATH}"

# ─── Крок 4: Налаштування git config ─────────────────────────────────────────

printf "\n  ${BOLD}[4/4]${RESET} Налаштування git config...\n"

git config hooks.gitleaks.enable true
green "  ✔  hooks.gitleaks.enable = true"

# ─── Підсумок ─────────────────────────────────────────────────────────────────

printf "\n${GREEN}────────────────────────────────────────────────────────────${RESET}\n"
printf "${GREEN}  ✔  Встановлення завершено успішно!${RESET}\n"
printf "${GREEN}────────────────────────────────────────────────────────────${RESET}\n\n"

printf "  Що далі:\n\n"
printf "  • Зробіть будь-який коміт — hook запуститься автоматично\n"
printf "  • Щоб вимкнути hook:\n"
printf "      git config hooks.gitleaks.enable false\n"
printf "  • Щоб пропустити одноразово:\n"
printf "      SKIP_GITLEAKS=1 git commit\n\n"
