# 📊 Stepik Stats Dashboard

Автоматический сбор статистики курсов Stepik с ежедневным обновлением через GitHub Actions и публикацией на GitHub Pages.

## Как это работает

1. **GitHub Actions** запускает `stepik_tracker.py` каждый день в 11:00 по Москве
2. Скрипт собирает данные через Stepik API и обновляет `stepik_stats.json` + `stepik_report.html`
3. Изменения коммитятся обратно в репозиторий
4. **GitHub Pages** раздаёт `stepik_report.html` по публичному URL
5. HTML-отчёт защищён паролем через AES-256-GCM шифрование — данные в файле зашифрованы и видны только после ввода пароля

---

## Первоначальная настройка

### 1. Создать репозиторий на GitHub

```bash
git init
git add .
git commit -m "init: stepik stats tracker"
```

Создай новый репозиторий на [github.com/new](https://github.com/new), затем:

```bash
git remote add origin https://github.com/YOUR_USERNAME/stepik-stats.git
git branch -M main
git push -u origin main
```

### 2. Добавить секреты в GitHub

Открой **Settings → Secrets and variables → Actions → New repository secret** и добавь три секрета:

| Название              | Значение                        |
|-----------------------|---------------------------------|
| `STEPIK_CLIENT_ID`    | твой Client ID из Stepik API    |
| `STEPIK_CLIENT_SECRET`| твой Client Secret из Stepik API|
| `DASHBOARD_PASSWORD`  | пароль для просмотра дашборда   |

> **Где взять Stepik API ключи:** [stepik.org/oauth2/applications/](https://stepik.org/oauth2/applications/) → создай приложение с grant type "Client credentials"

> **Пароль дашборда:** придумай любой, например `Stepik2024!` — он нигде не хранится в открытом виде, только как GitHub Secret. Запомни его сам.

### 3. Включить GitHub Pages

Открой **Settings → Pages** в репозитории:
- Source: **Deploy from a branch**
- Branch: `main` / `/ (root)`
- Сохрани

После этого дашборд будет доступен по адресу:
```
https://YOUR_USERNAME.github.io/stepik-stats/stepik_report.html
```

### 4. Запустить первый раз вручную

Открой вкладку **Actions** в репозитории → `Daily Stepik Stats` → **Run workflow**.

---

## Структура файлов

```
.
├── stepik_tracker.py          # основной скрипт сбора данных
├── stepik_stats.json          # исторические данные (растёт со временем)
├── stepik_report.html         # зашифрованный HTML-дашборд
├── .github/
│   └── workflows/
│       └── daily.yml          # расписание GitHub Actions
└── README.md
```

## Локальный запуск

```bash
export STEPIK_CLIENT_ID="..."
export STEPIK_CLIENT_SECRET="..."
export DASHBOARD_PASSWORD="твой_пароль"
pip install requests cryptography
python stepik_tracker.py
```

Открой `stepik_report.html` в браузере и введи пароль.

---

## Безопасность

- Данные дашборда зашифрованы алгоритмом **AES-256-GCM**
- Ключ шифрования получается из пароля через **PBKDF2** (100 000 итераций, SHA-256)
- Расшифровка происходит **только в браузере** пользователя — сервер (GitHub Pages) видит только зашифрованный blob
- Даже имея доступ к репозиторию, прочитать данные без пароля невозможно
