<div align="center">

# ip-roller

**Selectel VPC — сканер плавающих IP (OpenStack Neutron), dual-аккаунты, Rich-дашборд.**

Короче, README заставили написать — читай, там по делу.

</div>

> [!CAUTION]
>
> ### Секреты и `.env`
> Файл **`.env` с паролями не коммить**. Доверенная копия проекта только у тебя локально; в репозитории смотри **`.env.example`**.

> [!IMPORTANT]
>
> ### Whitelist и удаления
> Адрес, который **попал в `whitelist.txt`** и учтён как **match**, **не должен удаляться** логикой сканера:
>
> - при работе воркеров матч убирается из очереди «своих миссов» и в **DELETE уходит только список промахов**, не матчи;
> - **reconcile** и **cleanup на старте** берут кандидатов только среди **не-whitelist** плавающих IP без привязки к порту (см. `_is_existing_cleanup_candidate` в `scanner/main.py`);
> - при **выходе** чистится только **`owned_unmatched`** — матчи туда не попадают после регистрации.
>
> После **перезапуска** инвентарь подтягивается снова: IP из whitelist заново попадают в `matches`, а не в корзину на удаление.
>
> В **`_delete_records`** стоит явный запрет удалять ресурс, если он уже в **`matches`** или адрес входит в **whitelist** — на случай редких веток «дубликат в батче».

---

## ⚙️ Запуск

Рабочая директория — **корень репозитория** (там лежат `main.py`, `.env`, `whitelist.txt`).  
**`main.py`** сам поднимает **`.venv`**, синхронизирует **`pip install -r requirements.txt`** и при необходимости перезапускается внутри venv — можно вызывать и напрямую через `python`, и через обёртки ниже.

### Все ОС: напрямую

Если **Python 3** в `PATH` (на Windows удобно установщик с галкой *Add python.exe to PATH* или `py` launcher):

```bash
python main.py
```

Аргументы сканера передаются как обычно, например:

```bash
python main.py --help
python main.py --log-file temp/scanner.log
```

### macOS и Linux — `run.sh`

Скрипт переходит в каталог репозитория, при отсутствии `.venv` создаёт его и ставит зависимости, затем запускает `main.py` (с теми же аргументами, что ты передал).

```bash
chmod +x run.sh
./run.sh
./run.sh --help
./run.sh --log-file temp/scanner.log
```

**Не пиши просто `run.sh`** — в zsh/bash текущая папка **не** в `PATH`, будет `command not found`. Нужно **`./run.sh`** или **`bash run.sh`**.

Нужен **bash**. На Linux без `python3` в PATH поставь пакет `python3` / `python3-venv` (названия зависят от дистрибутива).

### Windows — `run.bat`

Двойной клик по **`run.bat`** (консоль откроется и закроется — лучше из терминала) или из **cmd** / **PowerShell**:

```bat
run.bat
run.bat --help
run.bat --log-file temp\scanner.log
```

Используется команда **`python`** из PATH. Если установлен только **`py`**, сначала: `py -m venv .venv`, потом снова `run.bat`, либо правь первую строку запуска на `py main.py` под себя.

### Windows + WSL / Linux в контейнере

В **WSL** или на сервере без GUI веди себя как на Linux: **`run.sh`** или `python3 main.py` из каталога проекта.

### Сводка

| ОС | Удобный вариант | Заметка |
|----|-----------------|--------|
| **macOS** | `./run.sh` или `python3 main.py` | `chmod +x run.sh` один раз |
| **Linux** | `./run.sh` или `python3 main.py` | Установи `python3`, при ошибке venv — пакет `python3-venv` |
| **Windows** | `run.bat` или `python main.py` | Путь без кириллицы в корне диска — меньше сюрпризов с кодировкой |

---

## ✨ Что делает

- Логин в **Keystone** Selectel, из каталога — endpoint **Neutron** по регионам (`ru-1`, `ru-2`, `ru-3`, …).
- В регионах крутит воркеры: **`POST /v2.0/floatingips`**, ждёт появления объекта в API, смотрит адрес.
- Сверка с **`whitelist.txt`** (по умолчанию в корне проекта). Матч — запись в **`temp/selectel-scanner-state.json`** (секции `account-1` / `account-2` у dual).
- **Dual:** первый аккаунт — переменные **`SEL_*`**, второй — **`SEL2_*`**. Лимит **`SEL_MAX_IPS_PER_MINUTE`** — скользящие **60 с на аккаунт** (у каждого воркера свой счётчик).
- Публичная дока Selectel по облаку и floating IP: [Проекты и ресурсы облачной платформы](https://docs.selectel.ru/api/cloud-projects-and-resources/) (создание ресурсов в облаке у них же через **OpenStack API**, что и использует сканер).

---

## 📋 Откуда взять данные для `.env`

Скопируй **`.env.example` → `.env`**. В панели Selectel (названия разделов могут меняться):

| Переменная | Где взять |
|------------|-----------|
| `SEL_USERNAME`, `SEL_PASSWORD` | Пользователь **IAM** для API (раздел пользователей / доступа к API). |
| `SEL_ACCOUNT_ID` | **Номер аккаунта** в биллинге / настройках. |
| `SEL_PROJECT_NAME` или `SEL_PROJECT_ID` | Облако → **проекты** VPC: имя или UUID проекта. |
| `SEL_SERVER_ID_RU2`, `SEL_SERVER_ID_RU3` | Облако → **серверы** в нужном регионе → **UUID** инстанса (удобно для ориентира по зонам; регионы можно задать явно через `SEL*_SCANNER_REGIONS`). |
| `SEL2_*` | То же для **второго** аккаунта. |

Регионы:

- **`SEL1_SCANNER_REGIONS`**, **`SEL2_SCANNER_REGIONS`** — через запятую, напр. `ru-1,ru-2,ru-3`.
- Одиночный режим: **`SEL_SCANNER_REGIONS`**.

Тайминги и лимиты — см. комментарии в **`.env.example`** (ориентир «~30 IP/мин на воркер» и т.д.).

---

## ℹ️ Файлы и состояние

| Путь | Назначение |
|------|------------|
| `run.sh` | Обёртка запуска для **macOS / Linux** (bash). |
| `run.bat` | Обёртка запуска для **Windows** (cmd). |
| `whitelist.txt` | Сети/адреса для матча (по умолчанию). |
| `temp/selectel-scanner-state.json` | Сохранённые матчи по секциям аккаунтов. |
| `scanner/` | Код клиента Neutron, воркеры, стратегия. |

---

## ☑️ Короткий FAQ

### Где смотреть код удаления и whitelist?

`scanner/main.py`: классификация батча **`_classify_allocated`**, очистка **`_cleanup_existing_non_matches`**, **`_reconcile_unbound_non_matches`**, выход **`_cleanup_owned_unmatched`**.

### Не подтягивается зависимость после обновления репо?

`main.py` при каждом старте гоняет **`pip install -r requirements.txt`** в venv — старый `.venv` подтянет новые пакеты.

---

## ⚖️ Лицензия

Уточни по репозиторию, если выкладываешь наружу: отдельный `LICENSE` при необходимости добавь сам.

---

<div align="center">

Если разобрался — пользуйся. Если нет — открой `scanner/main.py` и не ной.

</div>
