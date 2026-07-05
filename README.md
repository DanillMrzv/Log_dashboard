# Nginx / Apache Log Analyzer \& Incident Dashboard

Веб-инструмент для визуального анализа access-логов веб-сервера (Combined
Log Format — стандарт nginx и Apache). Загружаете лог через браузер —
получаете дашборд трафика, автоматическое обнаружение брутфорса, всплесков
нагрузки и попыток сканирования уязвимостей, фильтрацию и выгрузку данных.

Сделан как тестовое задание для компании, предоставляющей услуги хостинга,
доменов и серверов — поэтому акцент сделан не на общей веб-аналитике
"посещаемости", а на том, что реально ищет админ/support при разборе
инцидента на клиентском сервере.

\---

## Содержание

* [Что умеет](#что-умеет)
* [Структура проекта](#структура-проекта)
* [Архитектурные решения — и почему именно так](#архитектурные-решения--и-почему-именно-так)
* [Используемые библиотеки и подходы](#используемые-библиотеки-и-подходы)
* [Полный код](#полный-код)
* [Быстрый запуск на удалённом сервере](#быстрый-запуск-на-удалённом-сервере)
* [Как проверялась работоспособность](#как-проверялась-работоспособность)
* [Что было найдено и исправлено в процессе](#что-было-найдено-и-исправлено-в-процессе)
* [Осознанные ограничения](#осознанные-ограничения)
* [Что было бы иначе для настоящего продакшена](#что-было-бы-иначе-для-настоящего-продакшена)

\---

## Что умеет



**Дашборд** — активность по часам, топ-10 URL, распределение HTTP-статусов,
доля бот-трафика. KPI-карточки: всего запросов, уникальные IP, доля ошибок,
отдельно — сбои хостинга (502/504) и ошибки кода сайта (500).



**Безопасность** — автоматическое обнаружение сканирования уязвимостей по
сигнатурам URL: WordPress-эндпоинты, утечки конфигов (`.env`, `.git`),
админ-панели, бэкапы, вебшеллы, path traversal, SQLi-паттерны. Топ IP-адресов
сканеров и разбивка по категориям атак.



**Брутфорс и аномалии** — детект брутфорса (IP, превысившие N попыток с
кодами 401/403 за скользящее окно), детект всплесков трафика (статистический
подход, потенциальный DDoS) с разбивкой по числу уникальных IP в аномальном
интервале, и отдельно — детект одиночного источника аномальной активности.
Все пороги настраиваются прямо в интерфейсе.



**Сравнение логов** — режим "до / после инцидента": сводная таблица метрик,
новые IP, новые источники сканирования.



**Фильтры** — по типу трафика (люди/боты/всё), диапазону дат, IP,
HTTP-статусу, с возможностью исключить список IP (свои мониторинги,
health-check балансировщика).



**Экспорт** — CSV с разделителем `;` и BOM (открывается в русском Excel без
"кракозябр"), JSON, отдельные выгрузки списков брутфорс-IP и атак.



**Демо-режим** — кнопка "Загрузить демо-лог" сразу показывает все разделы
дашборда на встроенном тестовом логе с намеренными инцидентами, без
необходимости искать свой access.log.

\---

## Структура проекта



```
log\_dashboard/
├── app.py                  # UI-слой (Streamlit) — только интерфейс
├── analysis.py             # Вся аналитика — парсинг, детекция инцидентов
├── requirements.txt        # Зависимости с зафиксированными версиями
├── .streamlit/
│   └── config.toml         # Продакшн-конфиг (порт, лимит загрузки, тема)
├── deploy/
│   ├── nginx.conf                # Reverse proxy конфиг
│   ├── log-analyzer.service      # systemd unit (автозапуск/автовосстановление)
│   └── DEPLOY.md                  # Пошаговый деплой на чистый Ubuntu
└── sample-data/
    └── sample\_access.log         # Демо-лог с намеренными инцидентами
```



**Почему `analysis.py` отделён от `app.py`.** Вся логика парсинга и детекции
инцидентов — чистые функции на pandas, ничего не знающие о существовании
Streamlit. Это позволяет тестировать логику напрямую, без запуска веб-сервера,
и не размазывает бизнес-логику по UI-виджетам (частая проблема Streamlit-кода,
которая делает его нетестируемым).



\---

## Архитектурные решения — и почему именно так



**Почему детекция инцидентов, а не только "аналитика посещаемости".**
Конечный пользователь такого инструмента в хостинг-компании — это админ или
support, который открывает лог не из любопытства, а когда что-то уже
случилось. Поэтому в приоритете: кто ломится на `/wp-login.php`, кто сканирует
`.env`/`.git`, не заваливает ли сервер один агрессивный IP или это
распределённая нагрузка — а не просто "сколько было визитов".



**Почему скользящее окно (two-pointer), а не деление на фиксированные
интервалы, для брутфорса.** Наивная реализация "разбить время на 5-минутные
блоки и посчитать попытки в каждом" пропустит атаку, если она пришлась ровно
на границу двух блоков (например, 3 минуты в одном блоке + 3 минуты в
следующем — итого 6 минут интенсивной атаки, но ни один блок по отдельности
не показывает превышения). Скользящее окно с двумя указателями проверяет
вообще все возможные окна, а не только выровненные по границам, и при этом
остаётся линейным по времени на каждый IP.



**Почему z-score (статистический подход), а не жёсткий порог, для всплесков
трафика.** Жёсткий порог типа "больше 1000 запросов в минуту — тревога"
требует заранее знать, какая нагрузка нормальна именно для этого сайта — для
маленького блога и крупного магазина это разные цифры. Z-score считает порог
из самих данных: интервал считается аномальным, если превышает среднее по
логу на несколько стандартных отклонений — то есть "статистически
неожиданно" для конкретно этого сайта, а не по абсолютному числу.



**Почему кэширование детекторов было добавлено отдельно от кэширования
парсинга.** Streamlit перезапускает весь скрипт на каждый клик в интерфейсе.
Парсинг файла кэшировался с самого начала (иначе загрузка была бы
мучительной), но детекторы инцидентов изначально пересчитывались заново на
любое действие — даже не связанное с детекцией (например, смену фильтра по
типу трафика). Это всплыло как реальная просадка производительности на
логе в 50+ тысяч строк и было исправлено кэшированием по хэшу данных +
значениям порогов (подробнее — в разделе "что было найдено и исправлено").

\---

## Используемые библиотеки и подходы



**Streamlit** — превращает обычный Python-скрипт в веб-интерфейс без
отдельного фронтенда: `st.button()`, `st.slider()`, `st.dataframe()` и т.д.
сами рендерятся в браузере. Ключевая особенность: при любом клике весь
скрипт перезапускается сверху вниз — без кэширования тяжёлых вычислений это
означает, что любое действие пересчитывает всё заново.



**pandas** — все данные лога хранятся как DataFrame, агрегации ("топ-10 IP",
"запросы по часам") делаются векторизованными операциями pandas, а не
ручными циклами по строкам. Векторизация — операция применяется сразу ко
всему столбцу на уровне C, а не построчно на уровне Python; на больших логах
разница на порядки.



**plotly (plotly.express)** — интерактивные графики (зум, наведение) "из
коробки", без дополнительного кода, в отличие от статичных графиков
matplotlib.



**re (регулярные выражения) — для парсинга лога.** Access-log — обычный
текст фиксированного формата, поэтому одно регулярное выражение с
именованными группами разбирает строку на IP/время/URL/статус за один
проход.



**re — для детекции ботов и сигнатур атак.** Тот же инструмент для другой
задачи: проверка, содержит ли user-agent ключевые слова (`bot`, `crawl`,
`spider`), и содержит ли URL паттерны атак (`.env`, `wp-login`, `phpmyadmin`).
Самый быстрый способ проверить это сразу по всей таблице одной командой.

**Скользящее окно (two-pointer)** — для брутфорса и одиночных всплесков, см.
раздел выше.



**Статистический подход (z-score)** — для всплесков трафика, см. раздел выше.

**dataclasses (`ParseReport`)** — структурированный результат парсинга
(сколько строк обработано/пропущено, примеры ошибок) без ручного
`\_\_init\_\_`.



**hashlib** — MD5 не ради криптографии, а как быстрый "отпечаток" содержимого
файла, чтобы Streamlit понимал, что файл не изменился, и брал результат из
кэша вместо повторного парсинга.



**st.cache\_data** — механизм "если функция уже вызывалась с такими же
аргументами — верни готовый результат". Отсутствие этого на детекторах и
было причиной тормозов, описанных ниже.



**cProfile** — встроенный профилировщик Python, использовался в разработке
для поиска реального узкого места по времени.

\---

## Полный код



### `analysis.py`



```python
"""
analysis.py — вся аналитическая логика Nginx/Apache Log Analyzer,
отделённая от Streamlit-интерфейса. Тестируется напрямую через pytest
или интерактивно, без поднятия веб-приложения.
"""
from \_\_future\_\_ import annotations

import re
import io
from dataclasses import dataclass, field

import pandas as pd


# =========================================================================
# 1. ПАРСИНГ ЛОГОВ
# =========================================================================

# Combined Log Format — покрывает и nginx, и Apache (формат идентичен).
# Поддерживаем и вариант с $request\_time в хвосте строки (частое
# кастомное расширение log\_format в nginx), если он есть — используем,
# если нет — просто игнорируем недостающую группу.
LOG\_PATTERN = re.compile(
    r'(?P<ip>\\S+) \\S+ \\S+ \\\[(?P<datetime>\[^\\]]+)\\] '
    r'"(?P<method>\[A-Z]+|-)\\s?(?P<url>\\S\*)\\s?(?:HTTP/\[\\d.]+)?" '
    r'(?P<status>\\d{3}) (?P<size>\\S+) '
    r'"(?P<referrer>\[^"]\*)" "(?P<user\_agent>\[^"]\*)"'
    r'(?:\\s+(?P<request\_time>\[\\d.]+))?'
)

REQUIRED\_GROUPS = {"ip", "datetime", "method", "url", "status", "size"}

# Ключевые слова для определения бот-трафика по User-Agent. Это стандартный
# подход для лог-анализаторов (GoAccess, AWStats и т.п.) — полноценный разбор
# UA (браузер/ОС/устройство) через тяжёлые библиотеки избыточен, когда нужен
# только булев признак "бот/не бот", а на больших логах это заметно быстрее
# (векторизованная regex-проверка вместо построчного парсинга в Python).
BOT\_UA\_PATTERN = re.compile(
    r"bot|crawl|spider|slurp|mediapartners|facebookexternalhit|whatsapp|"
    r"telegrambot|applebot|bingpreview|archiver|ahrefs|semrush|mj12bot|dotbot|"
    r"petalbot|sogou|exabot|python-requests|curl/|wget/|scrapy|go-http-client|"
    r"libwww-perl|headlesschrome|phantomjs|selenium|python-urllib",
    re.IGNORECASE,
)


@dataclass
class ParseReport:
    total\_lines: int = 0
    parsed: int = 0
    skipped: int = 0
    skipped\_sample: list\[str] = field(default\_factory=list)
    unparsed\_datetime: int = 0


def parse\_log(raw\_text: str) -> tuple\[pd.DataFrame, ParseReport]:
    """Парсит текст access-лога в DataFrame. Не падает на кривых строках —
    пропускает их и репортит количество/примеры, чтобы админ видел, что
    часть данных не учтена, а не тихо получал неполную картину."""
    report = ParseReport()
    rows = \[]

    lines = raw\_text.splitlines()
    report.total\_lines = len(lines)

    for line in lines:
        if not line.strip():
            continue
        m = LOG\_PATTERN.match(line)
        if not m:
            report.skipped += 1
            if len(report.skipped\_sample) < 5:
                report.skipped\_sample.append(line\[:200])
            continue
        d = m.groupdict()
        rows.append(d)
        report.parsed += 1

    if not rows:
        return pd.DataFrame(), report

    df = pd.DataFrame(rows)

    # Типы
    df\["status"] = pd.to\_numeric(df\["status"], errors="coerce").fillna(0).astype(int)
    df\["size"] = pd.to\_numeric(df\["size"], errors="coerce").fillna(0).astype(int)
    if "request\_time" in df.columns:
        df\["request\_time"] = pd.to\_numeric(df\["request\_time"], errors="coerce")

    # Дата: "10/Oct/2023:13:55:36 +0300" -> берём датувремя + сохраняем офсет отдельно
    dt\_main = df\["datetime"].str.extract(r"^(\[^\\s]+) (\[+-]\\d{4})$")
    df\["datetime"] = pd.to\_datetime(
        dt\_main\[0], format="%d/%b/%Y:%H:%M:%S", errors="coerce"
    )
    df\["tz\_offset"] = dt\_main\[1]

    report.unparsed\_datetime = int(df\["datetime"].isna().sum())
    df = df.dropna(subset=\["datetime"]).reset\_index(drop=True)

    df\["date"] = df\["datetime"].dt.date
    df\["hour"] = df\["datetime"].dt.hour

    # Боты — быстрая векторизованная проверка по ключевым словам в UA
    # (см. BOT\_UA\_PATTERN), вместо построчного разбора тяжёлой библиотекой.
    df\["is\_bot"] = df\["user\_agent"].str.contains(BOT\_UA\_PATTERN, na=False)

    return df, report


# =========================================================================
# 2. СИГНАТУРЫ АТАК / СКАНИРОВАНИЯ
# =========================================================================

ATTACK\_SIGNATURES = {
    "wp-login / WordPress": \["wp-login", "wp-admin", "wp-content", "xmlrpc.php"],
    "Утечка конфигов": \[".env", ".git", "config.php", "docker-compose", ".htaccess", "web.config"],
    "Админ-панели": \["phpmyadmin", "/admin", "/administrator", "pma/"],
    "Backup / архивы": \[".sql", ".bak", ".zip", ".tar.gz", "backup"],
    "Shell / вебшеллы": \["shell.php", "cmd.php", "c99", "eval(", "base64\_decode"],
    "Path traversal": \["../", "..%2f", "%2e%2e"],
    "SQLi-паттерны": \["union+select", "union select", "' or 1=1", "1=1--"],
}


def detect\_attack\_signatures(df: pd.DataFrame) -> pd.DataFrame:
    """Помечает строки, чей URL совпал с известными паттернами сканирования
    уязвимостей. Возвращает только совпавшие строки + категорию атаки."""
    if df.empty:
        return df.assign(attack\_category=pd.Series(dtype=str))

    url\_lower = df\["url"].str.lower()
    matches = \[]

    for category, patterns in ATTACK\_SIGNATURES.items():
        mask = pd.Series(False, index=df.index)
        for p in patterns:
            mask |= url\_lower.str.contains(re.escape(p.lower()), regex=True, na=False)
        if mask.any():
            hit = df\[mask].copy()
            hit\["attack\_category"] = category
            matches.append(hit)

    if not matches:
        return df.iloc\[0:0].assign(attack\_category=pd.Series(dtype=str))

    return pd.concat(matches, ignore\_index=True)


# =========================================================================
# 3. ОБНАРУЖЕНИЕ БРУТФОРСА
# =========================================================================

def detect\_bruteforce(
    df: pd.DataFrame,
    status\_codes: tuple\[int, ...] = (401, 403),
    min\_attempts: int = 10,
    window\_minutes: int = 5,
) -> pd.DataFrame:
    """
    Ищет IP, которые за скользящее окно `window\_minutes` минут дали
    не менее `min\_attempts` ответов с кодами из `status\_codes`.

    Возвращает по одной строке на IP: пик интенсивности (макс. число
    попыток в любом окне), общее число попыток, целевые URL, период.
    """
    cols = \["ip", "datetime", "status", "url"]
    if df.empty or not set(cols).issubset(df.columns):
        return pd.DataFrame(columns=\["ip", "attempts\_total", "max\_in\_window", "urls", "first\_seen", "last\_seen"])

    auth\_fails = df\[df\["status"].isin(status\_codes)]\[cols].sort\_values("datetime")
    if auth\_fails.empty:
        return pd.DataFrame(columns=\["ip", "attempts\_total", "max\_in\_window", "urls", "first\_seen", "last\_seen"])

    results = \[]
    window = pd.Timedelta(minutes=window\_minutes)

    for ip, group in auth\_fails.groupby("ip"):
        times = group\["datetime"].reset\_index(drop=True)
        max\_in\_window = 0
        # Скользящее окно по отсортированным меткам времени — O(n) через два указателя
        left = 0
        for right in range(len(times)):
            while times\[right] - times\[left] > window:
                left += 1
            max\_in\_window = max(max\_in\_window, right - left + 1)

        if max\_in\_window >= min\_attempts:
            results.append({
                "ip": ip,
                "attempts\_total": len(group),
                "max\_in\_window": max\_in\_window,
                "urls": ", ".join(sorted(group\["url"].value\_counts().head(3).index)),
                "first\_seen": group\["datetime"].min(),
                "last\_seen": group\["datetime"].max(),
            })

    if not results:
        return pd.DataFrame(columns=\["ip", "attempts\_total", "max\_in\_window", "urls", "first\_seen", "last\_seen"])

    return pd.DataFrame(results).sort\_values("max\_in\_window", ascending=False).reset\_index(drop=True)


# =========================================================================
# 4. АНОМАЛИИ ТРАФИКА (ВОЗМОЖНЫЙ DDoS)
# =========================================================================

def detect\_traffic\_spikes(
    df: pd.DataFrame,
    bucket: str = "1min",
    sigma\_threshold: float = 3.0,
    min\_bucket\_requests: int = 20,
) -> pd.DataFrame:
    """
    Бьёт трафик на равные интервалы (`bucket`), считает среднее и
    стандартное отклонение по числу запросов в интервале, и помечает
    интервалы, которые превышают mean + sigma\_threshold\*std.

    min\_bucket\_requests — отсекает статистический шум на малых логах
    (всплеск с 2 до 8 запросов формально "аномалия", но бессмысленна).
    """
    if df.empty or "datetime" not in df.columns:
        return pd.DataFrame(columns=\["bucket\_start", "requests", "unique\_ips", "z\_score"])

    s = df.set\_index("datetime").resample(bucket).size()
    if len(s) < 3:
        return pd.DataFrame(columns=\["bucket\_start", "requests", "unique\_ips", "z\_score"])

    mean, std = s.mean(), s.std(ddof=0)
    if std == 0:
        return pd.DataFrame(columns=\["bucket\_start", "requests", "unique\_ips", "z\_score"])

    z = (s - mean) / std
    spikes = s\[(z >= sigma\_threshold) \& (s >= min\_bucket\_requests)]

    if spikes.empty:
        return pd.DataFrame(columns=\["bucket\_start", "requests", "unique\_ips", "z\_score"])

    unique\_ips = df.set\_index("datetime")\["ip"].resample(bucket).nunique()

    result = pd.DataFrame({
        "bucket\_start": spikes.index,
        "requests": spikes.values,
        "unique\_ips": unique\_ips.loc\[spikes.index].values,
        "z\_score": z.loc\[spikes.index].round(2).values,
    }).sort\_values("requests", ascending=False).reset\_index(drop=True)

    return result


def detect\_single\_source\_bursts(
    df: pd.DataFrame,
    window\_seconds: int = 10,
    min\_requests: int = 30,
) -> pd.DataFrame:
    """
    Отдельно от общих всплесков трафика — ищет отдельные IP, выдавшие
    аномально много запросов за короткое окно (`window\_seconds`).
    Это отличает "один агрессивный источник" (вероятный DoS/скан) от
    органического роста трафика с разных IP.
    """
    cols = \["ip", "datetime"]
    if df.empty or not set(cols).issubset(df.columns):
        return pd.DataFrame(columns=\["ip", "max\_requests\_in\_window", "total\_requests"])

    window = pd.Timedelta(seconds=window\_seconds)
    results = \[]

    for ip, group in df\[cols].sort\_values("datetime").groupby("ip"):
        if len(group) < min\_requests:
            continue
        times = group\["datetime"].reset\_index(drop=True)
        max\_in\_window = 0
        left = 0
        for right in range(len(times)):
            while times\[right] - times\[left] > window:
                left += 1
            max\_in\_window = max(max\_in\_window, right - left + 1)
        if max\_in\_window >= min\_requests:
            results.append({"ip": ip, "max\_requests\_in\_window": max\_in\_window, "total\_requests": len(group)})

    if not results:
        return pd.DataFrame(columns=\["ip", "max\_requests\_in\_window", "total\_requests"])

    return pd.DataFrame(results).sort\_values("max\_requests\_in\_window", ascending=False).reset\_index(drop=True)


# =========================================================================
# 5. ЭКСПОРТ (CSV под русский Excel)
# =========================================================================

def to\_excel\_csv\_bytes(df: pd.DataFrame) -> bytes:
    """CSV с разделителем ';' и BOM (utf-8-sig) — открывается в русском
    Excel без «кракозябр» и без разъезжания колонок по запятым внутри URL."""
    buf = io.StringIO()
    df.to\_csv(buf, sep=";", index=False)
    return buf.getvalue().encode("utf-8-sig")
```



### `app.py`



```python
"""
app.py — Nginx/Apache Log Analyzer \& Incident Dashboard.

UI-слой. Вся аналитика вынесена в analysis.py и не зависит от Streamlit —
её можно тестировать напрямую (см. analysis.py).
"""
import hashlib
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from analysis import (
    parse\_log,
    detect\_attack\_signatures,
    detect\_bruteforce,
    detect\_traffic\_spikes,
    detect\_single\_source\_bursts,
    to\_excel\_csv\_bytes,
)

st.set\_page\_config(layout="wide", page\_title="Log Analyzer \& Incident Dashboard", page\_icon="📊")


# =========================================================================
# КЭШИРУЕМЫЙ ПАРСИНГ
# =========================================================================

@st.cache\_data(show\_spinner="Разбираю лог-файл…")
def cached\_parse(file\_bytes: bytes, \_cache\_key: str):
    text = file\_bytes.decode("utf-8", errors="ignore")
    return parse\_log(text)


def load\_uploaded\_file(uploaded\_file):
    raw = uploaded\_file.getvalue()
    cache\_key = hashlib.md5(raw).hexdigest()
    df, report = cached\_parse(raw, cache\_key)
    return df, report, cache\_key


DEMO\_LOG\_PATH = Path(\_\_file\_\_).parent / "sample-data" / "sample\_access.log"


def load\_demo\_file():
    """Загружает лог, вшитый в проект — с намеренно встроенными брутфорсом,
    сканированием уязвимостей и всплеском трафика, чтобы сразу показать
    все разделы дашборда без необходимости искать собственный access.log."""
    if not DEMO\_LOG\_PATH.exists():
        return None, None, None
    raw = DEMO\_LOG\_PATH.read\_bytes()
    cache\_key = "demo:" + hashlib.md5(raw).hexdigest()
    df, report = cached\_parse(raw, cache\_key)
    return df, report, cache\_key


# Детекторы пересчитываются на каждый rerun Streamlit (т.е. на любой клик
# в интерфейсе — даже не связанный с детекцией). Кэшируем по хэшу данных +
# по значениям порогов, чтобы пересчёт шёл только когда реально что-то
# изменилось, а не при каждом движении курсора по странице.

@st.cache\_data(show\_spinner=False)
def cached\_detect\_bruteforce(df\_hash: str, \_df: pd.DataFrame, min\_attempts: int, window\_minutes: int):
    return detect\_bruteforce(\_df, min\_attempts=min\_attempts, window\_minutes=window\_minutes)


@st.cache\_data(show\_spinner=False)
def cached\_detect\_spikes(df\_hash: str, \_df: pd.DataFrame, sigma\_threshold: float):
    return detect\_traffic\_spikes(\_df, sigma\_threshold=sigma\_threshold)


@st.cache\_data(show\_spinner=False)
def cached\_detect\_bursts(df\_hash: str, \_df: pd.DataFrame, window\_seconds: int, min\_requests: int):
    return detect\_single\_source\_bursts(\_df, window\_seconds=window\_seconds, min\_requests=min\_requests)


@st.cache\_data(show\_spinner=False)
def cached\_detect\_attacks(df\_hash: str, \_df: pd.DataFrame):
    return detect\_attack\_signatures(\_df)


# =========================================================================
# САЙДБАР — ЗАГРУЗКА
# =========================================================================

st.sidebar.title("📊 Log Analyzer")

mode = st.sidebar.radio(
    "Режим работы",
    \["Один лог", "Сравнение двух логов (до / после инцидента)"],
    help="Сравнение полезно, если у вас есть срез лога до подозрительной активности и после",
)

df, report, df\_b, report\_b = None, None, None, None
file\_hash, file\_hash\_b = None, None

if mode == "Один лог":
    uploaded = st.sidebar.file\_uploader("Загрузите access.log", type=\["log", "txt"])

    if st.sidebar.button("🎬 Загрузить демо-лог", width="stretch",
                          help="Тестовый лог с намеренно встроенными брутфорсом, "
                               "сканированием уязвимостей и всплеском трафика — "
                               "показывает все разделы дашборда сразу"):
        st.session\_state\["use\_demo"] = True

    if uploaded:
        st.session\_state\["use\_demo"] = False  # свой файл всегда важнее демо
        df, report, file\_hash = load\_uploaded\_file(uploaded)
    elif st.session\_state.get("use\_demo"):
        df, report, file\_hash = load\_demo\_file()
        if df is None:
            st.sidebar.error("Демо-файл не найден на сервере (sample-data/sample\_access.log).")
        else:
            st.sidebar.caption("📎 Показан демонстрационный лог")
else:
    col\_a, col\_b = st.sidebar.columns(2)
    uploaded\_a = st.sidebar.file\_uploader("Лог «до» инцидента", type=\["log", "txt"], key="log\_a")
    uploaded\_b = st.sidebar.file\_uploader("Лог «после» инцидента", type=\["log", "txt"], key="log\_b")
    if uploaded\_a:
        df, report, file\_hash = load\_uploaded\_file(uploaded\_a)
    if uploaded\_b:
        df\_b, report\_b, file\_hash\_b = load\_uploaded\_file(uploaded\_b)


if df is None or df.empty:
    st.title("📊 Nginx / Apache Log Analyzer")
    st.info(
        "Загрузите access.log в формате \*\*Combined Log Format\*\* (стандартный формат "
        "nginx и Apache) через панель слева, чтобы получить дашборд, поиск инцидентов "
        "и брутфорса, детекцию всплесков трафика и выгрузку отфильтрованных данных."
    )
    if report is not None and report.parsed == 0:
        st.error(
            f"Не удалось распознать ни одной строки из {report.total\_lines}. "
            "Проверьте, что это access log в формате combined (nginx/Apache)."
        )
    st.stop()

if report.skipped > 0:
    pct = report.skipped / report.total\_lines \* 100
    st.warning(
        f"⚠️ Пропущено {report.skipped} строк из {report.total\_lines} ({pct:.1f}%) — "
        f"не совпал формат combined log. Показанная статистика построена только по "
        f"распознанным строкам.",
        icon="⚠️",
    )
    with st.expander("Примеры пропущенных строк"):
        for s in report.skipped\_sample:
            st.code(s, language=None)

if report.unparsed\_datetime > 0:
    st.warning(f"⚠️ У {report.unparsed\_datetime} строк не удалось разобрать дату — они исключены из анализа.")


# =========================================================================
# САЙДБАР — ФИЛЬТРЫ
# =========================================================================

st.sidebar.divider()
st.sidebar.header("⏳ Фильтры")

traffic\_type = st.sidebar.selectbox("Тип трафика", \["Все посетители", "Только люди", "Только боты / поисковики"])

min\_date, max\_date = df\["date"].min(), df\["date"].max()
selected\_dates = st.sidebar.date\_input(
    "Диапазон дат", \[min\_date, max\_date], min\_value=min\_date, max\_value=max\_date
)

all\_ips = \["Все"] + sorted(df\["ip"].unique().tolist())
selected\_ip = st.sidebar.selectbox("Фильтр по IP", all\_ips)

all\_statuses = \["Все"] + sorted(df\["status"].unique().tolist())
selected\_status = st.sidebar.selectbox("Фильтр по HTTP-статусу", all\_statuses)

exclude\_ips\_raw = st.sidebar.text\_area(
    "Исключить IP (через запятую или с новой строки)",
    help="Удобно вычесть собственные IP, мониторинг, health-check'и балансировщика — "
         "чтобы они не засоряли графики и детекцию аномалий",
    placeholder="203.0.113.10, 203.0.113.11",
)
exclude\_ips = {ip.strip() for chunk in exclude\_ips\_raw.split(",") for ip in chunk.splitlines() if ip.strip()}

with st.sidebar.expander("⚙️ Чувствительность детекции"):
    bf\_min\_attempts = st.slider("Брутфорс: мин. попыток в окне", 5, 50, 10)
    bf\_window = st.slider("Брутфорс: окно, минут", 1, 30, 5)
    spike\_sigma = st.slider("Всплески: чувствительность (σ)", 1.5, 5.0, 3.0, step=0.5)
    burst\_window = st.slider("Одиночный источник: окно, секунд", 5, 60, 10)
    burst\_min\_req = st.slider("Одиночный источник: мин. запросов в окне", 10, 100, 30)


# =========================================================================
# ПРИМЕНЕНИЕ ФИЛЬТРОВ
# =========================================================================

filtered\_df = df.copy()

if exclude\_ips:
    filtered\_df = filtered\_df\[\~filtered\_df\["ip"].isin(exclude\_ips)]

if traffic\_type == "Только люди":
    filtered\_df = filtered\_df\[\~filtered\_df\["is\_bot"]]
elif traffic\_type == "Только боты / поисковики":
    filtered\_df = filtered\_df\[filtered\_df\["is\_bot"]]

if isinstance(selected\_dates, (list, tuple)) and len(selected\_dates) == 2:
    start\_date, end\_date = selected\_dates
    filtered\_df = filtered\_df\[(filtered\_df\["date"] >= start\_date) \& (filtered\_df\["date"] <= end\_date)]

if selected\_ip != "Все":
    filtered\_df = filtered\_df\[filtered\_df\["ip"] == selected\_ip]

if selected\_status != "Все":
    filtered\_df = filtered\_df\[filtered\_df\["status"] == selected\_status]


# =========================================================================
# ФОНОВАЯ ДЕТЕКЦИЯ (на полном df, исключая только exclude\_ips — фильтры
# дат/IP/статуса не должны прятать инциденты от алерт-баннера)
# =========================================================================

detection\_df = df\[\~df\["ip"].isin(exclude\_ips)] if exclude\_ips else df

# Ключ кэша строим из хэша файла + отсортированного списка исключённых IP —
# этого достаточно, чтобы однозначно определить содержимое detection\_df,
# не хэшируя сам DataFrame (это было бы дороже, чем сама детекция).
detection\_cache\_key = f"{file\_hash}:{','.join(sorted(exclude\_ips))}"

bruteforce\_hits = cached\_detect\_bruteforce(detection\_cache\_key, detection\_df, bf\_min\_attempts, bf\_window)
spikes = cached\_detect\_spikes(detection\_cache\_key, detection\_df, spike\_sigma)
bursts = cached\_detect\_bursts(detection\_cache\_key, detection\_df, burst\_window, burst\_min\_req)
attack\_hits = cached\_detect\_attacks(detection\_cache\_key, detection\_df)


# =========================================================================
# ЗАГОЛОВОК + АЛЕРТ-БАННЕР
# =========================================================================

st.title("📊 Nginx / Apache Log Analyzer")

alerts = \[]
if not bruteforce\_hits.empty:
    alerts.append(f"🔴 \*\*Брутфорс:\*\* {len(bruteforce\_hits)} IP превысили порог попыток авторизации")
if not bursts.empty:
    alerts.append(f"🟠 \*\*Одиночный источник-аномалия:\*\* {len(bursts)} IP с подозрительно высокой частотой запросов")
if not spikes.empty:
    alerts.append(f"🟡 \*\*Всплеск трафика:\*\* {len(spikes)} интервалов превысили норму — возможен DDoS")
if not attack\_hits.empty:
    alerts.append(f"🔴 \*\*Сканирование уязвимостей:\*\* {len(attack\_hits)} запросов совпали с сигнатурами атак")

if alerts:
    st.error("  \\n".join(alerts))
else:
    st.success("✅ Явных признаков брутфорса, аномального трафика или сканирования не обнаружено")


# =========================================================================
# KPI-КАРТОЧКИ
# =========================================================================

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Запросов (отфильтровано)", len(filtered\_df))
c2.metric("Уникальных IP", filtered\_df\["ip"].nunique())
c3.metric("Доля ошибок 4xx/5xx", f"{(filtered\_df\['status'] >= 400).mean() \* 100:.1f}%" if len(filtered\_df) else "0%")
c4.metric("Сбои хостинга (502/504)", int(filtered\_df\["status"].isin(\[502, 504]).sum()))
c5.metric("Ошибки кода сайта (500)", int((filtered\_df\["status"] == 500).sum()))
c6.metric("Трафик ботов", f"{filtered\_df\['is\_bot'].mean() \* 100:.1f}%" if len(filtered\_df) else "0%")


# =========================================================================
# ВКЛАДКИ
# =========================================================================

tab\_names = \["📈 Дашборд", "🚨 Безопасность", "🥊 Брутфорс и аномалии", "📄 Данные и экспорт"]
if df\_b is not None:
    tab\_names.insert(3, "🔁 Сравнение")

tabs = st.tabs(tab\_names)
tab\_dashboard, tab\_security, tab\_incidents = tabs\[0], tabs\[1], tabs\[2]
tab\_compare = tabs\[3] if df\_b is not None else None
tab\_export = tabs\[-1]


# --- Дашборд ---------------------------------------------------------
with tab\_dashboard:
    if filtered\_df.empty:
        st.info("Нет данных под текущие фильтры.")
    else:
        st.subheader("Активность по часам")
        hourly = filtered\_df.groupby("hour").size().reset\_index(name="Запросы")
        fig = px.line(hourly, x="hour", y="Запросы", labels={"hour": "Час суток"}, template="plotly\_dark")
        st.plotly\_chart(fig, width="stretch")

        col\_l, col\_r = st.columns(2)
        with col\_l:
            st.subheader("Топ-10 URL")
            top\_urls = filtered\_df\["url"].value\_counts().head(10).reset\_index()
            top\_urls.columns = \["url", "count"]
            fig\_u = px.bar(top\_urls, x="count", y="url", orientation="h", template="plotly\_dark")
            fig\_u.update\_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly\_chart(fig\_u, width="stretch")
        with col\_r:
            st.subheader("Распределение HTTP-статусов")
            status\_counts = filtered\_df\["status"].astype(str).value\_counts().reset\_index()
            status\_counts.columns = \["status", "count"]
            fig\_s = px.pie(status\_counts, names="status", values="count", hole=0.45, template="plotly\_dark")
            st.plotly\_chart(fig\_s, width="stretch")

        st.subheader("Люди vs боты")
        bot\_counts = filtered\_df\["is\_bot"].map({True: "Боты", False: "Люди"}).value\_counts().reset\_index()
        bot\_counts.columns = \["тип", "count"]
        fig\_b = px.bar(bot\_counts, x="тип", y="count", template="plotly\_dark")
        st.plotly\_chart(fig\_b, width="stretch")


# --- Безопасность ------------------------------------------------------
with tab\_security:
    st.subheader("Сигнатуры сканирования уязвимостей")
    if attack\_hits.empty:
        st.success("Совпадений с известными сигнатурами атак не найдено.")
    else:
        st.error(f"Найдено {len(attack\_hits)} запросов, похожих на сканирование уязвимостей.")

        col\_l, col\_r = st.columns(2)
        with col\_l:
            st.markdown("\*\*Топ IP-адресов сканеров\*\*")
            top\_attackers = attack\_hits\["ip"].value\_counts().reset\_index()
            top\_attackers.columns = \["ip", "запросов"]
            st.dataframe(top\_attackers, width="stretch", hide\_index=True)
        with col\_r:
            st.markdown("\*\*По категориям\*\*")
            cat\_counts = attack\_hits\["attack\_category"].value\_counts().reset\_index()
            cat\_counts.columns = \["категория", "запросов"]
            st.dataframe(cat\_counts, width="stretch", hide\_index=True)

        st.markdown("\*\*Совпавшие запросы\*\*")
        st.dataframe(
            attack\_hits\[\["datetime", "ip", "method", "url", "status", "attack\_category", "user\_agent"]],
            width="stretch", hide\_index=True,
        )
        st.download\_button(
            "⬇️ Скачать сырые строки атак (CSV)",
            data=to\_excel\_csv\_bytes(attack\_hits),
            file\_name="attack\_signatures.csv",
            mime="text/csv",
        )


# --- Брутфорс и аномалии -----------------------------------------------
with tab\_incidents:
    st.subheader("Брутфорс (частые 401/403 с одного IP)")
    if bruteforce\_hits.empty:
        st.success("Признаков брутфорса не обнаружено при текущих порогах чувствительности.")
    else:
        st.error(f"{len(bruteforce\_hits)} IP превысили порог: {bf\_min\_attempts} попыток за {bf\_window} мин.")
        st.dataframe(bruteforce\_hits, width="stretch", hide\_index=True)
        st.download\_button(
            "⬇️ Скачать список (CSV)",
            data=to\_excel\_csv\_bytes(bruteforce\_hits),
            file\_name="bruteforce\_ips.csv",
            mime="text/csv",
        )

    st.divider()
    st.subheader("Всплески трафика (возможный DDoS)")
    if spikes.empty:
        st.success("Аномальных всплесков не обнаружено.")
    else:
        st.warning(f"{len(spikes)} временных интервалов превысили норму (порог: {spike\_sigma}σ).")
        fig\_spike = px.bar(
            spikes, x="bucket\_start", y="requests", color="unique\_ips",
            labels={"bucket\_start": "Время", "requests": "Запросов", "unique\_ips": "Уник. IP"},
            template="plotly\_dark",
        )
        st.plotly\_chart(fig\_spike, width="stretch")
        st.dataframe(spikes, width="stretch", hide\_index=True)
        st.caption(
            "Много уникальных IP в аномальном интервале → похоже на распределённую нагрузку (DDoS). "
            "Мало уникальных IP → смотрите раздел «Одиночный источник» ниже."
        )

    st.divider()
    st.subheader("Одиночный источник аномальной активности")
    if bursts.empty:
        st.success("IP с аномально высокой частотой запросов не обнаружено.")
    else:
        st.warning(f"{len(bursts)} IP выдали подозрительно много запросов за короткое окно ({burst\_window} сек).")
        st.dataframe(bursts, width="stretch", hide\_index=True)
        st.download\_button(
            "⬇️ Скачать список (CSV)",
            data=to\_excel\_csv\_bytes(bursts),
            file\_name="single\_source\_bursts.csv",
            mime="text/csv",
        )


# --- Сравнение (если загружены два файла) -------------------------------
if tab\_compare is not None:
    with tab\_compare:
        if df\_b is None or df\_b.empty:
            st.info("Загрузите второй файл («после инцидента») в панели слева.")
        else:
            st.subheader("Сводное сравнение")

            def summarize(d):
                # Значения приводим к строке сразу — иначе колонка "До"/"После"
                # получает смешанные типы (int + "12.3%") и Streamlit не может
                # сериализовать DataFrame в Arrow для отображения.
                return {
                    "Запросов": str(len(d)),
                    "Уникальных IP": str(d\["ip"].nunique()),
                    "Доля ошибок 4xx/5xx": f"{(d\['status'] >= 400).mean() \* 100:.1f}%",
                    "502/504": str(int(d\["status"].isin(\[502, 504]).sum())),
                    "500": str(int((d\["status"] == 500).sum())),
                    "Доля ботов": f"{d\['is\_bot'].mean() \* 100:.1f}%",
                }

            summary\_a, summary\_b = summarize(df), summarize(df\_b)
            compare\_table = pd.DataFrame({"До": summary\_a, "После": summary\_b})
            st.dataframe(compare\_table, width="stretch")

            st.divider()
            st.subheader("Новые IP, которых не было в логе «до»")
            new\_ips = sorted(set(df\_b\["ip"]) - set(df\["ip"]))
            st.write(f"Найдено новых IP: {len(new\_ips)}")
            if new\_ips:
                new\_ips\_df = df\_b\[df\_b\["ip"].isin(new\_ips)]\["ip"].value\_counts().reset\_index()
                new\_ips\_df.columns = \["ip", "запросов"]
                st.dataframe(new\_ips\_df.head(50), width="stretch", hide\_index=True)

            st.divider()
            st.subheader("Новые сигнатуры атак в логе «после»")
            attacks\_a = cached\_detect\_attacks(file\_hash, df)
            attacks\_b = cached\_detect\_attacks(file\_hash\_b, df\_b)
            new\_attack\_ips = sorted(set(attacks\_b\["ip"]) - set(attacks\_a\["ip"])) if not attacks\_b.empty else \[]
            if new\_attack\_ips:
                st.error(f"Новые IP со сканированием уязвимостей: {', '.join(new\_attack\_ips\[:20])}")
            else:
                st.success("Новых источников сканирования в логе «после» не появилось.")


# --- Данные и экспорт ----------------------------------------------------
with tab\_export:
    st.subheader("Отфильтрованные записи")
    st.caption(f"Показано записей: {len(filtered\_df)} из {len(df)} исходных")

    display\_cols = \["datetime", "ip", "method", "url", "status", "size", "is\_bot"]
    st.dataframe(filtered\_df\[display\_cols], width="stretch", hide\_index=True, height=420)

    col\_csv, col\_json = st.columns(2)
    with col\_csv:
        st.download\_button(
            "⬇️ Скачать в CSV (Excel RU: ';' + BOM)",
            data=to\_excel\_csv\_bytes(filtered\_df\[display\_cols]),
            file\_name="access\_log\_filtered.csv",
            mime="text/csv",
            width="stretch",
        )
    with col\_json:
        st.download\_button(
            "⬇️ Скачать в JSON",
            data=filtered\_df\[display\_cols].to\_json(orient="records", force\_ascii=False, date\_format="iso"),
            file\_name="access\_log\_filtered.json",
            mime="application/json",
            width="stretch",
        )

st.sidebar.divider()
st.sidebar.caption("Файл обрабатывается в памяти процесса и нигде не сохраняется на диске.")
```

### `requirements.txt`

```
streamlit==1.58.0
pandas==2.2.3
plotly==5.24.1
```



\---

## Быстрый запуск на удалённом сервере



Предполагается Ubuntu-сервер с уже созданной виртуальной средой `venv` в
папке проекта.

```bash
# 1. Файлы analysis.py, app.py, requirements.txt и sample-data/ уже в папке проекта

# 2. Зависимости
source venv/bin/activate
pip install -r requirements.txt
deactivate

# 3. Проверка синтаксиса
source venv/bin/activate
python3 -m py\_compile app.py analysis.py \&\& echo OK
deactivate

# 4. Запуск (доступен с любой машины по адресу http://IP\_СЕРВЕРА:8501)
source venv/bin/activate
nohup streamlit run app.py \\
    --server.headless true \\
    --server.port 8501 \\
    --server.address 0.0.0.0 \\
    --server.maxUploadSize 60 \\
    > \~/streamlit.log 2>\&1 \&
disown
deactivate

# 5. Проверка
curl -s -o /dev/null -w "HTTP\_STATUS:%{http\_code}\\n" http://127.0.0.1:8501
```

Firewall должен разрешать нужный порт:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 8501/tcp
sudo ufw enable
```

**Это временный/тестовый вариант запуска** — без HTTPS и без nginx. Для
постоянной публичной эксплуатации нужен reverse proxy (nginx), systemd для
автозапуска/автовосстановления и HTTPS через Let's Encrypt — полная
инструкция в [`deploy/DEPLOY.md`](deploy/DEPLOY.md), готовые конфиги в
[`deploy/nginx.conf`](deploy/nginx.conf) и
[`deploy/log-analyzer.service`](deploy/log-analyzer.service).





* Streamlit не должен торчать в интернет напрямую — нет rate limiting,
слабая защита от больших payload'ов. Порт 8501 биндится на `127.0.0.1`,
наружу смотрит только nginx на 80/443.



* Форма публичная и без логина → нужны лимит размера файла и rate limiting
на уровне nginx, иначе это открытый вектор DoS через память/диск.



* HTTPS обязателен: форма принимает файлы от посторонних людей, а
access-логи содержат IP-адреса третьих лиц — гонять их открытым текстом
не стоит.

\---



## Как проверялась работоспособность



**Юнит-проверка чистой логики** — на синтетическом логе с намеренно
встроенными брутфорсом, сканированием и всплеском трафика проверялось, что:
парсер разбирает 100% строк корректного формата; брутфорс-детектор находит
IP с 25 попытками за 5 минут и не путает его с обычным трафиком; детектор
атак корректно классифицирует `.env`, `.git`, `wp-login.php`; детектор
всплесков отличает распределённый всплеск (много IP) от одиночного
агрессивного источника (один IP).



**Сквозная проверка приложения** через `streamlit.testing.v1.AppTest` —
загрузка файла, переключение в режим сравнения, рендер всех вкладок и
графиков прогонялись программно на отсутствие исключений — и на демо-логе
(602 строки), и на синтетическом логе, сопоставимом по объёму с реальным
логом заказчика (\~50 000 строк, 2665 уникальных IP).



Проверить логику после правок можно так, без запуска веб-интерфейса:

```bash
python3 -c "
from analysis import parse\_log, detect\_bruteforce
with open('sample-data/sample\_access.log') as f:
    df, report = parse\_log(f.read())
print(report)
print(detect\_bruteforce(df))
"
```

\---



## Что было найдено и исправлено в процессе



На реальном логе клиента (\~50 000 строк) обнаружилась заметная просадка
производительности. Разобрано двумя независимыми находками, а не общими
догадками:



**1. Отсутствие кэширования на детекторах инцидентов.** Streamlit
перезапускает весь скрипт на любой клик в интерфейсе — даже не связанный с
детекцией (например, смена фильтра трафика). Детекторы брутфорса, всплесков
и сигнатур атак пересчитывались заново на каждое такое действие. Добавлено
кэширование (`@st.cache\_data`) по хэшу данных + значениям порогов
чувствительности — пересчёт идёт только когда реально что-то изменилось.



**2. Медленная детекция ботов.** Профилировкой (`cProfile`) найдено, что
основное время уходило на построчный разбор User-Agent тяжёлой библиотекой,
полностью определяющей браузер/ОС/устройство — хотя нужен был только один
булев признак "бот/не бот". Заменено на векторизованную regex-проверку по
ключевым словам (тот же подход, что в GoAccess/AWStats) — время обработки
файла сократилось почти вдвое.



Обе находки сделаны через измерение (профилировщик, замеры времени
до/после), а не "на глаз" — это позволило чинить конкретное узкое место, а
не переписывать код наугад.

\---

## Осознанные ограничения



* **Формат** — только Combined Log Format (стандарт nginx/Apache по
умолчанию). Кастомные `log\_format` с другим порядком полей потребуют
правки регулярного выражения в `analysis.py` (`LOG\_PATTERN`).



* **Обработка полностью в памяти процесса, без базы данных** — соответствует
требованию "без хранения между визитами", но означает, что очень большие
логи (сотни МБ+) стоит заранее нарезать (`split`/`grep` по дате) перед
загрузкой.



* **Детекция брутфорса/аномалий — эвристики на статистических порогах**, не
замена полноценной SIEM-системы; задача — быстро подсветить, куда
смотреть, а не заменить `fail2ban`/полноценный WAF.



* **Различение браузеров (Chrome/Firefox/Safari и т.д.) не реализовано** —
сейчас есть только признак "бот/не бот". Полноценное определение браузера
через специализированную библиотеку возможно, но библиотеку выгодно
применять не построчно ко всем 50 000+ запросам, а только к уникальным
значениям User-Agent (их обычно на порядки меньше, чем строк лога), после
чего результат "подставляется" обратно в таблицу по соответствию.

