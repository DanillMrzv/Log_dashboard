"""
analysis.py — вся аналитическая логика Nginx/Apache Log Analyzer,
отделённая от Streamlit-интерфейса. Тестируется напрямую через pytest
или интерактивно, без поднятия веб-приложения.
"""
from __future__ import annotations

import re
import io
from dataclasses import dataclass, field

import pandas as pd


# =========================================================================
# 1. ПАРСИНГ ЛОГОВ
# =========================================================================

# Combined Log Format — покрывает и nginx, и Apache (формат идентичен).
# Поддерживаем и вариант с $request_time в хвосте строки (частое
# кастомное расширение log_format в nginx), если он есть — используем,
# если нет — просто игнорируем недостающую группу.
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>[A-Z]+|-)\s?(?P<url>\S*)\s?(?:HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
    r'(?:\s+(?P<request_time>[\d.]+))?'
)

REQUIRED_GROUPS = {"ip", "datetime", "method", "url", "status", "size"}

# Ключевые слова для определения бот-трафика по User-Agent. Это стандартный
# подход для лог-анализаторов (GoAccess, AWStats и т.п.) — полноценный разбор
# UA (браузер/ОС/устройство) через тяжёлые библиотеки избыточен, когда нужен
# только булев признак "бот/не бот", а на больших логах это заметно быстрее
# (векторизованная regex-проверка вместо построчного парсинга в Python).
BOT_UA_PATTERN = re.compile(
    r"bot|crawl|spider|slurp|mediapartners|facebookexternalhit|whatsapp|"
    r"telegrambot|applebot|bingpreview|archiver|ahrefs|semrush|mj12bot|dotbot|"
    r"petalbot|sogou|exabot|python-requests|curl/|wget/|scrapy|go-http-client|"
    r"libwww-perl|headlesschrome|phantomjs|selenium|python-urllib",
    re.IGNORECASE,
)


@dataclass
class ParseReport:
    total_lines: int = 0
    parsed: int = 0
    skipped: int = 0
    skipped_sample: list[str] = field(default_factory=list)
    unparsed_datetime: int = 0


def parse_log(raw_text: str) -> tuple[pd.DataFrame, ParseReport]:
    """Парсит текст access-лога в DataFrame. Не падает на кривых строках —
    пропускает их и репортит количество/примеры, чтобы админ видел, что
    часть данных не учтена, а не тихо получал неполную картину."""
    report = ParseReport()
    rows = []

    lines = raw_text.splitlines()
    report.total_lines = len(lines)

    for line in lines:
        if not line.strip():
            continue
        m = LOG_PATTERN.match(line)
        if not m:
            report.skipped += 1
            if len(report.skipped_sample) < 5:
                report.skipped_sample.append(line[:200])
            continue
        d = m.groupdict()
        rows.append(d)
        report.parsed += 1

    if not rows:
        return pd.DataFrame(), report

    df = pd.DataFrame(rows)

    # Типы
    df["status"] = pd.to_numeric(df["status"], errors="coerce").fillna(0).astype(int)
    df["size"] = pd.to_numeric(df["size"], errors="coerce").fillna(0).astype(int)
    if "request_time" in df.columns:
        df["request_time"] = pd.to_numeric(df["request_time"], errors="coerce")

    # Дата: "10/Oct/2023:13:55:36 +0300" -> берём датувремя + сохраняем офсет отдельно
    dt_main = df["datetime"].str.extract(r"^([^\s]+) ([+-]\d{4})$")
    df["datetime"] = pd.to_datetime(
        dt_main[0], format="%d/%b/%Y:%H:%M:%S", errors="coerce"
    )
    df["tz_offset"] = dt_main[1]

    report.unparsed_datetime = int(df["datetime"].isna().sum())
    df = df.dropna(subset=["datetime"]).reset_index(drop=True)

    df["date"] = df["datetime"].dt.date
    df["hour"] = df["datetime"].dt.hour

    # Боты — быстрая векторизованная проверка по ключевым словам в UA
    # (см. BOT_UA_PATTERN), вместо построчного разбора тяжёлой библиотекой.
    df["is_bot"] = df["user_agent"].str.contains(BOT_UA_PATTERN, na=False)

    return df, report


# =========================================================================
# 2. СИГНАТУРЫ АТАК / СКАНИРОВАНИЯ
# =========================================================================

ATTACK_SIGNATURES = {
    "wp-login / WordPress": ["wp-login", "wp-admin", "wp-content", "xmlrpc.php"],
    "Утечка конфигов": [".env", ".git", "config.php", "docker-compose", ".htaccess", "web.config"],
    "Админ-панели": ["phpmyadmin", "/admin", "/administrator", "pma/"],
    "Backup / архивы": [".sql", ".bak", ".zip", ".tar.gz", "backup"],
    "Shell / вебшеллы": ["shell.php", "cmd.php", "c99", "eval(", "base64_decode"],
    "Path traversal": ["../", "..%2f", "%2e%2e"],
    "SQLi-паттерны": ["union+select", "union select", "' or 1=1", "1=1--"],
}


def detect_attack_signatures(df: pd.DataFrame) -> pd.DataFrame:
    """Помечает строки, чей URL совпал с известными паттернами сканирования
    уязвимостей. Возвращает только совпавшие строки + категорию атаки."""
    if df.empty:
        return df.assign(attack_category=pd.Series(dtype=str))

    url_lower = df["url"].str.lower()
    matches = []

    for category, patterns in ATTACK_SIGNATURES.items():
        mask = pd.Series(False, index=df.index)
        for p in patterns:
            mask |= url_lower.str.contains(re.escape(p.lower()), regex=True, na=False)
        if mask.any():
            hit = df[mask].copy()
            hit["attack_category"] = category
            matches.append(hit)

    if not matches:
        return df.iloc[0:0].assign(attack_category=pd.Series(dtype=str))

    return pd.concat(matches, ignore_index=True)


# =========================================================================
# 3. ОБНАРУЖЕНИЕ БРУТФОРСА
# =========================================================================

def detect_bruteforce(
    df: pd.DataFrame,
    status_codes: tuple[int, ...] = (401, 403),
    min_attempts: int = 10,
    window_minutes: int = 5,
) -> pd.DataFrame:
    """
    Ищет IP, которые за скользящее окно `window_minutes` минут дали
    не менее `min_attempts` ответов с кодами из `status_codes`.

    Возвращает по одной строке на IP: пик интенсивности (макс. число
    попыток в любом окне), общее число попыток, целевые URL, период.
    """
    cols = ["ip", "datetime", "status", "url"]
    if df.empty or not set(cols).issubset(df.columns):
        return pd.DataFrame(columns=["ip", "attempts_total", "max_in_window", "urls", "first_seen", "last_seen"])

    auth_fails = df[df["status"].isin(status_codes)][cols].sort_values("datetime")
    if auth_fails.empty:
        return pd.DataFrame(columns=["ip", "attempts_total", "max_in_window", "urls", "first_seen", "last_seen"])

    results = []
    window = pd.Timedelta(minutes=window_minutes)

    for ip, group in auth_fails.groupby("ip"):
        times = group["datetime"].reset_index(drop=True)
        max_in_window = 0
        # Скользящее окно по отсортированным меткам времени — O(n) через два указателя
        left = 0
        for right in range(len(times)):
            while times[right] - times[left] > window:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window >= min_attempts:
            results.append({
                "ip": ip,
                "attempts_total": len(group),
                "max_in_window": max_in_window,
                "urls": ", ".join(sorted(group["url"].value_counts().head(3).index)),
                "first_seen": group["datetime"].min(),
                "last_seen": group["datetime"].max(),
            })

    if not results:
        return pd.DataFrame(columns=["ip", "attempts_total", "max_in_window", "urls", "first_seen", "last_seen"])

    return pd.DataFrame(results).sort_values("max_in_window", ascending=False).reset_index(drop=True)


# =========================================================================
# 4. АНОМАЛИИ ТРАФИКА (ВОЗМОЖНЫЙ DDoS)
# =========================================================================

def detect_traffic_spikes(
    df: pd.DataFrame,
    bucket: str = "1min",
    sigma_threshold: float = 3.0,
    min_bucket_requests: int = 20,
) -> pd.DataFrame:
    """
    Бьёт трафик на равные интервалы (`bucket`), считает среднее и
    стандартное отклонение по числу запросов в интервале, и помечает
    интервалы, которые превышают mean + sigma_threshold*std.

    min_bucket_requests — отсекает статистический шум на малых логах
    (всплеск с 2 до 8 запросов формально "аномалия", но бессмысленна).
    """
    if df.empty or "datetime" not in df.columns:
        return pd.DataFrame(columns=["bucket_start", "requests", "unique_ips", "z_score"])

    s = df.set_index("datetime").resample(bucket).size()
    if len(s) < 3:
        return pd.DataFrame(columns=["bucket_start", "requests", "unique_ips", "z_score"])

    mean, std = s.mean(), s.std(ddof=0)
    if std == 0:
        return pd.DataFrame(columns=["bucket_start", "requests", "unique_ips", "z_score"])

    z = (s - mean) / std
    spikes = s[(z >= sigma_threshold) & (s >= min_bucket_requests)]

    if spikes.empty:
        return pd.DataFrame(columns=["bucket_start", "requests", "unique_ips", "z_score"])

    unique_ips = df.set_index("datetime")["ip"].resample(bucket).nunique()

    result = pd.DataFrame({
        "bucket_start": spikes.index,
        "requests": spikes.values,
        "unique_ips": unique_ips.loc[spikes.index].values,
        "z_score": z.loc[spikes.index].round(2).values,
    }).sort_values("requests", ascending=False).reset_index(drop=True)

    return result


def detect_single_source_bursts(
    df: pd.DataFrame,
    window_seconds: int = 10,
    min_requests: int = 30,
) -> pd.DataFrame:
    """
    Отдельно от общих всплесков трафика — ищет отдельные IP, выдавшие
    аномально много запросов за короткое окно (`window_seconds`).
    Это отличает "один агрессивный источник" (вероятный DoS/скан) от
    органического роста трафика с разных IP.
    """
    cols = ["ip", "datetime"]
    if df.empty or not set(cols).issubset(df.columns):
        return pd.DataFrame(columns=["ip", "max_requests_in_window", "total_requests"])

    window = pd.Timedelta(seconds=window_seconds)
    results = []

    for ip, group in df[cols].sort_values("datetime").groupby("ip"):
        if len(group) < min_requests:
            continue
        times = group["datetime"].reset_index(drop=True)
        max_in_window = 0
        left = 0
        for right in range(len(times)):
            while times[right] - times[left] > window:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)
        if max_in_window >= min_requests:
            results.append({"ip": ip, "max_requests_in_window": max_in_window, "total_requests": len(group)})

    if not results:
        return pd.DataFrame(columns=["ip", "max_requests_in_window", "total_requests"])

    return pd.DataFrame(results).sort_values("max_requests_in_window", ascending=False).reset_index(drop=True)


# =========================================================================
# 5. ЭКСПОРТ (CSV под русский Excel)
# =========================================================================

def to_excel_csv_bytes(df: pd.DataFrame) -> bytes:
    """CSV с разделителем ';' и BOM (utf-8-sig) — открывается в русском
    Excel без «кракозябр» и без разъезжания колонок по запятым внутри URL."""
    buf = io.StringIO()
    df.to_csv(buf, sep=";", index=False)
    return buf.getvalue().encode("utf-8-sig")
