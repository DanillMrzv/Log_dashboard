"""
app.py — Nginx/Apache Log Analyzer & Incident Dashboard.

UI-слой. Вся аналитика вынесена в analysis.py и не зависит от Streamlit —
её можно тестировать напрямую (см. analysis.py).
"""
import hashlib
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from analysis import (
    parse_log,
    detect_attack_signatures,
    detect_bruteforce,
    detect_traffic_spikes,
    detect_single_source_bursts,
    to_excel_csv_bytes,
)

st.set_page_config(layout="wide", page_title="Log Analyzer & Incident Dashboard", page_icon="📊")


# =========================================================================
# КЭШИРУЕМЫЙ ПАРСИНГ
# =========================================================================

@st.cache_data(show_spinner="Разбираю лог-файл…")
def cached_parse(file_bytes: bytes, _cache_key: str):
    text = file_bytes.decode("utf-8", errors="ignore")
    return parse_log(text)


def load_uploaded_file(uploaded_file):
    raw = uploaded_file.getvalue()
    cache_key = hashlib.md5(raw).hexdigest()
    df, report = cached_parse(raw, cache_key)
    return df, report, cache_key


DEMO_LOG_PATH = Path(__file__).parent / "sample-data" / "sample_access.log"


def load_demo_file():
    """Загружает лог, вшитый в проект — с намеренно встроенными брутфорсом,
    сканированием уязвимостей и всплеском трафика, чтобы сразу показать
    все разделы дашборда без необходимости искать собственный access.log."""
    if not DEMO_LOG_PATH.exists():
        return None, None, None
    raw = DEMO_LOG_PATH.read_bytes()
    cache_key = "demo:" + hashlib.md5(raw).hexdigest()
    df, report = cached_parse(raw, cache_key)
    return df, report, cache_key


# Детекторы пересчитываются на каждый rerun Streamlit (т.е. на любой клик
# в интерфейсе — даже не связанный с детекцией). Кэшируем по хэшу данных +
# по значениям порогов, чтобы пересчёт шёл только когда реально что-то
# изменилось, а не при каждом движении курсора по странице.

@st.cache_data(show_spinner=False)
def cached_detect_bruteforce(df_hash: str, _df: pd.DataFrame, min_attempts: int, window_minutes: int):
    return detect_bruteforce(_df, min_attempts=min_attempts, window_minutes=window_minutes)


@st.cache_data(show_spinner=False)
def cached_detect_spikes(df_hash: str, _df: pd.DataFrame, sigma_threshold: float):
    return detect_traffic_spikes(_df, sigma_threshold=sigma_threshold)


@st.cache_data(show_spinner=False)
def cached_detect_bursts(df_hash: str, _df: pd.DataFrame, window_seconds: int, min_requests: int):
    return detect_single_source_bursts(_df, window_seconds=window_seconds, min_requests=min_requests)


@st.cache_data(show_spinner=False)
def cached_detect_attacks(df_hash: str, _df: pd.DataFrame):
    return detect_attack_signatures(_df)


# =========================================================================
# САЙДБАР — ЗАГРУЗКА
# =========================================================================

st.sidebar.title("📊 Log Analyzer")

mode = st.sidebar.radio(
    "Режим работы",
    ["Один лог", "Сравнение двух логов (до / после инцидента)"],
    help="Сравнение полезно, если у вас есть срез лога до подозрительной активности и после",
)

df, report, df_b, report_b = None, None, None, None
file_hash, file_hash_b = None, None

if mode == "Один лог":
    uploaded = st.sidebar.file_uploader("Загрузите access.log", type=["log", "txt"])

    if st.sidebar.button("🎬 Загрузить демо-лог", width="stretch",
                          help="Тестовый лог с намеренно встроенными брутфорсом, "
                               "сканированием уязвимостей и всплеском трафика — "
                               "показывает все разделы дашборда сразу"):
        st.session_state["use_demo"] = True

    if uploaded:
        st.session_state["use_demo"] = False  # свой файл всегда важнее демо
        df, report, file_hash = load_uploaded_file(uploaded)
    elif st.session_state.get("use_demo"):
        df, report, file_hash = load_demo_file()
        if df is None:
            st.sidebar.error("Демо-файл не найден на сервере (sample-data/sample_access.log).")
        else:
            st.sidebar.caption("📎 Показан демонстрационный лог")
else:
    col_a, col_b = st.sidebar.columns(2)
    uploaded_a = st.sidebar.file_uploader("Лог «до» инцидента", type=["log", "txt"], key="log_a")
    uploaded_b = st.sidebar.file_uploader("Лог «после» инцидента", type=["log", "txt"], key="log_b")
    if uploaded_a:
        df, report, file_hash = load_uploaded_file(uploaded_a)
    if uploaded_b:
        df_b, report_b, file_hash_b = load_uploaded_file(uploaded_b)


if df is None or df.empty:
    st.title("📊 Nginx / Apache Log Analyzer")
    st.info(
        "Загрузите access.log в формате **Combined Log Format** (стандартный формат "
        "nginx и Apache) через панель слева, чтобы получить дашборд, поиск инцидентов "
        "и брутфорса, детекцию всплесков трафика и выгрузку отфильтрованных данных."
    )
    if report is not None and report.parsed == 0:
        st.error(
            f"Не удалось распознать ни одной строки из {report.total_lines}. "
            "Проверьте, что это access log в формате combined (nginx/Apache)."
        )
    st.stop()

if report.skipped > 0:
    pct = report.skipped / report.total_lines * 100
    st.warning(
        f"⚠️ Пропущено {report.skipped} строк из {report.total_lines} ({pct:.1f}%) — "
        f"не совпал формат combined log. Показанная статистика построена только по "
        f"распознанным строкам.",
        icon="⚠️",
    )
    with st.expander("Примеры пропущенных строк"):
        for s in report.skipped_sample:
            st.code(s, language=None)

if report.unparsed_datetime > 0:
    st.warning(f"⚠️ У {report.unparsed_datetime} строк не удалось разобрать дату — они исключены из анализа.")


# =========================================================================
# САЙДБАР — ФИЛЬТРЫ
# =========================================================================

st.sidebar.divider()
st.sidebar.header("⏳ Фильтры")

traffic_type = st.sidebar.selectbox("Тип трафика", ["Все посетители", "Только люди", "Только боты / поисковики"])

min_date, max_date = df["date"].min(), df["date"].max()
selected_dates = st.sidebar.date_input(
    "Диапазон дат", [min_date, max_date], min_value=min_date, max_value=max_date
)

all_ips = ["Все"] + sorted(df["ip"].unique().tolist())
selected_ip = st.sidebar.selectbox("Фильтр по IP", all_ips)

all_statuses = ["Все"] + sorted(df["status"].unique().tolist())
selected_status = st.sidebar.selectbox("Фильтр по HTTP-статусу", all_statuses)

exclude_ips_raw = st.sidebar.text_area(
    "Исключить IP (через запятую или с новой строки)",
    help="Удобно вычесть собственные IP, мониторинг, health-check'и балансировщика — "
         "чтобы они не засоряли графики и детекцию аномалий",
    placeholder="203.0.113.10, 203.0.113.11",
)
exclude_ips = {ip.strip() for chunk in exclude_ips_raw.split(",") for ip in chunk.splitlines() if ip.strip()}

with st.sidebar.expander("⚙️ Чувствительность детекции"):
    bf_min_attempts = st.slider("Брутфорс: мин. попыток в окне", 5, 50, 10)
    bf_window = st.slider("Брутфорс: окно, минут", 1, 30, 5)
    spike_sigma = st.slider("Всплески: чувствительность (σ)", 1.5, 5.0, 3.0, step=0.5)
    burst_window = st.slider("Одиночный источник: окно, секунд", 5, 60, 10)
    burst_min_req = st.slider("Одиночный источник: мин. запросов в окне", 10, 100, 30)


# =========================================================================
# ПРИМЕНЕНИЕ ФИЛЬТРОВ
# =========================================================================

filtered_df = df.copy()

if exclude_ips:
    filtered_df = filtered_df[~filtered_df["ip"].isin(exclude_ips)]

if traffic_type == "Только люди":
    filtered_df = filtered_df[~filtered_df["is_bot"]]
elif traffic_type == "Только боты / поисковики":
    filtered_df = filtered_df[filtered_df["is_bot"]]

if isinstance(selected_dates, (list, tuple)) and len(selected_dates) == 2:
    start_date, end_date = selected_dates
    filtered_df = filtered_df[(filtered_df["date"] >= start_date) & (filtered_df["date"] <= end_date)]

if selected_ip != "Все":
    filtered_df = filtered_df[filtered_df["ip"] == selected_ip]

if selected_status != "Все":
    filtered_df = filtered_df[filtered_df["status"] == selected_status]


# =========================================================================
# ФОНОВАЯ ДЕТЕКЦИЯ (на полном df, исключая только exclude_ips — фильтры
# дат/IP/статуса не должны прятать инциденты от алерт-баннера)
# =========================================================================

detection_df = df[~df["ip"].isin(exclude_ips)] if exclude_ips else df

# Ключ кэша строим из хэша файла + отсортированного списка исключённых IP —
# этого достаточно, чтобы однозначно определить содержимое detection_df,
# не хэшируя сам DataFrame (это было бы дороже, чем сама детекция).
detection_cache_key = f"{file_hash}:{','.join(sorted(exclude_ips))}"

bruteforce_hits = cached_detect_bruteforce(detection_cache_key, detection_df, bf_min_attempts, bf_window)
spikes = cached_detect_spikes(detection_cache_key, detection_df, spike_sigma)
bursts = cached_detect_bursts(detection_cache_key, detection_df, burst_window, burst_min_req)
attack_hits = cached_detect_attacks(detection_cache_key, detection_df)


# =========================================================================
# ЗАГОЛОВОК + АЛЕРТ-БАННЕР
# =========================================================================

st.title("📊 Nginx / Apache Log Analyzer")

alerts = []
if not bruteforce_hits.empty:
    alerts.append(f"🔴 **Брутфорс:** {len(bruteforce_hits)} IP превысили порог попыток авторизации")
if not bursts.empty:
    alerts.append(f"🟠 **Одиночный источник-аномалия:** {len(bursts)} IP с подозрительно высокой частотой запросов")
if not spikes.empty:
    alerts.append(f"🟡 **Всплеск трафика:** {len(spikes)} интервалов превысили норму — возможен DDoS")
if not attack_hits.empty:
    alerts.append(f"🔴 **Сканирование уязвимостей:** {len(attack_hits)} запросов совпали с сигнатурами атак")

if alerts:
    st.error("  \n".join(alerts))
else:
    st.success("✅ Явных признаков брутфорса, аномального трафика или сканирования не обнаружено")


# =========================================================================
# KPI-КАРТОЧКИ
# =========================================================================

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Запросов (отфильтровано)", len(filtered_df))
c2.metric("Уникальных IP", filtered_df["ip"].nunique())
c3.metric("Доля ошибок 4xx/5xx", f"{(filtered_df['status'] >= 400).mean() * 100:.1f}%" if len(filtered_df) else "0%")
c4.metric("Сбои хостинга (502/504)", int(filtered_df["status"].isin([502, 504]).sum()))
c5.metric("Ошибки кода сайта (500)", int((filtered_df["status"] == 500).sum()))
c6.metric("Трафик ботов", f"{filtered_df['is_bot'].mean() * 100:.1f}%" if len(filtered_df) else "0%")


# =========================================================================
# ВКЛАДКИ
# =========================================================================

tab_names = ["📈 Дашборд", "🚨 Безопасность", "🥊 Брутфорс и аномалии", "📄 Данные и экспорт"]
if df_b is not None:
    tab_names.insert(3, "🔁 Сравнение")

tabs = st.tabs(tab_names)
tab_dashboard, tab_security, tab_incidents = tabs[0], tabs[1], tabs[2]
tab_compare = tabs[3] if df_b is not None else None
tab_export = tabs[-1]


# --- Дашборд ---------------------------------------------------------
with tab_dashboard:
    if filtered_df.empty:
        st.info("Нет данных под текущие фильтры.")
    else:
        st.subheader("Активность по часам")
        hourly = filtered_df.groupby("hour").size().reset_index(name="Запросы")
        fig = px.line(hourly, x="hour", y="Запросы", labels={"hour": "Час суток"}, template="plotly_dark")
        st.plotly_chart(fig, width="stretch")

        col_l, col_r = st.columns(2)
        with col_l:
            st.subheader("Топ-10 URL")
            top_urls = filtered_df["url"].value_counts().head(10).reset_index()
            top_urls.columns = ["url", "count"]
            fig_u = px.bar(top_urls, x="count", y="url", orientation="h", template="plotly_dark")
            fig_u.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig_u, width="stretch")
        with col_r:
            st.subheader("Распределение HTTP-статусов")
            status_counts = filtered_df["status"].astype(str).value_counts().reset_index()
            status_counts.columns = ["status", "count"]
            fig_s = px.pie(status_counts, names="status", values="count", hole=0.45, template="plotly_dark")
            st.plotly_chart(fig_s, width="stretch")

        st.subheader("Люди vs боты")
        bot_counts = filtered_df["is_bot"].map({True: "Боты", False: "Люди"}).value_counts().reset_index()
        bot_counts.columns = ["тип", "count"]
        fig_b = px.bar(bot_counts, x="тип", y="count", template="plotly_dark")
        st.plotly_chart(fig_b, width="stretch")


# --- Безопасность ------------------------------------------------------
with tab_security:
    st.subheader("Сигнатуры сканирования уязвимостей")
    if attack_hits.empty:
        st.success("Совпадений с известными сигнатурами атак не найдено.")
    else:
        st.error(f"Найдено {len(attack_hits)} запросов, похожих на сканирование уязвимостей.")

        col_l, col_r = st.columns(2)
        with col_l:
            st.markdown("**Топ IP-адресов сканеров**")
            top_attackers = attack_hits["ip"].value_counts().reset_index()
            top_attackers.columns = ["ip", "запросов"]
            st.dataframe(top_attackers, width="stretch", hide_index=True)
        with col_r:
            st.markdown("**По категориям**")
            cat_counts = attack_hits["attack_category"].value_counts().reset_index()
            cat_counts.columns = ["категория", "запросов"]
            st.dataframe(cat_counts, width="stretch", hide_index=True)

        st.markdown("**Совпавшие запросы**")
        st.dataframe(
            attack_hits[["datetime", "ip", "method", "url", "status", "attack_category", "user_agent"]],
            width="stretch", hide_index=True,
        )
        st.download_button(
            "⬇️ Скачать сырые строки атак (CSV)",
            data=to_excel_csv_bytes(attack_hits),
            file_name="attack_signatures.csv",
            mime="text/csv",
        )


# --- Брутфорс и аномалии -----------------------------------------------
with tab_incidents:
    st.subheader("Брутфорс (частые 401/403 с одного IP)")
    if bruteforce_hits.empty:
        st.success("Признаков брутфорса не обнаружено при текущих порогах чувствительности.")
    else:
        st.error(f"{len(bruteforce_hits)} IP превысили порог: {bf_min_attempts} попыток за {bf_window} мин.")
        st.dataframe(bruteforce_hits, width="stretch", hide_index=True)
        st.download_button(
            "⬇️ Скачать список (CSV)",
            data=to_excel_csv_bytes(bruteforce_hits),
            file_name="bruteforce_ips.csv",
            mime="text/csv",
        )

    st.divider()
    st.subheader("Всплески трафика (возможный DDoS)")
    if spikes.empty:
        st.success("Аномальных всплесков не обнаружено.")
    else:
        st.warning(f"{len(spikes)} временных интервалов превысили норму (порог: {spike_sigma}σ).")
        fig_spike = px.bar(
            spikes, x="bucket_start", y="requests", color="unique_ips",
            labels={"bucket_start": "Время", "requests": "Запросов", "unique_ips": "Уник. IP"},
            template="plotly_dark",
        )
        st.plotly_chart(fig_spike, width="stretch")
        st.dataframe(spikes, width="stretch", hide_index=True)
        st.caption(
            "Много уникальных IP в аномальном интервале → похоже на распределённую нагрузку (DDoS). "
            "Мало уникальных IP → смотрите раздел «Одиночный источник» ниже."
        )

    st.divider()
    st.subheader("Одиночный источник аномальной активности")
    if bursts.empty:
        st.success("IP с аномально высокой частотой запросов не обнаружено.")
    else:
        st.warning(f"{len(bursts)} IP выдали подозрительно много запросов за короткое окно ({burst_window} сек).")
        st.dataframe(bursts, width="stretch", hide_index=True)
        st.download_button(
            "⬇️ Скачать список (CSV)",
            data=to_excel_csv_bytes(bursts),
            file_name="single_source_bursts.csv",
            mime="text/csv",
        )


# --- Сравнение (если загружены два файла) -------------------------------
if tab_compare is not None:
    with tab_compare:
        if df_b is None or df_b.empty:
            st.info("Загрузите второй файл («после инцидента») в панели слева.")
        else:
            st.subheader("Сводное сравнение")

            def summarize(d):
                # Значения приводим к строке сразу — иначе колонка "До"/"После"
                # получает смешанные типы (int + "12.3%") и Streamlit не может
                # сериализовать DataFrame в Arrow для отображения.
                return {
                    "Запросов": str(len(d)),
                    "Уникальных IP": str(d["ip"].nunique()),
                    "Доля ошибок 4xx/5xx": f"{(d['status'] >= 400).mean() * 100:.1f}%",
                    "502/504": str(int(d["status"].isin([502, 504]).sum())),
                    "500": str(int((d["status"] == 500).sum())),
                    "Доля ботов": f"{d['is_bot'].mean() * 100:.1f}%",
                }

            summary_a, summary_b = summarize(df), summarize(df_b)
            compare_table = pd.DataFrame({"До": summary_a, "После": summary_b})
            st.dataframe(compare_table, width="stretch")

            st.divider()
            st.subheader("Новые IP, которых не было в логе «до»")
            new_ips = sorted(set(df_b["ip"]) - set(df["ip"]))
            st.write(f"Найдено новых IP: {len(new_ips)}")
            if new_ips:
                new_ips_df = df_b[df_b["ip"].isin(new_ips)]["ip"].value_counts().reset_index()
                new_ips_df.columns = ["ip", "запросов"]
                st.dataframe(new_ips_df.head(50), width="stretch", hide_index=True)

            st.divider()
            st.subheader("Новые сигнатуры атак в логе «после»")
            attacks_a = cached_detect_attacks(file_hash, df)
            attacks_b = cached_detect_attacks(file_hash_b, df_b)
            new_attack_ips = sorted(set(attacks_b["ip"]) - set(attacks_a["ip"])) if not attacks_b.empty else []
            if new_attack_ips:
                st.error(f"Новые IP со сканированием уязвимостей: {', '.join(new_attack_ips[:20])}")
            else:
                st.success("Новых источников сканирования в логе «после» не появилось.")


# --- Данные и экспорт ----------------------------------------------------
with tab_export:
    st.subheader("Отфильтрованные записи")
    st.caption(f"Показано записей: {len(filtered_df)} из {len(df)} исходных")

    display_cols = ["datetime", "ip", "method", "url", "status", "size", "is_bot"]
    st.dataframe(filtered_df[display_cols], width="stretch", hide_index=True, height=420)

    col_csv, col_json = st.columns(2)
    with col_csv:
        st.download_button(
            "⬇️ Скачать в CSV (Excel RU: ';' + BOM)",
            data=to_excel_csv_bytes(filtered_df[display_cols]),
            file_name="access_log_filtered.csv",
            mime="text/csv",
            width="stretch",
        )
    with col_json:
        st.download_button(
            "⬇️ Скачать в JSON",
            data=filtered_df[display_cols].to_json(orient="records", force_ascii=False, date_format="iso"),
            file_name="access_log_filtered.json",
            mime="application/json",
            width="stretch",
        )

st.sidebar.divider()
st.sidebar.caption("Файл обрабатывается в памяти процесса и нигде не сохраняется на диске.")
