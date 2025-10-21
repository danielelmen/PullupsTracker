import streamlit as st
import gspread
import pandas as pd
from google.oauth2.service_account import Credentials
import datetime as dt
import re
from typing import List

@st.cache_data(ttl=60)
def list_user_tabs() -> List[str]:
    """Returnér alle data-faner (ekskl. _settings og skjulte)."""
    _, sh = get_client_and_sheet()
    titles = [ws.title for ws in sh.worksheets()]
    return [t for t in titles if t != SETTINGS_SHEET and not t.startswith("_")]

@st.cache_data(ttl=15)
def read_all_users_df(tab_names: List[str]) -> pd.DataFrame:
    """Læs alle brugeres data og returnér ét samlet DF med DATA_HEADERS."""
    if not tab_names:
        return pd.DataFrame(columns=DATA_HEADERS)
    frames = []
    _, sh = get_client_and_sheet()
    for name in tab_names:
        try:
            ws = sh.worksheet(name)
            values = ws.get("A1:E10000")
            if not values:
                continue
            headers = values[0]
            rows = values[1:]
            rows = [r + [""]*(len(headers)-len(r)) for r in rows]
            rows = [r[:len(headers)] for r in rows]
            df_i = pd.DataFrame(rows, columns=headers)
            if not df_i.empty:
                df_i["pullups"] = pd.to_numeric(df_i["pullups"], errors="coerce").fillna(0).astype(int)
            frames.append(df_i)
        except Exception:
            continue
    if not frames:
        return pd.DataFrame(columns=DATA_HEADERS)
    df = pd.concat(frames, ignore_index=True)
    for c in DATA_HEADERS:
        if c not in df.columns:
            df[c] = "" if c != "pullups" else 0
    return df[DATA_HEADERS]

# --- UI helper & styles ---
def format_int(n: int) -> str:
    # DK-format med punktum som tusindtalsseparator
    return f"{n:,}".replace(",", ".")

st.markdown("""
<style>
.hero-card{
  display:flex;justify-content:space-between;align-items:center;gap:16px;
  padding:18px 22px;border-radius:16px;border:1px solid #e5e7eb;
  background:linear-gradient(135deg,#0ea5e933,#22c55e33);
}
.hero-left .hero-label{font-size:14px;color:#374151}
.hero-left .hero-number{font-size:42px;font-weight:800;line-height:1.1;margin-top:4px}
.hero-left .hero-sub{font-size:12px;color:#6b7280;margin-top:2px}
.hero-right{display:flex;gap:8px;align-items:center}
.chip{padding:6px 10px;border-radius:999px;background:#111827;color:#fff;font-weight:600}
@media (prefers-color-scheme: dark){
  .hero-card{border-color:#374151;background:linear-gradient(135deg,#0ea5e91a,#22c55e1a)}
  .hero-left .hero-label,.hero-left .hero-sub{color:#9ca3af}
}
</style>
""", unsafe_allow_html=True)

# -------- Community helpers --------
from typing import List

@st.cache_data(ttl=60)
def list_user_tabs() -> List[str]:
    """Returnér alle data-faner (ekskl. _settings og skjulte)."""
    _, sh = get_client_and_sheet()
    titles = [ws.title for ws in sh.worksheets()]
    return [t for t in titles if t != SETTINGS_SHEET and not t.startswith("_")]

@st.cache_data(ttl=15)
def read_all_users_df(tab_names: List[str]) -> pd.DataFrame:
    """Læs alle brugeres data og returnér ét samlet DF med samme kolonner som DATA_HEADERS."""
    if not tab_names:
        return pd.DataFrame(columns=DATA_HEADERS)
    frames = []
    _, sh = get_client_and_sheet()
    for name in tab_names:
        try:
            ws = sh.worksheet(name)
            values = ws.get("A1:E10000")
            if not values:
                continue
            headers = values[0]
            rows = values[1:]
            rows = [r + [""]*(len(headers)-len(r)) for r in rows]
            rows = [r[:len(headers)] for r in rows]
            df_i = pd.DataFrame(rows, columns=headers)
            if not df_i.empty:
                df_i["pullups"] = pd.to_numeric(df_i["pullups"], errors="coerce").fillna(0).astype(int)
            frames.append(df_i)
        except Exception:
            # Ignorér faner der ikke kan læses
            continue
    if not frames:
        return pd.DataFrame(columns=DATA_HEADERS)
    df = pd.concat(frames, ignore_index=True)
    # sikkerhed: udfyld manglende kolonner
    for c in DATA_HEADERS:
        if c not in df.columns:
            df[c] = "" if c != "pullups" else 0
    return df[DATA_HEADERS]

def compute_week_label(d: dt.date) -> str:
    iso = d.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"

################ Konfiguration ####################
SHEET_TITLE = "PullupsSheet"  # skal matche din Google Sheet titel
DATA_HEADERS = ["username","date","pullups","week_start","week_number"]

# Nyt _settings layout uden "locked"
SETTINGS_SHEET = "_settings"
SETTINGS_HEADERS = ["username","weekly_goal","updated_at"]

DEFAULT_WEEKLY_GOAL = 500
GOAL_MIN, GOAL_MAX = 50, 10000  # enkel sanity range

################ Login ####################
users = st.secrets.get("users", {})

def authenticate():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "username" not in st.session_state:
        st.session_state["username"] = ""
    if not st.session_state["authenticated"]:
        st.title("Log ind")
        username = st.text_input("Brugernavn")
        password = st.text_input("Adgangskode", type="password")
        if st.button("Login"):
            if username in users and users[username] == password:
                st.session_state["authenticated"] = True
                st.session_state["username"] = username
                st.success("Login lykkedes! Appen genindlæses...")
                st.rerun()
            else:
                st.error("Forkert brugernavn eller adgangskode")
        st.stop()

authenticate()
user = st.session_state["username"]

################ Google Sheets ####################
def monday_of_week(d: dt.date) -> dt.date:
    return d - dt.timedelta(days=d.weekday())  # mandag=0

def user_tab(username: str) -> str:
    """Sanitizér brugernavn til et gyldigt fanenavn."""
    u = username.strip().lower()
    u = re.sub(r'[^a-z0-9\-]+', '-', u)
    u = re.sub(r'-{2,}', '-', u).strip('-')[:90]
    return u or "user"

@st.cache_resource
def get_client_and_sheet():
    creds = Credentials.from_service_account_info(
        st.secrets["gcp_service_account"],
        scopes=[
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive",
        ],
    )
    gc = gspread.authorize(creds)
    sh = gc.open(SHEET_TITLE)
    return gc, sh

def ensure_user_ws(tab_name: str):
    """Åbn eller opret data-fanen (ingen cache her)."""
    _, sh = get_client_and_sheet()
    try:
        ws = sh.worksheet(tab_name)
    except gspread.exceptions.WorksheetNotFound:
        ws = sh.add_worksheet(title=tab_name, rows=1000, cols=10)
        ws.update("A1", [DATA_HEADERS])  # skriv headers første gang
    return ws

def ensure_headers(ws, expected_headers):
    first_row = ws.row_values(1)
    if not first_row or first_row != expected_headers:
        ws.update("A1", [expected_headers])

def ensure_settings_ws():
    """Opret/_åbn settings-worksheet uden 'locked'. Har migrations-tålmodighed."""
    _, sh = get_client_and_sheet()
    try:
        ws = sh.worksheet(SETTINGS_SHEET)
    except gspread.exceptions.WorksheetNotFound:
        ws = sh.add_worksheet(title=SETTINGS_SHEET, rows=100, cols=10)
        ws.update("A1", [SETTINGS_HEADERS])
        return ws

    # Hvis arket findes men mangler de rigtige headers, opdatér dem
    headers = ws.row_values(1)
    if headers != SETTINGS_HEADERS:
        # Accepter gamle varianter med 'locked' og omskriv til nye headers i minnet
        ws.update("A1", [SETTINGS_HEADERS])
    return ws

@st.cache_data(ttl=15)
def read_user_df(tab_name: str) -> pd.DataFrame:
    _, sh = get_client_and_sheet()
    ws = sh.worksheet(tab_name)
    values = ws.get("A1:E10000")
    if not values:
        return pd.DataFrame(columns=DATA_HEADERS)
    headers = values[0]
    rows = values[1:]
    rows = [r + [""]*(len(headers)-len(r)) for r in rows]
    rows = [r[:len(headers)] for r in rows]
    df = pd.DataFrame(rows, columns=headers)
    if not df.empty:
        df["pullups"] = pd.to_numeric(df["pullups"], errors="coerce").fillna(0).astype(int)
    return df

@st.cache_data(ttl=60)
def read_settings_df() -> pd.DataFrame:
    ws = ensure_settings_ws()
    values = ws.get("A1:C10000")  # nye 3 kolonner
    if not values:
        return pd.DataFrame(columns=SETTINGS_HEADERS)

    headers = values[0]
    rows = values[1:]
    # Migration: hvis der ligger en ældre version med 4 kolonner (inkl. locked),
    # så trim til de første 3 (username, weekly_goal, updated_at)
    if len(headers) >= 3:
        rows = [r + [""]*(len(headers)-len(r)) for r in rows]
        # Map/trim til første 3 kolonner
        rows = [r[:3] for r in rows]

    df = pd.DataFrame(rows, columns=SETTINGS_HEADERS)
    if not df.empty:
        df["weekly_goal"] = pd.to_numeric(df["weekly_goal"], errors="coerce").fillna(DEFAULT_WEEKLY_GOAL).astype(int)
    return df

def get_user_goal(username: str) -> tuple[int, bool]:
    """Returnér (goal, found) — dvs. om brugeren allerede har et mål i settings."""
    df = read_settings_df()
    rec = df[df["username"].str.lower() == username.lower()]
    if rec.empty:
        return DEFAULT_WEEKLY_GOAL, False  # Ikke fundet i settings
    return int(rec.iloc[0]["weekly_goal"]), True

def set_user_goal(username: str, goal: int):
    """Skriv/overskriv målet i _settings (altid frit ændreligt)."""
    _, sh = get_client_and_sheet()
    ws = ensure_settings_ws()
    data = ws.get_all_values()
    headers = data[0] if data else SETTINGS_HEADERS

    # find eksisterende række
    idx = None
    for i, r in enumerate(data[1:], start=2):  # 1-baseret, spring headers over
        if len(r) > 0 and r[0].strip().lower() == username.strip().lower():
            idx = i
            break

    now_iso = dt.datetime.now().isoformat(timespec="seconds")
    row = [username, str(int(goal)), now_iso]

    if idx is None:
        ws.append_row(row)
    else:
        ws.update(f"A{idx}:C{idx}", [row])

    st.cache_data.clear()  # ryd læse-caches

# --- UI: hent mål og vis hint kun første gang ---
current_goal, goal_found = get_user_goal(user)

with st.sidebar:
    st.markdown("### ⚙️ Indstillinger")
    st.write(f"Aktuelt ugemål: **{current_goal}**")
    with st.expander("Rediger ugemål", expanded=False):
        new_goal = st.number_input("Ugentligt mål (reps)", min_value=GOAL_MIN, max_value=GOAL_MAX,
                                   value=int(current_goal), step=10)
        if st.button("Gem mål"):
            set_user_goal(user, int(new_goal))
            st.success(f"Ugemål gemt ({int(new_goal)}).")
            st.rerun()

# Vises kun hvis brugeren ikke har noget i settings endnu
if not goal_found:
    st.info("Tip: Du kan vælge dit ugentlige mål i sidebaren under **Indstillinger**.")

################ Forside: data & logging ####################
tab_name = user_tab(user)
st.title(f"🏋️ Din uge, {user}")

tab1, tab2 = st.tabs(["Min uge", "Community"])
with tab1:
    ws = ensure_user_ws(tab_name)
    df = read_user_df(tab_name)

    # --- All time & startdato (beregning) ---
    all_time_total = int(df["pullups"].sum()) if not df.empty else 0
    first_date = None
    if not df.empty and "date" in df.columns:
        try:
            first_date = pd.to_datetime(df["date"]).min().date()
        except Exception:
            first_date = None

    # --- HERO: All time i toppen ---
    st.markdown(f"""
    <div class="hero-card">
    <div class="hero-left">
        <div class="hero-label">All time</div>
        <div class="hero-number">{format_int(all_time_total)}</div>
        {f'<div class="hero-sub">siden {first_date.isoformat()}</div>' if first_date else ''}
    </div>
    <div class="hero-right">
        <div>Ugemål</div>
        <div class="chip">{format_int(int(current_goal))}</div>
    </div>
    </div>
    """, unsafe_allow_html=True)


    # Quick log (kun for dig selv)
    with st.form("log_pullups"):
        qty = st.number_input("Tilføj pullups", min_value=1, step=5)
        add = st.form_submit_button("Tilføj")
        if add:
            today = dt.date.today()
            row = [
                user,
                today.isoformat(),
                int(qty),
                monday_of_week(today).isoformat(),
                today.isocalendar().week,
            ]
            ensure_headers(ws, DATA_HEADERS)
            ws.append_row(row)
            st.success(f"Tilføjede {qty} for {user}")
            st.cache_data.clear()
            st.rerun()

    # Stats for i dag og denne uge
    today = dt.date.today()
    this_week_start = monday_of_week(today).isoformat()

    my_week = pd.DataFrame(columns=df.columns if not df.empty else DATA_HEADERS)
    my_day_total = 0
    my_week_total = 0

    if not df.empty:
        my_week = df[df["week_start"] == this_week_start]
        my_day_total = int(my_week[my_week["date"] == today.isoformat()]["pullups"].sum())
        my_week_total = int(my_week["pullups"].sum())

    goal = max(int(current_goal), 1)
    remaining = max(goal - my_week_total, 0)
    days_left = max(1, 7 - today.weekday())  # inkl. i dag
    avg_needed = (remaining + days_left - 1) // days_left  # ceil

    # 4 metrics (uden All time)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("I dag", my_day_total)
    col2.metric("Denne uge", my_week_total)
    col3.metric(f"Til {goal}", remaining)
    col4.metric("Behov / dag", avg_needed)


    st.subheader("Dine loggede pullups (denne uge)")
    st.dataframe(
        my_week[["date","pullups"]].sort_values("date", ascending=False).reset_index(drop=True)
        if not my_week.empty else pd.DataFrame(columns=["date","pullups"]),
        use_container_width=True
    )

    # --- Slet seneste log ---
    if st.button("🗑️ Fortryd seneste log"):
        all_values = ws.get_all_values()
        if len(all_values) <= 1:
            st.info("Ingen rækker at slette endnu.")
        else:
            last_row_index = len(all_values)  # 1-baseret i Sheets
            last_row = all_values[-1]
            if last_row[0].lower() == user.lower():
                ws.delete_rows(last_row_index)
                st.success(f"Slettede seneste log ({last_row[1]} – {last_row[2]} reps)")
                st.cache_data.clear()
                st.rerun()
            else:
                st.warning("Den seneste række ser ikke ud til at være din.")

    # --- Ugentlige totaler (all time) ---
    st.subheader("Ugentlige totaler (all time)")
    if df.empty:
        st.info("Ingen data endnu.")
    else:
        # Sikr datatyper
        tmp = df.copy()
        tmp["pullups"] = pd.to_numeric(tmp["pullups"], errors="coerce").fillna(0).astype(int)
        # Brug eksisterende week_start (allerede mandag) og beregn iso-år/uge for tydelig label
        tmp["week_start"] = pd.to_datetime(tmp["week_start"], errors="coerce").dt.date
        # Fald tilbage hvis week_start mangler/er tom: rekalkulér fra date
        mask_missing_ws = tmp["week_start"].isna()
        if mask_missing_ws.any():
            tmp_date = pd.to_datetime(tmp.loc[mask_missing_ws, "date"], errors="coerce").dt.date
            tmp.loc[mask_missing_ws, "week_start"] = tmp_date.map(lambda d: monday_of_week(d) if pd.notna(d) else pd.NaT)

        # iso label (år-uge)
        try:
            ws_dt = pd.to_datetime(tmp["week_start"])
            iso_year = ws_dt.dt.isocalendar().year.astype(int)
            iso_week = ws_dt.dt.isocalendar().week.astype(int)
        except Exception:
            # fallback hvis parsning fejler
            iso_year = pd.Series([None]*len(tmp))
            iso_week = pd.Series([None]*len(tmp))

        tmp["iso_year"] = iso_year
        tmp["iso_week"] = iso_week

        weekly = (
            tmp.groupby(["iso_year", "iso_week", "week_start"], dropna=False)["pullups"]
            .sum()
            .reset_index()
            .sort_values(["week_start"], ascending=False)
        )

        # Tilføj mål, status og progress for hver uge
        weekly["goal"] = int(current_goal)
        weekly["status"] = weekly["pullups"].ge(weekly["goal"]).map({True: "✅ Opnået", False: "⏳ Ikke i mål"})
        weekly["progress"] = (weekly["pullups"] / weekly["goal"]).clip(upper=1.0)

        # Pæne labels/kolonner
        weekly["uge"] = weekly.apply(
            lambda r: f"{int(r['iso_year'])}-W{int(r['iso_week']):02d}" if pd.notna(r["iso_year"]) and pd.notna(r["iso_week"]) else "",
            axis=1
        )
        weekly["uge_start"] = weekly["week_start"].astype(str)

        # Vælg og omdøb kolonner til visning
        view = weekly[["uge", "uge_start", "pullups", "goal", "status"]].rename(
            columns={
                "uge": "Uge",
                "uge_start": "Uge start",
                "pullups": "Total",
                "goal": "Mål",
                "status": "Status",
            }
        )

        # Streamlit-tabel
        st.dataframe(
            view,
            use_container_width=True,
            hide_index=True,
        )
# ------------- FANEN: Community -------------
with tab2:
    st.header("🌍 Community")

    # --- Hent data ---
    tabs = list_user_tabs()
    all_df = read_all_users_df(tabs)
    settings_df = read_settings_df()

    if all_df.empty and settings_df.empty:
        st.info("Ingen community-data endnu.")
        st.stop()

    # --- Typer: sørg for at week_start er DATE (ikke string) ---
    if not all_df.empty:
        all_df["pullups"] = pd.to_numeric(all_df["pullups"], errors="coerce").fillna(0).astype(int)
        all_df["week_start"] = pd.to_datetime(all_df["week_start"], errors="coerce").dt.date
        all_df["date"] = pd.to_datetime(all_df["date"], errors="coerce").dt.date

    if not settings_df.empty:
        settings_df["weekly_goal"] = pd.to_numeric(settings_df["weekly_goal"], errors="coerce")\
                                        .fillna(DEFAULT_WEEKLY_GOAL).astype(int)

    # Deltagere: union af dem der har data + dem der findes i settings (ingen case-ændringer)
    users_in_data = set(all_df["username"].dropna().astype(str)) if not all_df.empty else set()
    users_in_settings = set(settings_df["username"].dropna().astype(str)) if not settings_df.empty else set()
    participants = sorted(users_in_data.union(users_in_settings))

    # --- Denne uge (date vs date!) ---
    today = dt.date.today()
    this_week_start = monday_of_week(today)  # date-objekt

    if not all_df.empty:
        week_df = all_df[all_df["week_start"] == this_week_start]
        week_totals = (week_df.groupby("username", as_index=False)["pullups"]
                               .sum().rename(columns={"pullups":"week_total"}))
    else:
        week_totals = pd.DataFrame(columns=["username","week_total"])

    # Mål pr. bruger
    goals = settings_df[["username","weekly_goal"]].copy() if not settings_df.empty \
            else pd.DataFrame(columns=["username","weekly_goal"])

    # Fuldt leaderboard (alle deltagere, 0 hvis ingen logs)
    base = pd.DataFrame({"username": participants})
    leaderboard = base.merge(week_totals, how="left", on="username")\
                      .merge(goals, how="left", on="username")
    leaderboard["week_total"] = leaderboard["week_total"].fillna(0).astype(int)
    leaderboard["weekly_goal"] = leaderboard["weekly_goal"].fillna(DEFAULT_WEEKLY_GOAL).astype(int)
    leaderboard["pct"] = (leaderboard["week_total"] / leaderboard["weekly_goal"]).replace([pd.NA, float("inf")], 0).fillna(0.0)
    leaderboard["Status"] = leaderboard["pct"].ge(1.0).map({True:"✅ Opnået", False:"⏳ Ikke endnu"})
    leaderboard = leaderboard.sort_values(["pct","week_total"], ascending=[False, False]).reset_index(drop=True)

    # --- Community hero ---
    community_week_total = int(leaderboard["week_total"].sum())
    community_week_goal  = int(leaderboard["weekly_goal"].sum())
    community_pct        = 0 if community_week_goal == 0 else community_week_total / community_week_goal

    st.markdown(f"""
    <div class="hero-card" style="margin-top:8px;">
      <div class="hero-left">
        <div class="hero-label">Denne uge ({compute_week_label(today)})</div>
        <div class="hero-number">{format_int(community_week_total)} / {format_int(community_week_goal)}</div>
        <div class="hero-sub">{int(community_pct*100)}% af fælles ugemål</div>
      </div>
      <div class="hero-right">
        <div>👥 Deltagere</div>
        <div class="chip">{len(participants)}</div>
      </div>
    </div>
    """, unsafe_allow_html=True)
    st.progress(min(community_pct, 1.0))

    # --- Ugentligt leaderboard (denne uge) ---
    st.subheader("🔥Ugentligt leaderboard🔥")

    # lav en 0–100 kolonne til visning
    view = leaderboard.copy()
    view["FremdriftPct"] = (view["pct"] * 100).clip(lower=0, upper=100)

    st.data_editor(
        view.rename(columns={
            "username": "Bruger",
            "week_total": "Ugens total",
            "weekly_goal": "Mål",
            "FremdriftPct": "Fremdrift",
            "Status": "Status",
        })[["Bruger", "Ugens total", "Mål", "Fremdrift", "Status"]],
        use_container_width=True,
        hide_index=True,
        disabled=True,
        column_config={
            "Ugens total": st.column_config.NumberColumn("Ugens total", format="%d"),
            "Mål": st.column_config.NumberColumn("Mål", format="%d"),
            "Fremdrift": st.column_config.ProgressColumn(
                "Fremdrift",
                help="Andel af ugemål",
                format="%.0f%%",   # nu passer det, fordi værdien er 0–100
                min_value=0,
                max_value=100,
            ),
        }
    )


    # --- All-time leaderboard ---
    st.subheader("🏆All-time leaderboard🏆")
    if not all_df.empty:
        alltime = (all_df.groupby("username", as_index=False)["pullups"]
                          .sum().rename(columns={"pullups":"Total"}))
        weeks_per_user = (all_df.dropna(subset=["week_start"])
                               .groupby("username")["week_start"].nunique()
                               .reset_index().rename(columns={"week_start":"Uger"}))
        alltime = alltime.merge(weeks_per_user, how="left", on="username")
        alltime["Uger"] = alltime["Uger"].fillna(0).astype(int)
        alltime["Snit/uge"] = alltime.apply(lambda r: int(r["Total"]/r["Uger"]) if r["Uger"] > 0 else 0, axis=1)
        alltime = alltime.sort_values("Total", ascending=False).reset_index(drop=True)

        st.dataframe(
            alltime.rename(columns={"username":"Bruger"})[["Bruger","Total","Snit/uge","Uger"]],
            use_container_width=True, hide_index=True
        )
    else:
        st.info("Ingen logs endnu til all-time leaderboardet.")
