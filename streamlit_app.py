import streamlit as st
import gspread
import pandas as pd
from google.oauth2.service_account import Credentials
import datetime as dt
import re

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

ws = ensure_user_ws(tab_name)
df = read_user_df(tab_name)

# All-time total for brugeren
all_time_total = int(df["pullups"].sum()) if not df.empty else 0

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

# 5 metrics inkl. all-time
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("I dag", my_day_total)
col2.metric("Denne uge", my_week_total)
col3.metric(f"Til {goal}", remaining)
col4.metric("Behov / dag", avg_needed)
col5.metric("All time", all_time_total)
st.progress(min(my_week_total / goal, 1.0))

# --- (Valgfrit) vis startdato for all time ---
first_date = None
if not df.empty and "date" in df.columns:
    try:
        first_date = pd.to_datetime(df["date"]).min().date()
    except Exception:
        first_date = None

if first_date:
    st.caption(f"All time tæller fra **{first_date.isoformat()}**")

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
