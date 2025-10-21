import streamlit as st
import gspread
import pandas as pd
from google.oauth2.service_account import Credentials
import datetime as dt
import re

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
st.write(f"Du er logget ind som: {user}")

################ Google Sheets ####################

SHEET_TITLE = "PullupsSheet"  # skal matche din Google Sheet titel
HEADERS     = ["username","date","pullups","week_start","week_number"]

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
    """Åbn eller opret fanen (ingen cache her)."""
    _, sh = get_client_and_sheet()
    try:
        ws = sh.worksheet(tab_name)
    except gspread.exceptions.WorksheetNotFound:
        ws = sh.add_worksheet(title=tab_name, rows=1000, cols=10)
        ws.update("A1", [HEADERS])  # skriv headers første gang
    return ws

def ensure_headers(ws):
    first_row = ws.row_values(1)
    if not first_row or first_row != HEADERS:
        ws.update("A1", [HEADERS])

@st.cache_data(ttl=15)
def read_user_df(tab_name: str) -> pd.DataFrame:
    """Cache på STRINGS, ikke worksheet-objekter."""
    _, sh = get_client_and_sheet()
    ws = sh.worksheet(tab_name)  # åbnes inde i funktionen
    values = ws.get("A1:E10000")  # eksplicit range > stabilt
    if not values:
        return pd.DataFrame(columns=HEADERS)
    headers = values[0]
    rows = values[1:]
    rows = [r + [""]*(len(headers)-len(r)) for r in rows]
    rows = [r[:len(headers)] for r in rows]
    df = pd.DataFrame(rows, columns=headers)
    if not df.empty:
        df["pullups"] = pd.to_numeric(df["pullups"], errors="coerce").fillna(0).astype(int)
    return df

# ---------- Forside: Kun egne data ----------
tab_name = user_tab(user)
st.title(f"🏋️ Din uge, {user}")

ws = ensure_user_ws(tab_name)   # lås til brugerens fane (opret hvis mangler)
df = read_user_df(tab_name)     # cache læsning baseret på fanenavn (hashbar)

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
        ensure_headers(ws)
        ws.append_row(row)
        st.success(f"Tilføjede {qty} for {user}")
        st.cache_data.clear()  # opdatér visning
        st.rerun()

# Stats for i dag og denne uge
today = dt.date.today()
this_week_start = monday_of_week(today).isoformat()

my_week = pd.DataFrame(columns=df.columns if not df.empty else HEADERS)
my_day_total = 0
my_week_total = 0

if not df.empty:
    my_week = df[df["week_start"] == this_week_start]
    my_day_total = int(my_week[my_week["date"] == today.isoformat()]["pullups"].sum())
    my_week_total = int(my_week["pullups"].sum())

remaining = max(500 - my_week_total, 0)
days_left = max(1, 7 - today.weekday())  # inkl. i dag
avg_needed = (remaining + days_left - 1) // days_left  # ceil

col1, col2, col3, col4 = st.columns(4)
col1.metric("I dag", my_day_total)
col2.metric("Denne uge", my_week_total)
col3.metric("Til 500", remaining)
col4.metric("Behov / dag", avg_needed)
st.progress(min(my_week_total/500, 1.0))

st.subheader("Dine loggede sæt (denne uge)")
st.dataframe(
    my_week[["date","pullups"]].sort_values("date", ascending=False).reset_index(drop=True)
    if not my_week.empty else pd.DataFrame(columns=["date","pullups"]),
    use_container_width=True
)
