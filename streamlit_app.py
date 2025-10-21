import streamlit as st
import gspread
import pandas as pd
from google.oauth2.service_account import Credentials
import datetime as dt

################ Login ####################

users = st.secrets.get("users", {})

def authenticate():
    """Håndterer login med en sikker og stabil metode."""
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
                st.rerun()  # Tvinger en opdatering af appen
            else:
                st.error("Forkert brugernavn eller adgangskode")
        
        st.stop()

authenticate()

user = st.session_state["username"]
st.write(f"Du er logget ind som: {user}")

################ Google sheets test

SHEET_TITLE = "PullupsSheet"   # your Google Sheet name
TAB_NAME    = "Sheets1"            # the tab name

@st.cache_resource
def get_ws():
    # Build creds from secrets
    creds = Credentials.from_service_account_info(
        st.secrets["gcp_service_account"],
        scopes=[
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive",
        ],
    )
    gc = gspread.authorize(creds)
    sh = gc.open(SHEET_TITLE)
    return sh.worksheet(TAB_NAME)

st.title("Pull-up Tracker!")

ws = get_ws()

# Read all
try:
    records = ws.get_all_records()
except gspread.exceptions.APIError as e:
    st.error("Google Sheets API fejl")
    st.exception(e)
    try:
        st.write("Response status:", getattr(e, "response", None).status_code)
        st.write("Response text:", getattr(e, "response", None).text[:500])
    except Exception:
        pass
    st.stop()
df = pd.DataFrame(records)
st.subheader("Current data")
st.dataframe(df if not df.empty else pd.DataFrame(columns=["username","date","pullups","week_start","week_number"]), use_container_width=True)

# Quick write test
with st.form("write_test"):
    st.write("Append a test row:")
    username = st.text_input("username", value="tester")
    qty = st.number_input("pullups", min_value=1, value=10)
    submitted = st.form_submit_button("Append")
    if submitted:
        today = dt.date.today()
        monday = today - dt.timedelta(days=today.weekday())
        row = [
            username,
            today.isoformat(),
            int(qty),
            monday.isoformat(),
            today.isocalendar().week
        ]
        ws.append_row(row)
        st.success("Row appended ✅")
        st.rerun()
