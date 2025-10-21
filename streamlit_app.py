import streamlit as st
import gspread
import pandas as pd
from google.oauth2.service_account import Credentials
import datetime as dt

SHEET_TITLE = "PullupsSheet"   # your Google Sheet name
TAB_NAME    = "overview"            # the tab name

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

st.title("🔌 Google Sheets connection test")

ws = get_ws()

# Read all
records = ws.get_all_records()
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
