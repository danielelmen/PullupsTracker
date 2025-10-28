import streamlit as st
import gspread
import pandas as pd
from google.oauth2.service_account import Credentials
import datetime as dt
import re
from typing import List, Optional
import random, time
from gspread.exceptions import APIError, WorksheetNotFound
from datetime import datetime, date, timedelta, timezone
import pytz
import base64, hmac, hashlib, json
import extra_streamlit_components as stx  # NEW
from html import escape


#Remember login
AUTH_SECRET = st.secrets.get("auth_secret", "dev-secret-change-me").encode("utf-8")
REMEMBER_DAYS = int(st.secrets.get("remember_days", 30))
COOKIE_NAME = st.secrets.get("cookie_name", "pullups_auth")
COOKIE_KEY = st.secrets.get("cookie_key", "pullups_cookie_namespace")  # namespace for the component

_COOKIE_MGR = None  # <-- global singleton

# --- Token helpers (HMAC-signeret payload) ---
def _b64u(x: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(x).decode().rstrip("=")

def _b64u_dec(s: str) -> bytes:
    import base64
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

def _now_ts() -> int:
    return int(time.time())

def _sign(payload: dict) -> str:
    msg = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(AUTH_SECRET, msg, hashlib.sha256).digest()
    return _b64u(msg) + "." + _b64u(sig)

def _verify(token: str) -> Optional[dict]:
    try:
        msg_b64, sig_b64 = token.split(".", 1)
        msg = _b64u_dec(msg_b64)
        expected = hmac.new(AUTH_SECRET, msg, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64u_dec(sig_b64)):
            return None
        payload = json.loads(msg.decode())
        if int(payload.get("exp", 0)) < _now_ts():
            return None
        return payload
    except Exception:
        return None

def _issue_token(username: str, days: int = REMEMBER_DAYS) -> str:
    payload = {"u": username, "exp": _now_ts() + days * 24 * 3600, "v": 1}
    return _sign(payload)

# --- Cookie manager (top-level cookies, delt på tværs af faner) ---
def _get_cookie_mgr():
    global _COOKIE_MGR
    if _COOKIE_MGR is None:
        # Opret KUN én CookieManager med stabil key
        _COOKIE_MGR = stx.CookieManager(key=COOKIE_KEY)
    return _COOKIE_MGR

def _set_cookie(token: str | None):
    cm = _get_cookie_mgr()
    if token:
        expires = datetime.now(timezone.utc) + timedelta(days=REMEMBER_DAYS)
        cm.set(COOKIE_NAME, token, expires_at=expires, same_site="Lax")
    else:
        cm.delete(COOKIE_NAME)

def _get_cookie() -> str | None:
    cm = _get_cookie_mgr()
    v = cm.get(COOKIE_NAME)
    if isinstance(v, dict):  # kompatibilitet på tværs af versioner
        return v.get(COOKIE_NAME)
    return v

def get_user_goal(username: str) -> tuple[int, bool]:
    """Returnér (goal, found) — dvs. om brugeren allerede har et mål i settings."""
    df = read_settings_df()
    rec = df[df["username"].str.lower() == username.lower()]
    if rec.empty:
        return DEFAULT_WEEKLY_GOAL, False  # Ikke fundet i settings
    return int(rec.iloc[0]["weekly_goal"]), True

def monday_of(d: pd.Timestamp) -> pd.Timestamp:
    # Returnér mandag for den uge, som d tilhører
    return d - pd.Timedelta(days=d.weekday())

def ensure_week_start(df: pd.DataFrame) -> pd.DataFrame:
    """Sikrer at df har en 'week_start'-kolonne i YYYY-MM-DD (date).
    Hvis kolonnen allerede findes, coerces til dato; ellers beregnes ud fra 'date'.
    """
    tmp = df.copy()
    if "week_start" in tmp.columns:
        tmp["week_start"] = pd.to_datetime(tmp["week_start"], errors="coerce")
    else:
        # Fald tilbage til 'date' hvis week_start ikke findes
        tmp["date"] = pd.to_datetime(tmp["date"], errors="coerce")
        tmp["week_start"] = tmp["date"].apply(monday_of)
    tmp["week_start"] = tmp["week_start"].dt.date
    return tmp

def compute_weekly_totals(df: pd.DataFrame, goal: int):
    """Returnerer liste [(week_start_date, total, reached_bool)] sorteret stigende."""
    if df.empty:
        return []
    tmp = ensure_week_start(df)
    # Sørg for numerisk pullups
    tmp["pullups"] = pd.to_numeric(tmp["pullups"], errors="coerce").fillna(0).astype(int)
    w = tmp.groupby("week_start")["pullups"].sum().sort_index()
    return [(ws, int(total), total >= goal) for ws, total in w.items()]

def current_streak(weekly_list):
    """Tæl uger i træk (baglæns) hvor målet er nået, ekskl. igangværende uge."""
    # Find mandag i den aktuelle uge
    today = pd.Timestamp.today().normalize()
    this_week_start = (today - pd.Timedelta(days=today.weekday())).date()

    # Fjern igangværende uge, hvis den ligger sidst i listen
    if weekly_list and weekly_list[-1][0] == this_week_start:
        weekly_iter = reversed(weekly_list[:-1])
    else:
        weekly_iter = reversed(weekly_list)

    s = 0
    for _, _, ok in weekly_iter:
        if ok:
            s += 1
        else:
            break
    return s

def gs_retry(fn, *args, **kwargs):
    # Retries ved typiske midlertidige fejl (429/5xx)
    delays = [0.25, 0.5, 1.0, 2.0]  # ~4 forsøg, ca. 3.75s max
    for i, d in enumerate([0.0] + delays):
        try:
            return fn(*args, **kwargs)
        except APIError as e:
            # gspread redacter beskeden, så vi kan ikke parse koden sikkert.
            # Vi antager midlertidig fejl og prøver igen nogle få gange.
            if i == len(delays):
                raise
            time.sleep(d + random.random()*0.1)

@st.cache_data(ttl=60)
def list_user_tabs() -> List[str]:
    """Returnér alle data-faner (ekskl. _settings og skjulte)."""
    _, sh = get_client_and_sheet()
    # <- beskyt API-kaldet med gs_retry
    worksheets = gs_retry(sh.worksheets)
    titles = [ws.title for ws in worksheets]
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
            # <- Begge netværkskald beskyttes af retry
            ws = gs_retry(sh.worksheet, name)
            values = gs_retry(ws.get, "A1:E10000")

            if not values:
                continue

            headers = values[0]
            rows = values[1:]

            # Normalisér rækker ift. headers-længde
            rows = [r + [""] * (len(headers) - len(r)) for r in rows]
            rows = [r[:len(headers)] for r in rows]

            df_i = pd.DataFrame(rows, columns=headers)

            if not df_i.empty:
                # Sikr kolonner og typer
                if "pullups" in df_i.columns:
                    df_i["pullups"] = pd.to_numeric(df_i["pullups"], errors="coerce").fillna(0).astype(int)
                frames.append(df_i)

        except gspread.exceptions.WorksheetNotFound:
            # Fanen findes ikke (kan være slettet i mellemtiden) -> spring over
            continue
        except gspread.exceptions.APIError:
            # Midlertidig fejl selv efter retries -> spring denne fane over
            # (alternativ: re-raise hvis du hellere vil fail'e hårdt)
            continue

    if not frames:
        return pd.DataFrame(columns=DATA_HEADERS)

    df = pd.concat(frames, ignore_index=True)

    # Udfyld evt. manglende kolonner og bestil kolonne-rækkefølge
    for c in DATA_HEADERS:
        if c not in df.columns:
            df[c] = 0 if c == "pullups" else ""

    # Returnér kun de forventede kolonner i korrekt orden
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

    # ← beskyt selve API-kaldet med gs_retry
    worksheets = gs_retry(sh.worksheets)
    titles = [ws.title for ws in worksheets]

    # filtrér bort settings og skjulte faner
    return [t for t in titles if t != SETTINGS_SHEET and not t.startswith("_")]

@st.cache_data(ttl=30)  # evt. lidt længere cache for at skåne API'et
def read_all_users_df(tab_names: List[str]) -> pd.DataFrame:
    """Læs alle brugeres data og returnér ét samlet DF med samme kolonner som DATA_HEADERS."""
    if not tab_names:
        return pd.DataFrame(columns=DATA_HEADERS)

    frames = []
    _, sh = get_client_and_sheet()

    for name in tab_names:
        try:
            # ← Tilføj gs_retry her for at håndtere rate limits / 5xx
            ws = gs_retry(sh.worksheet, name)
            values = gs_retry(ws.get, "A1:E10000")

            if not values:
                continue

            headers = values[0]
            rows = values[1:]

            # udfyld manglende celler, så alle rækker har samme længde
            rows = [r + [""] * (len(headers) - len(r)) for r in rows]
            rows = [r[:len(headers)] for r in rows]

            df_i = pd.DataFrame(rows, columns=headers)

            if not df_i.empty and "pullups" in df_i.columns:
                df_i["pullups"] = pd.to_numeric(
                    df_i["pullups"], errors="coerce"
                ).fillna(0).astype(int)

            frames.append(df_i)

        except gspread.exceptions.WorksheetNotFound:
            # f.eks. hvis fanen er slettet i mellemtiden
            continue
        except gspread.exceptions.APIError:
            # midlertidig fejl trods retries -> spring over
            continue
        except Exception as e:
            # andre fejl logges evt. som warning
            st.warning(f"Fejl ved læsning af '{name}': {e}")
            continue

    if not frames:
        return pd.DataFrame(columns=DATA_HEADERS)

    df = pd.concat(frames, ignore_index=True)

    # sikkerhed: udfyld manglende kolonner
    for c in DATA_HEADERS:
        if c not in df.columns:
            df[c] = 0 if c == "pullups" else ""

    return df[DATA_HEADERS]


def compute_week_label(d: dt.date) -> str:
    iso = d.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"

################ Konfiguration ####################
DATA_HEADERS = ["username","date","pullups","week_start","week_number"]
SHEET_NAME = st.secrets.get("SHEET")
MOTIVATION_TAB = "motivation"
# Valgfrit: fast "seed"-dato så rotationen er stabil uanset app restarts.
ROTATION_SEED = st.secrets.get("ROTATION_SEED", "2025-01-01")
TZ = pytz.timezone("Europe/Copenhagen")

# --- Google Sheets klient (cachet) ---
@st.cache_resource(show_spinner=False)
def get_gs_client():
    creds = Credentials.from_service_account_info(st.secrets["gcp_service_account"])
    scoped = creds.with_scopes([
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
    ])
    return gspread.authorize(scoped)

# --- Hent beskeder (cachet pr. dag for automatisk skift ved midnat) ---
@st.cache_data(show_spinner=False)
def load_motivation_messages(_date_key: str) -> list[str]:
    """
    _date_key bruges kun til at invaliderer cachen ved dato-skift.
    """
    gc = get_gs_client()

    # Brug gs_retry omkring alle netværkskald til Sheets
    try:
        sh = gs_retry(gc.open, SHEET_NAME)
    except APIError:
        # Hvis alle forsøg fejler, fail-soft (vis standardbanner)
        return []

    try:
        ws = gs_retry(sh.worksheet, MOTIVATION_TAB)
    except WorksheetNotFound:
        # Fane mangler — fail-soft
        return []
    except APIError:
        return []

    # Forsøg at læse rækker som records
    try:
        values = gs_retry(ws.get_all_records, head=1, default_blank="")
    except APIError:
        values = []

    df = pd.DataFrame(values)

    if "message" not in df.columns or df.empty:
        # Fallback: læs ren kolonne 1 hvis ingen header/records
        try:
            col = gs_retry(ws.col_values, 1)
        except APIError:
            col = []
        # drop evt. header hvis du har en
        msgs = [x for x in col if x and str(x).strip().lower() != "message"]
        return [str(m).strip() for m in msgs if str(m).strip()]

    # filtrér på enabled hvis kolonnen findes
    if "enabled" in df.columns:
        df = df[df["enabled"].astype(str).str.upper().isin(["TRUE", "1", "YES"])]

    msgs = [str(m).strip() for m in df["message"].tolist() if str(m).strip()]
    return msgs

def pick_today_message(messages: list[str]) -> str:
    if not messages:
        return "Breaking: Intet nyt… men pull-upsne laver ikke sig selv! 💪"

    today_local = datetime.now(TZ).date()
    seed_date = date.fromisoformat(ROTATION_SEED)
    days_since = (today_local - seed_date).days
    idx = days_since % len(messages)
    return messages[idx]

def render_top_banner(text: str):
    # kompakt “breaking news”-agtigt banner
    st.markdown(
        f"""
        <div style="
            background: linear-gradient(90deg, #FEE2E2, #FEF3C7);
            border: 1px solid #FCA5A5;
            padding: 10px 12px;
            border-radius: 10px;
            font-size: 0.95rem;
            display: flex; align-items: center; gap: 8px;
        ">
          <span style="
            background:#F37D7D; color:black; font-weight:700; 
            padding: 2px 8px; border-radius: 6px; font-size: 0.80rem;
            letter-spacing: .5px;
          ">🔔 Update</span>
          <span style="color:#111827;">{text}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )



# Nyt _settings layout uden "locked"
SETTINGS_SHEET = "_settings"
SETTINGS_HEADERS = ["username","weekly_goal","updated_at"]

DEFAULT_WEEKLY_GOAL = 500
GOAL_MIN, GOAL_MAX = 50, 10000  # enkel sanity range

################ Login ####################
users = st.secrets.get("users", {})


def authenticate():
    # Sørg for at komponenten er oprettet én gang i dette run
    _ = _get_cookie_mgr()

    st.session_state.setdefault("authenticated", False)
    st.session_state.setdefault("username", "")

    # 1) Session already authed
    if st.session_state["authenticated"]:
        return

    # 2) Prøv auto-login via cookie
    token = _get_cookie()
    if token:
        payload = _verify(token)
        if payload and (u := payload.get("u")) in users:
            st.session_state["authenticated"] = True
            st.session_state["username"] = u
            # valgfrit: “rolling” fornyelse
            fresh = _issue_token(u)
            _set_cookie(fresh)
            return

    # 3) Ingen gyldig cookie -> vis login-form
    st.title("Log ind")
    username = st.text_input("Brugernavn")
    password = st.text_input("Adgangskode", type="password")
    remember = st.checkbox("Forbliv logget (hvis din enhed tillader det)", value=True)

    if st.button("Login"):
        if username in users and users[username] == password:
            st.session_state["authenticated"] = True
            st.session_state["username"] = username

            if remember:
                t = _issue_token(username)
                _set_cookie(t)  # skriv cookie i browseren

                # VIGTIGT: giv browseren et øjeblik til at skrive cookien,
                # reload i TOP-vinduet, og stop Python-runnet nu.
                st.success("Logget ind – husker dit login på denne enhed.")
                st.markdown(
                    """
                    <script>
                    setTimeout(function(){
                    try { window.top.location.reload(); }
                    catch(e){ window.location.reload(); }
                    }, 150);
                    </script>
                    """,
                    unsafe_allow_html=True
                )
                st.stop()
            else:
                _set_cookie(None)
                st.rerun()
        else:
            st.error("Forkert brugernavn eller adgangskode")

    st.stop()  # stop resten af appen når ikke logget ind



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
    sh = gc.open(SHEET_NAME)
    return gc, sh

def ensure_user_ws(tab_name: str):
    """Åbn eller opret data-fanen (ingen cache her)."""
    _, sh = get_client_and_sheet()
    try:
        # ← beskyt mod midlertidige API-fejl
        ws = gs_retry(sh.worksheet, tab_name)
    except gspread.exceptions.WorksheetNotFound:
        # ← også beskyt disse to
        ws = gs_retry(sh.add_worksheet, title=tab_name, rows=1000, cols=10)
        gs_retry(ws.update, "A1", [DATA_HEADERS])  # skriv headers første gang
    return ws


def ensure_headers(ws, expected_headers):
    first_row = gs_retry(ws.row_values, 1)      # ← retry
    if not first_row or first_row != expected_headers:
        gs_retry(ws.update, "A1", [expected_headers])  # ← retry


def ensure_settings_ws():
    """Opret/_åbn settings-worksheet uden 'locked'. Har migrations-tålmodighed."""
    _, sh = get_client_and_sheet()

    try:
        # Beskyt API-kaldet mod midlertidige fejl
        ws = gs_retry(sh.worksheet, SETTINGS_SHEET)
    except gspread.exceptions.WorksheetNotFound:
        # Hvis arket ikke findes, opret det
        ws = gs_retry(sh.add_worksheet, title=SETTINGS_SHEET, rows=100, cols=10)
        gs_retry(ws.update, "A1", [SETTINGS_HEADERS])
        return ws

    # Hent første række (headers)
    headers = gs_retry(ws.row_values, 1)

    # Hvis headers ikke matcher, opdatér dem
    if headers != SETTINGS_HEADERS:
        gs_retry(ws.update, "A1", [SETTINGS_HEADERS])

    return ws


@st.cache_data(ttl=20)  # evt. en anelse højere end 15 for færre API-kald
def read_user_df(tab_name: str) -> pd.DataFrame:
    _, sh = get_client_and_sheet()
    try:
        ws = gs_retry(sh.worksheet, tab_name)          # API-kald 1 (retry)
        values = gs_retry(ws.get, "A1:E10000")         # API-kald 2 (retry)
    except gspread.exceptions.WorksheetNotFound:
        return pd.DataFrame(columns=DATA_HEADERS)
    except gspread.exceptions.APIError:
        # Midlertidig fejl selv efter retries – returnér tomt DF i korrekt format
        return pd.DataFrame(columns=DATA_HEADERS)

    if not values:
        return pd.DataFrame(columns=DATA_HEADERS)

    headers = values[0]
    rows = values[1:]

    # Normalisér rækker ift. headers-længde
    rows = [r + [""] * (len(headers) - len(r)) for r in rows]
    rows = [r[:len(headers)] for r in rows]

    df = pd.DataFrame(rows, columns=headers)

    # Sørg for forventede kolonner & typer
    for c in DATA_HEADERS:
        if c not in df.columns:
            df[c] = 0 if c == "pullups" else ""

    if not df.empty:
        df["pullups"] = pd.to_numeric(df["pullups"], errors="coerce").fillna(0).astype(int)

    # Returnér kun i den forventede kolonneorden
    return df[DATA_HEADERS]


@st.cache_data(ttl=120)  # du kan evt. øge TTL, da settings sjældent ændres
def read_settings_df() -> pd.DataFrame:
    ws = ensure_settings_ws()

    # ← beskyt selve hentningen af værdier med gs_retry
    values = gs_retry(ws.get, "A1:C10000")

    if not values:
        return pd.DataFrame(columns=SETTINGS_HEADERS)

    headers = values[0]
    rows = values[1:]

    # Migration: håndtér gamle versioner med 'locked' som ekstra kolonne
    if len(headers) >= 3:
        rows = [r + [""] * (len(headers) - len(r)) for r in rows]
        rows = [r[:3] for r in rows]

    df = pd.DataFrame(rows, columns=SETTINGS_HEADERS)

    if not df.empty:
        df["weekly_goal"] = pd.to_numeric(
            df["weekly_goal"], errors="coerce"
        ).fillna(DEFAULT_WEEKLY_GOAL).astype(int)

    return df


def set_user_goal(username: str, goal: int):
    """Skriv/overskriv målet i _settings (altid frit ændreligt)."""
    # (valgfrit) clamp for sanity
    try:
        g = int(goal)
    except Exception:
        g = DEFAULT_WEEKLY_GOAL
    g = max(GOAL_MIN, min(GOAL_MAX, g))

    ws = ensure_settings_ws()

    # Hent alle værdier (API-kald) m. retry
    data = gs_retry(ws.get_all_values)
    headers = data[0] if data else SETTINGS_HEADERS

    # find eksisterende række
    idx = None
    for i, r in enumerate(data[1:], start=2):  # 1-baseret, spring headers over
        if len(r) > 0 and r[0].strip().lower() == username.strip().lower():
            idx = i
            break

    now_iso = dt.datetime.now().isoformat(timespec="seconds")
    row = [username, str(g), now_iso]

    if idx is None:
        gs_retry(ws.append_row, row)                 # API-kald m. retry
    else:
        gs_retry(ws.update, f"A{idx}:C{idx}", [row]) # API-kald m. retry

    # Målrettet cache-rydning (ikke global)
    try:
        read_settings_df.clear()
    except Exception:
        pass

    # Opdatér session state så UI'er reflekterer det nye mål uden ekstra læs
    st.session_state["current_goal"] = g
    st.session_state["goal_user"] = username

def perform_logout():
    _ = _get_cookie_mgr()  # sikrer at komponenten er renderet

    st.session_state["authenticated"] = False
    st.session_state["username"] = ""

    try:
        _get_cookie_mgr().delete(COOKIE_NAME)
    except Exception:
        pass

    st.markdown(
        "<script>setTimeout(()=>{ try{window.top.location.reload()}catch(e){location.reload()} }, 80);</script>",
        unsafe_allow_html=True
    )
    st.stop()

# --- UI: hent mål og vis hint indtil brugerne har gemt data ---
current_goal, goal_found = get_user_goal(user)

with st.sidebar:
    if st.session_state.get("authenticated"):
        st.markdown("### ⚙️ Indstillinger")
        st.caption(f"Logget ind som **{user}**")

        # Log ud-knap (nulstiller session)
        if st.button("Log ud", use_container_width=True):
            perform_logout()

        st.write(f"Aktuelt ugemål: **{current_goal}**")
        with st.expander("Rediger ugemål", expanded=False):
            new_goal = st.number_input(
                "Ugentligt mål (reps)",
                min_value=GOAL_MIN, max_value=GOAL_MAX,
                value=int(current_goal), step=10, key="goal_input"
            )
            if st.button("Gem mål", key="save_goal_btn"):
                set_user_goal(user, int(new_goal))
                st.success(f"Ugemål gemt ({int(new_goal)}).")
                st.rerun()
    else:
        # (valgfrit) lille hint når man ikke er logget ind
        st.info("Log ind for at se indstillinger.")


# Vises kun hvis brugeren ikke har noget i settings endnu
if not goal_found:
    st.info("Hey! Du skal lige vælge dit ugentlige mål i sidebaren under **Indstillinger**.")

################ Forside: data & logging ####################
tab_name = user_tab(user)
st.title(f"💪 Pull-ups 💪")
st.caption(f"🏋️ Velkommen {user}")

# --- Kør banneret ---
today_key = datetime.now(TZ).strftime("%Y-%m-%d")  # tvinger cache-refresh hver kalenderdag i København
_messages = load_motivation_messages(today_key)
render_top_banner(pick_today_message(_messages))

tab1, tab2, tab3 = st.tabs(["Min uge", "Community", "Info"])
with tab1:
    ws = ensure_user_ws(tab_name)
    df = read_user_df(tab_name)

    # --------- UI / MIN UGE (PLACÉR I DIN VISNINGSDEL) ---------
    # Forudsætter at du har sat login/session tidligere:
    username = st.session_state.get("username", "")

    # 1) Hent alle faner og data (cachede helpers)
    tab_names = list_user_tabs()
    all_df = read_all_users_df(tab_names)

    # 2) Filtrér til aktuel bruger
    df_user = all_df[all_df["username"].str.lower() == username.lower()].copy()

    # 3) Sæt ugemål og beregn streak
    # Hent mål fra _settings (cachet) og spejl i session for ensartethed i UI
    current_goal, found = get_user_goal(username)      # din funktion fra før
    st.session_state["weekly_goal"] = int(current_goal)

    weekly = compute_weekly_totals(df_user, int(current_goal))
    streak = current_streak(weekly)

    # 4) Beregn denne uges tal til UI
    tmp = ensure_week_start(df_user)
    now = pd.Timestamp.now(tz=TZ)            # bruger din TZ = Europe/Copenhagen
    this_monday = (now - pd.Timedelta(days=now.weekday())).date()
    weekly_total = int(tmp.loc[tmp["week_start"] == this_monday, "pullups"].sum()) if not tmp.empty else 0

    remaining = max(0, int(current_goal) - weekly_total)
    days_left = 7 - now.weekday()            # inkl. i dag
    avg_needed = (remaining / max(1, days_left)) if current_goal > 0 else 0
    progress = (weekly_total / current_goal) if current_goal > 0 else 0.0


    # 6) (Valgfrit) Fejr når ugemål nås
    if weekly_total >= current_goal:
        st.success("Du er i MÅL! 💥")
        st.balloons()

    # --- All time ---
    all_time_total = int(df["pullups"].sum()) if not df.empty else 0


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



    st.markdown(f"""
    <div class="hero-card">
    <div class="hero-block">
        <div class="hero-label">All time</div>
        <div class="hero-number">{format_int(all_time_total)}</div>
    </div>

    <div class="hero-block">
        <div class="hero-label">I dag</div>
        <div class="hero-number">{format_int(my_day_total)}</div>
    </div>

    <div class="hero-block">
        <div class="hero-label">Ugestreak 🔥</div>
        <div class="hero-number">{format_int(int(streak))}</div>
    </div>
    </div>
    """, unsafe_allow_html=True)




    st.write("")  # bare for at lave lidt luft

    # Quick log (kun for dig selv)
    with st.form("log_pullups"):
        qty = st.number_input("Tilføj pullups", min_value=0, step=5)
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

            try:
                # Sørg for at headers findes, og beskyt alle API-kald
                ensure_headers(ws, DATA_HEADERS)
                gs_retry(ws.append_row, row)

                st.success(f"Tilføjede {qty} for {user}")

                # Ryd kun relevante caches (ikke globalt)
                try:
                    read_user_df.clear()
                    read_all_users_df.clear()
                    list_user_tabs.clear()
                except Exception:
                    pass

                st.rerun()

            except gspread.exceptions.APIError:
                st.warning("Der opstod et midlertidigt problem med Google Sheets. Prøv igen om et øjeblik.")
            except Exception as e:
                st.error(f"Uventet fejl under logning: {e}")


    #Display af tre elementer
    # --- Responsive metrics: 3 i én række (2 på meget små mobiler) ---
    st.markdown(f"""
    <style>
    .metrics-grid {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0,1fr)); /* 3 kolonner som standard */
    gap: 10px;
    margin: 6px 0 10px 0;
    }}
    @media (max-width: 380px) {{
    /* Ekstra smalle mobiler: 2 kolonner for bedre læsbarhed */
    .metrics-grid {{ grid-template-columns: repeat(2, minmax(0,1fr)); }}
    }}

    .metric-card {{
    border: 1px solid #e5e7eb; border-radius: 14px;
    background: linear-gradient(135deg, #f8fafc, #f1f5f9);
    padding: 10px 12px;
    }}
    .metric-label {{
    font-size: 12px; color: #6b7280; line-height: 1.1;
    }}
    .metric-value {{
    font-size: clamp(18px, 3.5vw, 22px);
    font-weight: 800; line-height: 1.1; color: #111827;
    }}

    @media (prefers-color-scheme: dark) {{
    .metric-card {{ border-color:#334155; background: linear-gradient(135deg,#0b1220,#0f172a); }}
    .metric-label {{ color:#9ca3af; }}
    .metric-value {{ color:#e5e7eb; }}
    }}
    </style>

    <div class="metrics-grid">
    <div class="metric-card">
        <div class="metric-label">Denne uge</div>
        <div class="metric-value">{int(my_week_total)}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Tilbage</div>
        <div class="metric-value">{int(remaining)}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Resterende pr/dag</div>
        <div class="metric-value">{int(avg_needed)}</div>
    </div>
    </div>
    """, unsafe_allow_html=True)



    st.subheader("Dagens pull-ups!")

    if my_week.empty:
        st.dataframe(pd.DataFrame(columns=["date", "pullups"]), use_container_width=True)
    else:
        # Filtrér til dagens dato
        today_str = dt.date.today().isoformat()
        today_logs = my_week[my_week["date"] == today_str]

        if today_logs.empty:
            st.info("Ingen logs for i dag endnu.")
        else:
            st.dataframe(
                today_logs[["date", "pullups"]]
                .sort_values("date", ascending=False)
                .reset_index(drop=True),
                use_container_width=True,
                hide_index=True
            )


        # --- Slet seneste log ---
        if st.button("🗑️ Fortryd seneste log"):
            try:
                # Beskyt API-kald mod midlertidige fejl
                all_values = gs_retry(ws.get_all_values)

                if len(all_values) <= 1:
                    st.info("Ingen rækker at slette endnu.")
                else:
                    last_row_index = len(all_values)  # 1-baseret i Sheets
                    last_row = all_values[-1]

                    # Ekstra sikkerhed: tjek at rækken tilhører brugeren
                    if last_row and last_row[0].strip().lower() == user.lower():
                        gs_retry(ws.delete_rows, last_row_index)  # ← retry med backoff
                        st.success(f"Slettede seneste log ({last_row[1]} – {last_row[2]} reps)")

                        # Ryd kun relevante caches (ikke globalt)
                        try:
                            read_user_df.clear()
                            read_all_users_df.clear()
                            list_user_tabs.clear()
                        except Exception:
                            pass

                        st.rerun()
                    else:
                        st.warning("Den seneste række ser ikke ud til at være din.")
            except gspread.exceptions.APIError:
                st.error("Google Sheets svarede ikke. Prøv igen om et øjeblik.")
            except Exception as e:
                st.error(f"Uventet fejl: {e}")


        # --- 7 dags-metrics (Mandag–Søndag), responsivt grid ---
        DANISH_DOW = ["Mandag", "Tirsdag", "Onsdag", "Torsdag", "Fredag", "Lørdag", "Søndag"]

        week_start_date = monday_of_week(dt.date.today())  # mandag (date-objekt)
        week_days = [week_start_date + dt.timedelta(days=i) for i in range(7)]

        # Byg dagssummer ud fra my_week (som allerede er filtreret til denne uge)
        if my_week.empty:
            daily_map = {d: 0 for d in week_days}
        else:
            tmp = my_week.copy()
            tmp["date"] = pd.to_datetime(tmp["date"], errors="coerce").dt.date
            grouped = tmp.groupby("date", as_index=False)["pullups"].sum()
            daily_map = {d: 0 for d in week_days}
            for _, r in grouped.iterrows():
                if r["date"] in daily_map:
                    daily_map[r["date"]] = int(r["pullups"])

        today = dt.date.today()

        st.markdown("""
        <style>
        .day-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr)); /* Mobil: 3 -> 3+3+1 */
        gap: 10px;
        margin: 6px 0 12px 0;
        }
        @media (max-width: 380px) {
        .day-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        }
        @media (min-width: 640px) {
        .day-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
        }
        @media (min-width: 1024px) {
        .day-grid { grid-template-columns: repeat(7, minmax(0, 1fr)); }
        }

        .day-card {
        border: 1px solid #e5e7eb;
        border-radius: 14px;
        background: linear-gradient(135deg, #f8fafc, #f1f5f9);
        padding: 10px 12px;
        display: flex; flex-direction: column; gap: 4px;
        }
        .day-card .lab { font-size: 12px; color: #6b7280; line-height: 1.1; }
        .day-card .date { font-size: 11px; color: #94a3b8; }
        .day-card .val { font-size: clamp(18px, 3.3vw, 22px); font-weight: 800; color: #111827; }

        .day-card.is-today { border-color: #60a5fa; box-shadow: 0 0 0 2px rgba(96,165,250,0.15) inset; }
        .day-card.is-weekend .lab { color: #64748b; }
        .day-card.is-zero .val { opacity: 0.8; }

        @media (prefers-color-scheme: dark) {
        .day-card { border-color:#334155; background: linear-gradient(135deg,#0b1220,#0f172a); }
        .day-card .lab { color:#9ca3af; }
        .day-card .date { color:#64748b; }
        .day-card .val { color:#e5e7eb; }
        .day-card.is-today { border-color:#38bdf8; box-shadow: 0 0 0 2px rgba(56,189,248,0.18) inset; }
        }
        </style>
        """, unsafe_allow_html=True)

        # Byg kortene (HTML), med highlight af "i dag" og weekend
        cards_html = []
        for i, d in enumerate(week_days):
            label = DANISH_DOW[i]
            val = daily_map.get(d, 0)
            date_str = d.strftime("%d/%m")
            classes = ["day-card"]
            if d == dt.date.today():
                classes.append("is-today")
            if i >= 5:
                classes.append("is-weekend")
            if val == 0:
                classes.append("is-zero")
            cards_html.append(
                f'<div class="{" ".join(classes)}">'
                f'<div class="lab">{label}</div>'
                f'<div class="date">{date_str}</div>'
                f'<div class="val">{val}</div>'
                f'</div>'
            )

        st.markdown('<div class="day-grid">' + "".join(cards_html) + '</div>', unsafe_allow_html=True)




        # --- Ugentlige resultater ---
        st.subheader("Ugentlige resultater")
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
                lambda r: f"{int(r['iso_year'])} - Week {int(r['iso_week']):02d}" if pd.notna(r["iso_year"]) and pd.notna(r["iso_week"]) else "",
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
    st.header("Hall of PAIN")

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

    # --- Community all-time (øverst) ---
    community_all_time = int(all_df["pullups"].sum()) if not all_df.empty else 0
    avg_per_user = int(round(community_all_time / max(1, len(participants))))  # valgfrit: snit pr. person

    st.markdown(f"""
    <div class="hero-card" style="margin-top:8px;">
    <div class="hero-left">
        <div class="hero-label">Community all time</div>
        <div class="hero-number">{format_int(community_all_time)}</div>
        <div class="hero-sub">samlet antal pullups</div>
    </div>
    <div class="hero-right">
        <div>👥 Deltagere</div>
        <div class="chip">{len(participants)}</div>
    </div>
    </div>
    """, unsafe_allow_html=True)

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
    st.subheader("🔥Ugentligt leaderboard")

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


    # --- All-time leaderboard (uden 'Uger') ---
    st.subheader("🏆All-time leaderboard")
    if not all_df.empty:
        # Grundtal: total pr. bruger
        totals = (all_df.groupby("username", as_index=False)["pullups"]
                        .sum().rename(columns={"pullups": "Total"}))

        # Sørg for week_start er sat korrekt til ugens mandag
        tmp = ensure_week_start(all_df.copy())

        # Beregn uge-streaks pr. bruger
        goal = st.session_state.get("weekly_goal", 500)
        streak_rows = []
        for user, df_u in tmp.groupby("username"):
            weekly = compute_weekly_totals(df_u, goal)   # [(week_start, total, reached_bool), ...]
            s = current_streak(weekly)
            streak_rows.append({"username": user, "Uge streaks": int(s)})

        streak_df = pd.DataFrame(streak_rows)

        # Merge og sortér (primært efter streaks, sekundært efter total)
        board = (totals.merge(streak_df, on="username", how="left")
                    .fillna({"Uge streaks": 0})
                    .astype({"Uge streaks": int})
                    .sort_values(["Total", "Uge streaks"], ascending=[False, False])
                    .reset_index(drop=True))

        st.dataframe(
            board.rename(columns={"username": "Bruger"})[["Bruger", "Total", "Uge streaks"]],
            use_container_width=True, hide_index=True
        )
    else:
        st.info("Ingen logs endnu til all-time leaderboardet.")


with tab3:
    st.header("Challenge")
    st.write("Sæt dit ugentlige pull-up-mål i menuen til venstre")
    st.write("Du bestemmer selv, hvordan du vil fordele dem, bare du når i mål inden ugen slutter")
    st.write("Log dine pull-ups i boksen på forsiden. (Du kan også altid slette det seneste entry ved at klikke på fortryd knappen)")
    st.write("Se hvor mange du mangler for at nå ugens mål")
    st.write("Følg din fremgang og streaks uge for uge")
    st.write("Brug community-fanen til at se, hvordan det går de andre")
    st.write("")
    st.write("")
    st.write("")
    st.write("")
    st.header("GET STRONG!")