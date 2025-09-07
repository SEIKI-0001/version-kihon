# app.py
# ============================================
# Study Plan API (itパス / 基本情報 切替対応, Calendar省略版)
# ============================================

# ===== Standard Library =====
import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional, List, Tuple, Dict

# ===== Third-party =====
import pandas as pd
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials as UserCredentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.cloud import storage
import random
from pydantic import BaseModel, AnyUrl
from fastapi.openapi.utils import get_openapi
from google.auth.exceptions import RefreshError

# ===== Configuration (env) =====
USER_TZ = os.getenv("USER_TZ", "Asia/Tokyo")
TZ_OFFSET = os.getenv("TZ_OFFSET", "+09:00")
BASE_URL = os.getenv("BASE_URL")  # e.g. https://<service>.a.run.app
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
APP_SECRET = os.getenv("APP_SECRET", "")
TOKEN_BUCKET = os.getenv("TOKEN_BUCKET", "gpts-oauth-tokens")
USER_SHEET_MAP_BUCKET = os.getenv("USER_SHEET_MAP_BUCKET", "user-sheet-mapping")
USER_SHEET_MAP_BLOB = os.getenv("USER_SHEET_MAP_BLOB", "mapping.json")
BACKUP_BUCKET = os.getenv("BACKUP_BUCKET", "gpts-plans-backup")
SERVICE_API_KEY = os.getenv("SERVICE_API_KEY", "")
BOOK_DATA_BUCKET = os.getenv("BOOK_DATA_BUCKET", "study-book-data")

# ← 追加: 試験種別とGCSパスの切替（itpass / kihon）
EXAM_TYPE = os.getenv("EXAM_TYPE", "itpass")  # "itpass" or "kihon"
BOOK_DATA_PREFIX = os.getenv("BOOK_DATA_PREFIX", "")  # 例: "kihon" / "itpass" / ""（無指定は直下）

ACRONYM_BUCKET = os.getenv("ACRONYM_BUCKET", "maru-acronyms")
ACRONYM_PATH = os.getenv(
    "ACRONYM_PATH",
    "acronyms/kihon_core.json" if EXAM_TYPE == "kihon" else "acronyms/itpass_core.json"
)
ACRONYM_REFRESH_SEC = int(os.getenv("ACRONYM_REFRESH_SEC", "3600"))

_AC_CACHE = {"terms": {}, "last": 0, "etag": None}

# Google API スコープ（Calendarは省略可。Sheets/Driveは必須）
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
]

# ===== 列マッピング =====
FIELD_TO_COL = {
    "task name": "B",
    "date": "C",
    "day": "D",
    "duration": "E",
    "status": "F",
}

# ===== ルート例外 =====
EXEMPT_PATHS = {"/", "/health", "/oauth/start", "/oauth/callback", "/auth/status"}

# ===== OAuth state TTL =====
STATE_TTL = 10 * 60  # sec
DAY_ABBR = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

# ===== FastAPI =====
app = FastAPI()

_GCS: Optional[storage.Client] = None
_SHEETS: Dict[str, Any] = {}
_ACCESS: Dict[str, UserCredentials] = {}


# ===== GCS =====
def gcs() -> storage.Client:
    global _GCS
    if _GCS is None:
        _GCS = storage.Client()
    return _GCS


# ===== Token Store (GCS) =====
def _token_bucket() -> storage.Bucket:
    return gcs().bucket(TOKEN_BUCKET)

def _token_blob_path(user_id: str) -> str:
    safe = base64.urlsafe_b64encode(user_id.encode()).decode().rstrip("=")
    return f"tokens/{safe}.json"

def save_refresh_token(user_id: str, refresh_token: str):
    blob = _token_bucket().blob(_token_blob_path(user_id))
    data = {"user_id": user_id, "refresh_token": refresh_token, "updated_at": int(time.time())}
    blob.upload_from_string(json.dumps(data, ensure_ascii=False), content_type="application/json")

def load_refresh_token(user_id: str) -> Optional[str]:
    blob = _token_bucket().blob(_token_blob_path(user_id))
    try:
        data = json.loads(blob.download_as_text())
        return data.get("refresh_token")
    except Exception:
        return None

def _delete_refresh_token(user_id: str):
    try:
        gcs().bucket(TOKEN_BUCKET).blob(_token_blob_path(user_id)).delete()
    except Exception:
        pass


# ===== OAuth State =====
def _state_blob(state: str):
    return _token_bucket().blob(f"oauth_state/{state}.json")

def save_oauth_state(state: str, data: dict):
    data = {**data, "exp": int(time.time()) + STATE_TTL}
    _state_blob(state).upload_from_string(json.dumps(data), content_type="application/json")

def pop_oauth_state(state: str) -> Optional[dict]:
    b = _state_blob(state)
    try:
        data = json.loads(b.download_as_text())
        if data.get("exp", 0) < int(time.time()):
            return None
        try:
            b.delete()
        except Exception:
            pass
        return data
    except Exception:
        return None


# ===== OAuth Client =====
def oauth_redirect_uri() -> str:
    base = (BASE_URL or "").rstrip("/")
    if not base:
        raise RuntimeError("BASE_URL is not configured")
    return f"{base}/oauth/callback"

def build_flow() -> Flow:
    client_config = {
        "web": {
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [oauth_redirect_uri()],
        }
    }
    return Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=oauth_redirect_uri())

def signed_state(user_id: str) -> str:
    ts = int(time.time())
    msg = f"{user_id}|{ts}".encode()
    sig = hmac.new(APP_SECRET.encode(), msg, hashlib.sha256).digest()
    packed = base64.urlsafe_b64encode(msg + b"|" + base64.urlsafe_b64encode(sig)).decode()
    return packed.rstrip("=")

def verify_state(state: str) -> Optional[str]:
    try:
        raw = base64.urlsafe_b64decode(state + "===")
        parts = raw.split(b"|")
        if len(parts) != 3:
            return None
        user_id = parts[0].decode()
        ts = int(parts[1].decode())
        sig_b64 = parts[2]
        expected = hmac.new(APP_SECRET.encode(), f"{user_id}|{ts}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(base64.urlsafe_b64encode(expected), sig_b64):
            return None
        if time.time() - ts > STATE_TTL:
            return None
        return user_id
    except Exception:
        return None


# ===== Credentials Cache =====
def _get_creds_cached(user_id: str) -> Optional[UserCredentials]:
    prev = _ACCESS.get(user_id)
    if prev and prev.valid:
        return prev

    rt = load_refresh_token(user_id)
    if not rt:
        return None

    creds = UserCredentials(
        token=getattr(prev, "token", None) if prev else None,
        refresh_token=rt,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=OAUTH_CLIENT_ID,
        client_secret=OAUTH_CLIENT_SECRET,
        scopes=SCOPES,
    )
    try:
        if not creds.valid:
            creds.refresh(GoogleRequest())
    except RefreshError:
        _delete_refresh_token(user_id)
        _ACCESS.pop(user_id, None)
        return None
    _ACCESS[user_id] = creds
    return creds

def load_user_credentials(user_id: str) -> Optional[UserCredentials]:
    return _get_creds_cached(user_id)


# ===== Google APIs =====
def get_user_sheets_service(user_id: str):
    if user_id in _SHEETS:
        return _SHEETS[user_id]
    creds = load_user_credentials(user_id)
    if not creds:
        return None
    svc = build("sheets", "v4", credentials=creds, cache_discovery=False)
    _SHEETS[user_id] = svc
    return svc


# ===== Utils (Date) =====
def parse_ymd(s: str) -> Optional[datetime.date]:
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None

def start_of_week(d: datetime.date) -> datetime.date:
    return d - timedelta(days=d.weekday())

def next_monday(today: Optional[datetime.date] = None) -> datetime.date:
    today = today or datetime.utcnow().date()
    n = (7 - today.weekday()) % 7
    n = 1 if n == 0 else n
    return today + timedelta(days=n)


# ===== OpenAPI =====
def required_envs_ok() -> bool:
    return all([BASE_URL, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, APP_SECRET, TOKEN_BUCKET])

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=f"Study Plan API ({EXAM_TYPE})",
        version="1.6.0",
        description="Study plan generator for IT Passport / FE (kihon).",
        routes=app.routes,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["ServiceBearer"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "API Key",
    }
    schema["security"] = [{"ServiceBearer": []}]
    for p in EXEMPT_PATHS:
        if "paths" in schema and p in schema["paths"]:
            schema["paths"][p].setdefault("get", {}).setdefault("security", [])
    app.openapi_schema = schema
    return schema

app.openapi = custom_openapi


# ===== API Key Guard =====
def verify_api_key(request: Request, authorization: str = Header(None)):
    path = (request.url.path or "/").rstrip("/") or "/"
    if path in EXEMPT_PATHS:
        return
    expected = (SERVICE_API_KEY or "").strip()
    if not expected:
        raise HTTPException(500, "Server API key not configured")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(403, "Invalid API key")
    provided = authorization[7:].strip()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(403, "Invalid API key")


# ===== Models (Pydantic) for Acronyms =====
try:
    from pydantic import ConfigDict  # v2
    V2 = True
except Exception:
    V2 = False

class AcronymSource(BaseModel):
    title: str | None = None
    url: AnyUrl | None = None

class AcronymCardModel(BaseModel):
    if V2:
        model_config = ConfigDict(extra='allow')
    else:
        class Config:
            extra = 'allow'
    term: str | None = None
    title: str | None = None
    description: str | None = None
    details: dict[str, Any] | None = None
    tags: list[str] | None = None
    sources: list[AcronymSource] | None = None

class AcronymCardsResponseModel(BaseModel):
    if V2:
        model_config = ConfigDict(extra='allow')
    else:
        class Config:
            extra = 'allow'
    cards: list[AcronymCardModel]
    count: int
    etag: str | None = None


# ===== Chapter helpers (GCS) =====
def _gcs_get_json_or_default(bucket_name: str, blob_path: str, default):
    try:
        b = gcs().bucket(bucket_name).blob(blob_path)
        return json.loads(b.download_as_text())
    except Exception:
        return default

def expand_chapter_items(counts: List[int], titles: Optional[List[str]] = None) -> List[str]:
    items = []
    for i, c in enumerate(counts):
        base = titles[i].strip() if titles and i < len(titles) and titles[i] else f"Chapter {i+1}"
        for j in range(1, int(c) + 1):
            items.append(f"{base} - Item {j}")
    return items

def _load_chapter_items_from_gcs_or_none(book_filename: str) -> Optional[List[str]]:
    # BOOK_DATA_PREFIX があればその下を見る（例: gs://study-book-data/kihon/{book}.json）
    path = f"{BOOK_DATA_PREFIX.strip('/')}/{book_filename}".strip("/")
    blob = gcs().bucket(BOOK_DATA_BUCKET).blob(path or book_filename)
    try:
        return json.loads(blob.download_as_text())
    except Exception:
        return None

def _normalize_chapter_items(data: dict, book_keyword: str) -> List[str]:
    # 1) payload を最優先
    if "chapter_items_list" in data and data["chapter_items_list"]:
        xs = data["chapter_items_list"]
        if all(isinstance(x, int) for x in xs):
            return expand_chapter_items(xs, None)
        if all(isinstance(x, str) for x in xs):
            return xs
        raise ValueError("chapter_items_list must be an array of integers or strings")

    if "chapter_counts" in data and data["chapter_counts"]:
        counts = [int(x) for x in data["chapter_counts"]]
        return expand_chapter_items(counts, None)

    if "chapters" in data and data["chapters"]:
        ch = data["chapters"]
        counts, titles = [], []
        for obj in ch:
            counts.append(int(obj.get("count", 0)))
            titles.append(str(obj.get("title") or "").strip() or None)
        return expand_chapter_items(counts, titles)

    # 2) GCS フォールバック
    fallback = _load_chapter_items_from_gcs_or_none(f"{book_keyword}.json")
    if fallback:
        return fallback

    # 3) 見つからなければエラー
    raise ValueError(
        "Chapter data not found. Provide one of: chapter_items_list (ints or strings), "
        "chapter_counts (ints), or chapters ([{title,count},...])."
    )


# ===== Study Planner =====
@dataclass
class UserSetting:
    user_id: str
    target_exam: datetime
    start_date: datetime
    weekday_minutes: int
    weekend_minutes: int
    rest_days: List[str]
    weekday_start: str
    weekend_start: str
    book_keyword: str

@dataclass
class Task:
    WBS: str
    Task_Name: str
    Date: datetime
    Duration: int
    Status: str = "未着手"

    @property
    def Day(self) -> str:
        return DAY_ABBR[self.Date.weekday()]

# 分割粒度（短学習）
MIN1 = 10
MIN2 = 7
MIN3 = 5

def weekday_abbr(d: datetime) -> str:
    return DAY_ABBR[d.weekday()]

def next_day(d: datetime) -> datetime:
    return d + timedelta(days=1)

def calculate_available_time(user: UserSetting, date: datetime) -> int:
    d = date.date() if isinstance(date, datetime) else date
    if DAY_ABBR[d.weekday()] in set(user.rest_days):
        return 0
    return user.weekend_minutes if d.weekday() >= 5 else user.weekday_minutes

class StudyPlanner:
    def __init__(self, user: UserSetting, chapter_items_list: List[str]):
        self.user = user
        self.chapter_items_list = chapter_items_list
        self.tasks: List[Task] = []
        self.wbs_counter = 0
        self.last_study_date: Optional[datetime] = None
        self.first_round_tasks: List[str] = []
        self.is_short = (self.user.target_exam - self.user.start_date).days <= 31

    def add_task(self, name: str, date: datetime, minutes: int):
        task = Task(f"wbs{self.wbs_counter}", name, date, minutes)
        self.tasks.append(task)
        self.wbs_counter += 1
        if self.last_study_date is None or date > self.last_study_date:
            self.last_study_date = date

    def allocate_tasks(self, tasks: List[Tuple[str, int]], start_date: datetime):
        current_date = start_date
        while tasks:
            if current_date > self.user.target_exam:
                break
            while calculate_available_time(self.user, current_date) == 0:
                current_date = next_day(current_date)
                if current_date > self.user.target_exam:
                    break
            available = calculate_available_time(self.user, current_date)
            while tasks and available >= tasks[0][1]:
                name, dur = tasks.pop(0)
                self.add_task(name, current_date, dur)
                available -= dur
            current_date = next_day(current_date)
        self.last_study_date = current_date
        return current_date

    def step0_setup(self):
        if self.user.weekday_minutes > 0:
            self.add_task("書籍の流し読みと概要把握", self.user.start_date, self.user.weekday_minutes)

    def step1_first_round(self):
        current_date = next_day(self.last_study_date)
        while self.chapter_items_list:
            available = calculate_available_time(self.user, current_date)
            while available >= MIN1 and self.chapter_items_list:
                name = self.chapter_items_list.pop(0)
                self.first_round_tasks.append(name)
                self.add_task(name, current_date, MIN1)
                available -= MIN1
            current_date = next_day(current_date)

    def step2_second_round(self):
        tasks = [(f"(2nd) {n}", MIN2) for n in self.first_round_tasks]
        self.allocate_tasks(tasks, next_day(self.last_study_date))

    def step3_first_exam(self):
        tasks = [("過去問 2025年 (1/2)", 60), ("過去問 2025年 (2/2)", 60), ("過去問 2025年 レビュー", 60)]
        self.allocate_tasks(tasks, next_day(next_day(self.last_study_date)))

    def step4_third_round(self):
        tasks = [(f"(3rd) {n}", MIN3) for n in self.first_round_tasks]
        self.allocate_tasks(tasks, next_day(self.last_study_date))

    def step5_weekend_reviews(self):
        current_date = self.user.start_date
        while current_date <= self.last_study_date:
            if current_date == self.user.start_date:
                current_date = next_day(current_date); continue
            day = weekday_abbr(current_date)
            if day == 'Sat':
                self.add_task("その週の復習", current_date, 60)
            elif day == 'Sun':
                self.add_task("アプリ演習と誤答復習", current_date, 60)
            current_date = next_day(current_date)

    def step6_refresh_days(self):
        current_date = next_day(self.last_study_date)
        for _ in range(2):
            self.add_task("リフレッシュ日", current_date, 0)
            current_date = next_day(current_date)

    def step7_past_exam_plan(self):
        YEARS = [2024, 2023, 2022, 2021, 2020, 2019, 2025]
        cutoff = self.user.target_exam - timedelta(days=1)
        start_date = next_day(self.last_study_date)

        def allocate_tasks_until(tasks, start_date, cutoff_date):
            current_date = start_date
            while tasks:
                if current_date > cutoff_date:
                    break
                while calculate_available_time(self.user, current_date) == 0:
                    current_date = next_day(current_date)
                    if current_date > cutoff_date:
                        break
                if current_date > cutoff_date:
                    break
                available = calculate_available_time(self.user, current_date)
                while tasks and available >= tasks[0][1]:
                    name, dur = tasks.pop(0)
                    self.add_task(name, current_date, dur)
                    available -= dur
                current_date = next_day(current_date)
            return current_date

        def year_tasks(y: int):
            return [
                (f"過去問 {y}年 (1/2)", 60),
                (f"過去問 {y}年 (2/2)", 60),
                (f"過去問 {y}年 レビュー", 60),
            ]

        for _round in range(3):
            if start_date > cutoff:
                break
            for y in YEARS:
                if start_date > cutoff:
                    break
                tasks = year_tasks(y)
                start_date = allocate_tasks_until(tasks, start_date, cutoff)
                if start_date > cutoff:
                    break
            if (not self.is_short) and (start_date <= cutoff):
                self.add_task("リフレッシュ日", start_date, 0)
                start_date = next_day(start_date)

        current_date = max(start_date, next_day(self.last_study_date))
        i = 1
        while current_date <= cutoff:
            if calculate_available_time(self.user, current_date) >= 60:
                self.add_task(f"過去問道場ランダム{i}", current_date, 60)
                i += 1
            current_date = next_day(current_date)

    def snapshot_raw_units(self) -> List[Dict[str, object]]:
        def _wbs_num(w: str) -> int:
            try:
                return int(str(w).replace("wbs", ""))
            except Exception:
                return 10**9
        items = []
        for t in sorted(self.tasks, key=lambda x: (x.Date, _wbs_num(x.WBS))):
            items.append({
                "WBS": t.WBS,
                "Task": t.Task_Name,
                "Date": t.Date.strftime("%Y-%m-%d"),
                "Day": t.Day,
                "Duration": t.Duration,
                "Status": t.Status,
                "meta": {
                    "round": ("3rd" if "(3rd)" in t.Task_Name else ("2nd" if "(2nd)" in t.Task_Name else "1st")),
                }
            })
        return items

    def step8_summarize_tasks(self):
        from collections import defaultdict
        grouped = defaultdict(list)
        for t in self.tasks:
            grouped[t.Date].append(t)

        new_tasks = []
        for date in sorted(grouped.keys()):
            tasks_for_day = grouped[date]
            normal = [t for t in tasks_for_day if "復習" not in t.Task_Name and "アプリ演習" not in t.Task_Name]
            review = [t for t in tasks_for_day if t not in normal]

            if len(normal) == 1:
                new_tasks.extend(normal)
            elif len(normal) > 1:
                first, last = normal[0], normal[-1]
                if "(2nd)" in first.Task_Name: lbl = "【2周】"
                elif "(3rd)" in first.Task_Name: lbl = "【3周】"
                elif "過去問" not in first.Task_Name and "レビュー" not in first.Task_Name: lbl = "【1周】"
                else: lbl = ""
                def clean(n): return n.replace("(2nd) ", "").replace("(3rd) ", "")
                combined = f"{lbl} {clean(first.Task_Name)} – {clean(last.Task_Name)}".strip()
                total = sum(t.Duration for t in normal)
                new_tasks.append(Task("", combined, date, total))
            new_tasks.extend(review)

        self.tasks = []
        for i, t in enumerate(sorted(new_tasks, key=lambda x: x.Date)):
            self.tasks.append(Task(f"wbs{i}", t.Task_Name, t.Date, t.Duration))

    def step9_merge_plan(self):
        self.plan_df = pd.DataFrame([{
            "WBS": t.WBS,
            "Task Name": t.Task_Name,
            "Date": t.Date.strftime('%Y-%m-%d'),
            "Day": t.Day,
            "Duration": t.Duration,
            "Status": t.Status
        } for t in self.tasks])
        self.plan_df.sort_values(by='Date', inplace=True)
        self.plan_df.reset_index(drop=True, inplace=True)
        self.plan_df['WBS'] = [f"wbs{i}" for i in range(len(self.plan_df))]

    def run_phase1(self):
        if not self.is_short:
            self.step0_setup()
        else:
            self.last_study_date = self.user.start_date - timedelta(days=1)
        self.step1_first_round()
        self.step3_first_exam()
        self.step2_second_round()
        self.step5_weekend_reviews()

    def run_phase2(self) -> List[Dict[str, object]]:
        if not self.is_short:
            self.step6_refresh_days()
        self.step7_past_exam_plan()
        raw_units = self.snapshot_raw_units()
        self.step8_summarize_tasks()
        self.step9_merge_plan()
        return raw_units


def generate_study_plan(data: dict, user_id: str) -> Tuple[pd.DataFrame, UserSetting, List[Dict[str, object]]]:
    user = UserSetting(
        user_id=user_id,
        target_exam=datetime.strptime(data["target_exam_date"], "%Y-%m-%d"),
        start_date=datetime.strptime(data["start_date"], "%Y-%m-%d"),
        weekday_minutes=int(data["weekday_minutes"]),
        weekend_minutes=int(data["weekend_minutes"]),
        rest_days=data.get("rest_days", ["Wed"]),
        weekday_start=data.get("weekday_start", "20:00"),
        weekend_start=data.get("weekend_start", "13:00"),
        book_keyword=data["book_keyword"],
    )
    try:
        chapter_items_list = _normalize_chapter_items(data, user.book_keyword)
    except Exception as e:
        raise ValueError(f"chapter items error: {e}")

    planner = StudyPlanner(user, chapter_items_list)
    planner.run_phase1()
    raw_units = planner.run_phase2()
    return planner.plan_df, user, raw_units


# ===== Raw Plan Units backup =====
def _raw_units_path(user_id: str, spreadsheet_id: str) -> str:
    return f"gpts-plans/{user_id}/raw/{spreadsheet_id}.json"

def save_raw_plan_units_to_gcs(user_id: str, spreadsheet_id: str, raw_units: List[Dict[str, object]]) -> str:
    bucket = gcs().bucket(BACKUP_BUCKET)
    path = _raw_units_path(user_id, spreadsheet_id)
    blob = bucket.blob(path)
    blob.upload_from_string(json.dumps(raw_units, ensure_ascii=False), content_type="application/json")
    return f"gs://{BACKUP_BUCKET}/{path}"

def load_raw_plan_units_from_gcs(user_id: str, spreadsheet_id: str) -> Optional[List[Dict[str, object]]]:
    bucket = gcs().bucket(BACKUP_BUCKET)
    path = _raw_units_path(user_id, spreadsheet_id)
    blob = bucket.blob(path)
    if not blob.exists():
        return None
    try:
        return json.loads(blob.download_as_text())
    except Exception:
        return None


# ===== URL-backup helpers =====
def _url_backup_object_name(user_id: str) -> str:
    return f"gpts-plans/{user_id}/history/url_backups.jsonl"

def append_url_backup(user_id: str, spreadsheet_id: str, spreadsheet_url: str, note: str = "") -> str:
    bucket = gcs().bucket(BACKUP_BUCKET)
    obj = _url_backup_object_name(user_id)
    blob = bucket.blob(obj)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    rec = json.dumps({
        "ts": ts,
        "user_id": user_id,
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": spreadsheet_url,
        "note": note
    }, ensure_ascii=False) + "\n"

    if blob.exists():
        tmp_name = f"{obj}.tmp.{ts}"
        tmp_blob = bucket.blob(tmp_name)
        tmp_blob.upload_from_string(rec, content_type="application/json")
        blob.compose([blob, tmp_blob])
        tmp_blob.delete()
    else:
        blob.upload_from_string(rec, content_type="application/json")
    return f"gs://{BACKUP_BUCKET}/{obj}"


# ===== Sheets I/O =====
def write_tasks_to_sheet(spreadsheet_id: str, plan_df: pd.DataFrame, user_id: Optional[str] = None) -> None:
    service = get_user_sheets_service(user_id) if user_id else None
    if service is None:
        raise PermissionError("No OAuth tokens. Authorize first.")
    service.spreadsheets().values().clear(
        spreadsheetId=spreadsheet_id,
        range="A:F"
    ).execute()
    service.spreadsheets().values().update(
        spreadsheetId=spreadsheet_id,
        range="A1",
        valueInputOption="RAW",
        body={"values": [list(plan_df.columns)]}
    ).execute()
    if not plan_df.empty:
        service.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id,
            range="A2",
            valueInputOption="RAW",
            body={"values": plan_df.values.tolist()}
        ).execute()

def create_sheet_and_write(plan_df: pd.DataFrame, sheet_title: str, user_id: str) -> str:
    svc = get_user_sheets_service(user_id)
    if svc is None:
        raise PermissionError("No OAuth tokens. Authorize first.")

    sheet = svc.spreadsheets().create(
        body={"properties": {"title": sheet_title}}, fields="spreadsheetId"
    ).execute()
    spreadsheet_id = sheet.get("spreadsheetId")

    svc.spreadsheets().values().update(
        spreadsheetId=spreadsheet_id, range="A1", valueInputOption="RAW",
        body={"values": [list(plan_df.columns)]}
    ).execute()
    if not plan_df.empty:
        svc.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id, range="A2", valueInputOption="RAW",
            body={"values": plan_df.values.tolist()}
        ).execute()

    meta2 = svc.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
    first_sheet_id = meta2["sheets"][0]["properties"]["sheetId"]

    # B列の列幅（失敗は警告だけ）
    try:
        svc.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={
                "requests": [{
                    "updateDimensionProperties": {
                        "range": {
                            "sheetId": first_sheet_id,
                            "dimension": "COLUMNS",
                            "startIndex": 1,   # B
                            "endIndex": 2
                        },
                        "properties": {"pixelSize": 210},
                        "fields": "pixelSize"
                    }
                }]
            }
        ).execute()
    except Exception as e:
        print("[warn] 列幅設定に失敗:", e)

    # F列(Status) の条件付き書式（失敗は警告だけ）
    try:
        requests = [
            {
                "addConditionalFormatRule": {
                    "rule": {
                        "ranges": [{
                            "sheetId": first_sheet_id,
                            "startRowIndex": 1,
                            "startColumnIndex": 5,  # F
                            "endColumnIndex": 6
                        }],
                        "booleanRule": {
                            "condition": {"type": "TEXT_EQ", "values": [{"userEnteredValue": "完了"}]},
                            "format": {"backgroundColor": {"red": 0.85, "green": 0.95, "blue": 0.85}}
                        }
                    },
                    "index": 0
                }
            },
            {
                "addConditionalFormatRule": {
                    "rule": {
                        "ranges": [{
                            "sheetId": first_sheet_id,
                            "startRowIndex": 1,
                            "startColumnIndex": 5,
                            "endColumnIndex": 6
                        }],
                        "booleanRule": {
                            "condition": {
                                "type": "CUSTOM_FORMULA",
                                "values": [{"userEnteredValue": '=AND($F2<>"", $F2<>"完了")'}]
                            },
                            "format": {"backgroundColor": {"red": 1.0, "green": 1.0, "blue": 0.85}}
                        }
                    },
                    "index": 0
                }
            }
        ]
        svc.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body={"requests": requests}).execute()
    except Exception as e:
        print("[warn] 条件付き書式の設定に失敗:", e)

    return spreadsheet_id


def generate_sheet_title(user: UserSetting) -> str:
    return f"user_{user.user_id}_plan_{user.start_date.strftime('%Y%m%d')}"


# ===== Mapping (user -> active sheet) =====
def load_user_sheet_map() -> Dict[str, Dict[str, str]]:
    # mapping.json はバケット直下（固定）
    return _gcs_get_json_or_default(USER_SHEET_MAP_BUCKET, USER_SHEET_MAP_BLOB, {})

def save_user_sheet_map(mapping: Dict[str, Dict[str, str]]) -> None:
    bucket = gcs().bucket(USER_SHEET_MAP_BUCKET)
    blob = bucket.blob(USER_SHEET_MAP_BLOB)
    blob.upload_from_string(json.dumps(mapping, ensure_ascii=False), content_type="application/json")

def get_user_spreadsheet_id(user_id: str) -> Optional[str]:
    return (load_user_sheet_map().get(user_id) or {}).get("spreadsheet_id")


# ===== Endpoints: Health/OAuth =====
@app.get("/")
def root():
    return {"ok": True}

@app.get("/health")
def health():
    return {"ok": True, "env_ready": required_envs_ok(), "exam_type": EXAM_TYPE}

@app.get("/oauth/start")
def oauth_start(user_id: Optional[str] = None):
    if not required_envs_ok():
        return JSONResponse({"error": "OAuth env not set"}, status_code=500)
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)
    flow = build_flow()
    state = signed_state(user_id)
    save_oauth_state(state, {"user_id": user_id})
    auth_url, _ = flow.authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent", state=state
    )
    return RedirectResponse(auth_url, status_code=302)

@app.get("/oauth/callback")
def oauth_callback(request: Request):
    if not required_envs_ok():
        return HTMLResponse("<h3>OAuth env not set</h3>", status_code=500)

    state = request.query_params.get("state", "")
    st = pop_oauth_state(state)
    user_id = (st or {}).get("user_id") or verify_state(state) or ""
    if not user_id:
        return HTMLResponse("<h3>Invalid state</h3>", status_code=400)

    code = request.query_params.get("code")
    if not code:
        return HTMLResponse("<h3>Missing code</h3>", status_code=400)

    try:
        flow = build_flow()
        flow.fetch_token(code=code)
        creds = flow.credentials
        rt = getattr(creds, "refresh_token", None)
        if not rt:
            existing = load_refresh_token(user_id)
            if not existing:
                return HTMLResponse("<h3>⚠️ refresh_token が取得できませんでした。もう一度お試しください。</h3>", status_code=400)
            return HTMLResponse("<h3>✅ 連携済みです。チャットに戻って再実行してください。</h3>")
        save_refresh_token(user_id, rt)
        return HTMLResponse("<h3>✅ 連携が完了しました。チャットに戻って再実行してください。</h3>")
    except Exception as e:
        return HTMLResponse(f"<h3>OAuth error: {e}</h3>", status_code=400)

@app.get("/auth/status")
def auth_status(user_id: Optional[str] = None):
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)
    ok = bool(_get_creds_cached(user_id))
    return {"user_id": user_id, "authorized": ok}


# ===== Endpoints: Plan Generate / Read / Mutations =====
@app.post("/generate", dependencies=[Depends(verify_api_key)])
def generate_plan(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    # 認可チェック（未連携なら authorize_url を返す）
    if not load_user_credentials(user_id):
        if not required_envs_ok():
            return JSONResponse({"error": "OAuth not configured on server"}, status_code=500)
        flow = build_flow()
        state = signed_state(user_id)
        save_oauth_state(state, {"user_id": user_id})
        auth_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            state=state
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Please authorize via the URL, then retry."
        }, status_code=200)

    # 生成 → Sheets 書き込み
    try:
        plan_df, user, raw_units = generate_study_plan(payload, user_id)
    except Exception as e:
        return JSONResponse({"error": f"plan generation failed: {e}"}, status_code=400)

    try:
        spreadsheet_id = create_sheet_and_write(plan_df, generate_sheet_title(user), user_id)
    except PermissionError:
        flow = build_flow()
        state = signed_state(user_id)
        save_oauth_state(state, {"user_id": user_id})
        auth_url, _ = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent", state=state
        )
        return JSONResponse({
            "requires_auth": True,
            "authorize_url": auth_url,
            "message": "Authorization expired. Please re-authorize."
        }, status_code=200)
    except Exception as e:
        return JSONResponse({"error": f"Sheets error: {e}"}, status_code=500)

    try:
        raw_uri = save_raw_plan_units_to_gcs(user.user_id, spreadsheet_id, raw_units)
    except Exception as e:
        print("[warn] save raw units failed:", e)
        raw_uri = None

    spreadsheet_url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}"

    # マッピング保存
    try:
        mapping = load_user_sheet_map()
        mapping[user_id] = {"spreadsheet_id": spreadsheet_id, "spreadsheet_url": spreadsheet_url}
        save_user_sheet_map(mapping)
    except Exception as e:
        print("[warn] save mapping failed:", e)

    return {
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": spreadsheet_url,
        "raw_backup_uri": raw_uri,
    }

@app.post("/get_tasks", dependencies=[Depends(verify_api_key)])
def get_tasks(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)

    svc = get_user_sheets_service(user_id)
    if svc is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    try:
        meta = svc.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        sheet_title = meta["sheets"][0]["properties"]["title"]
        res = svc.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=f"{sheet_title}!A1:F10000"
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read sheet: {e}"}, status_code=500)

    values = res.get("values", [])
    if not values or len(values) < 2:
        return {"tasks": []}

    headers = values[0]
    rows = values[1:]
    tasks = [
        {headers[i]: (row[i] if i < len(row) else "") for i in range(len(headers))}
        for row in rows
        if any((c or "").strip() for c in row)
    ]
    return {"tasks": tasks}

@app.post("/update_task", dependencies=[Depends(verify_api_key)])
def update_task(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    wbs_id = (payload.get("wbs_id") or "").strip()
    if not user_id or not wbs_id:
        return JSONResponse({"error": "user_id and wbs_id are required"}, status_code=400)

    updates = payload.get("updates")
    if not updates:
        field = (payload.get("field") or "").strip()
        value = payload.get("value", "")
        if not field:
            return JSONResponse({"error": "Specify 'updates' or ('field' and 'value')"}, status_code=400)
        updates = {field: value}

    if "wbs" in [k.strip().lower() for k in updates.keys()]:
        return JSONResponse({"error": "Updating WBS is not allowed."}, status_code=400)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)
    svc = get_user_sheets_service(user_id)
    if svc is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    try:
        meta = svc.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        sheet_title = meta["sheets"][0]["properties"]["title"]
    except Exception as e:
        return JSONResponse({"error": f"Failed to fetch sheet metadata: {e}"}, status_code=500)

    normalized_updates = {}
    for k, v in updates.items():
        key_norm = (k or "").strip().lower()
        if key_norm not in FIELD_TO_COL:
            return JSONResponse(
                {"error": f"Unknown field '{k}'. Allowed: {list(FIELD_TO_COL.keys())}"},
                status_code=400
            )
        normalized_updates[key_norm] = v

    try:
        rng_a = f"{sheet_title}!A2:A10000"
        got = svc.spreadsheets().values().get(spreadsheetId=spreadsheet_id, range=rng_a).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read WBS column: {e}"}, status_code=500)

    values = got.get("values", [])
    row_index = None
    for i, row in enumerate(values):
        cell = (row[0] if row else "").strip()
        if cell == wbs_id:
            row_index = i + 2
            break
    if not row_index:
        return JSONResponse({"error": f"WBS ID '{wbs_id}' not found"}, status_code=404)

    data_updates = []
    for field_lc, new_val in normalized_updates.items():
        col = FIELD_TO_COL[field_lc]
        a1 = f"{sheet_title}!{col}{row_index}"
        data_updates.append({"range": a1, "values": [[new_val]]})

    try:
        svc.spreadsheets().values().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={"valueInputOption": "RAW", "data": data_updates}
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Update failed: {e}"}, status_code=500)

    return {"message": "Task updated", "row": row_index, "updated_fields": list(normalized_updates.keys())}

@app.post("/insert_task", dependencies=[Depends(verify_api_key)])
def insert_task(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    task_in = (payload.get("task") or {})
    order = (payload.get("order") or "asc").lower()
    if not user_id or not task_in:
        return JSONResponse({"error": "user_id and task are required"}, status_code=400)

    task_txt = (task_in.get("task") or "").strip()
    date_str = (task_in.get("date") or "").strip()
    day_str  = (task_in.get("day")  or "").strip()
    duration_raw = task_in.get("duration", "")
    status   = (task_in.get("status") or "未着手").strip()

    ins_date = parse_ymd(date_str)
    if not ins_date:
        return JSONResponse({"error": "task.date must be 'YYYY-MM-DD'"}, status_code=400)
    if not day_str:
        day_str = DAY_ABBR[ins_date.weekday()]
    try:
        duration_val = int(str(duration_raw))
    except Exception:
        duration_val = 60

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)
    service = get_user_sheets_service(user_id)
    if service is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)
    try:
        meta = service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        sheet = meta["sheets"][0]
        sheet_id = sheet["properties"]["sheetId"]
        sheet_title = sheet["properties"]["title"]
    except Exception as e:
        return JSONResponse({"error": f"Failed to fetch sheet metadata: {e}"}, status_code=500)

    rng_c_all = f"{sheet_title}!C2:C10000"
    try:
        res = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=rng_c_all
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read existing rows: {e}"}, status_code=500)
    rows = res.get("values", [])

    insert_row_1based = 2 + len(rows)
    if order == "asc":
        for i, r in enumerate(rows):
            r_date = parse_ymd((r[0] if r else "").strip())
            if r_date and ins_date < r_date:
                insert_row_1based = 2 + i
                break

    start_idx0 = insert_row_1based - 1
    end_idx0 = start_idx0 + 1
    try:
        service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={
                "requests": [{
                    "insertDimension": {
                        "range": {"sheetId": sheet_id, "dimension": "ROWS", "startIndex": start_idx0, "endIndex": end_idx0},
                        "inheritFromBefore": True
                    }
                }]
            }
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Insert row failed: {e}"}, status_code=500)

    try:
        service.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id,
            range=f"{sheet_title}!B{insert_row_1based}:F{insert_row_1based}",
            valueInputOption="RAW",
            body={"values": [[task_txt, date_str, day_str, str(duration_val), status]]}
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Write values failed: {e}"}, status_code=500)

    try:
        resA = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=f"{sheet_title}!A2:A10000"
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read WBS column: {e}"}, status_code=500)
    a_vals = resA.get("values", [])

    def _wbs_start(a_first: str) -> int:
        try:
            return int((a_first or "").lower().replace("wbs", "").strip())
        except Exception:
            return 0

    start_num = _wbs_start((a_vals[0][0] if a_vals and a_vals[0] else "").strip()) if a_vals else 0
    new_wbs_col = [[f"wbs{start_num + i}"] for i in range(len(a_vals))]
    if new_wbs_col:
        try:
            service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_title}!A2:A{len(new_wbs_col)+1}",
                valueInputOption="RAW",
                body={"values": new_wbs_col}
            ).execute()
        except Exception as e:
            return JSONResponse({"error": f"Renumber WBS failed: {e}"}, status_code=500)

    inserted_wbs = f"wbs{start_num + (insert_row_1based - 2)}"
    return {"message": "Task inserted", "inserted_row": insert_row_1based, "wbs": inserted_wbs}

@app.post("/delete_task", dependencies=[Depends(verify_api_key)])
def delete_task(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    wbs_id = (payload.get("wbs_id") or "").strip()
    if not user_id or not wbs_id:
        return JSONResponse({"error": "user_id and wbs_id are required"}, status_code=400)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)
    service = get_user_sheets_service(user_id)
    if service is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    try:
        meta = service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        sheet = meta["sheets"][0]
        sheet_id = sheet["properties"]["sheetId"]
        sheet_title = sheet["properties"]["title"]
    except Exception as e:
        return JSONResponse({"error": f"Failed to fetch sheet metadata: {e}"}, status_code=500)

    rng = f"{sheet_title}!A2:A10000"
    try:
        result = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=rng
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read values: {e}"}, status_code=500)

    values = result.get("values", [])
    target_row_index_1based = None
    for i, row in enumerate(values):
        a = (row[0] if row else "").strip()
        if a == wbs_id:
            target_row_index_1based = i + 2
            break
    if not target_row_index_1based:
        return JSONResponse({"error": "WBS ID not found"}, status_code=404)

    start_index_0based = target_row_index_1based - 1
    end_index_0based = target_row_index_1based
    try:
        service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={
                "requests": [{
                    "deleteDimension": {
                        "range": {"sheetId": sheet_id, "dimension": "ROWS", "startIndex": start_index_0based, "endIndex": end_index_0based}
                    }
                }]
            }
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Delete failed: {e}"}, status_code=500)

    try:
        result2 = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=rng
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Failed to re-read values: {e}"}, status_code=500)

    a_values = result2.get("values", [])
    if not a_values:
        return {"message": "Task deleted (row removed). No remaining tasks to renumber.", "deleted_row": target_row_index_1based}

    def _safe_int_from_wbs(w: str):
        try:
            return int((w or "").lower().replace("wbs", "").strip())
        except Exception:
            return None

    first = (a_values[0][0] or "").strip()
    start_num = _safe_int_from_wbs(first)
    if start_num is None:
        start_num = 0

    new_wbs_col = [[f"wbs{start_num + i}"] for i in range(len(a_values))]
    try:
        service.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id,
            range=f"{sheet_title}!A2:A{len(new_wbs_col)+1}",
            valueInputOption="RAW",
            body={"values": new_wbs_col}
        ).execute()
    except Exception as e:
        return JSONResponse({"error": f"Renumber failed: {e}"}, status_code=500)

    return {
        "message": "Task deleted (row removed) and WBS renumbered",
        "deleted_row": target_row_index_1based,
        "renumber": {"start": start_num, "count": len(new_wbs_col)}
    }


# ===== Day-off (再配分) =====
def _parse_date(s: str):
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None

def _wbs_num(w: str) -> int:
    try:
        return int(str(w).replace("wbs", "").strip())
    except Exception:
        return 10**9

def _is_review_task(name: str) -> bool:
    n = name or ""
    return ("復習" in n) or ("アプリ演習" in n)

def _capacity_for_date(d: datetime.date, weekday_minutes: int, weekend_minutes: int,
                       rest_days: List[str], off_date: datetime.date,
                       repeat_weekday: bool) -> int:
    if d == off_date:
        return 0
    abbr = DAY_ABBR[d.weekday()]
    if abbr in set(rest_days):
        return 0
    if repeat_weekday and d.weekday() == off_date.weekday():
        return 0
    return weekend_minutes if d.weekday() >= 5 else weekday_minutes

def _redistribute_units_after_day_off(
    raw_units: List[Dict[str, object]],
    off_date: datetime.date,
    weekday_minutes: int,
    weekend_minutes: int,
    rest_days: List[str],
    repeat_weekday: bool = False
) -> List[Dict[str, object]]:
    def u_date(u):
        return _parse_date(str(u.get("Date", "")).strip())

    def key(u):
        return (u_date(u) or datetime(1970,1,1).date(), _wbs_num(str(u.get("WBS","wbs999999"))))

    before = [u for u in raw_units if (u_date(u) and u_date(u) < off_date)]
    tail   = [u for u in raw_units if (u_date(u) and u_date(u) >= off_date)]
    tail.sort(key=key)

    cur = off_date
    i = 0
    reassigned = []
    while i < len(tail):
        cap = _capacity_for_date(cur, weekday_minutes, weekend_minutes, rest_days, off_date, repeat_weekday)
        if cap <= 0:
            cur = cur + timedelta(days=1)
            continue

        used = 0
        while i < len(tail):
            try:
                dur = int(tail[i].get("Duration", 0))
            except Exception:
                dur = 0
            if dur <= 0:
                u = tail[i].copy()
                u["Date"] = cur.isoformat()
                reassigned.append(u)
                i += 1
                continue

            if used + dur <= cap:
                u = tail[i].copy()
                u["Date"] = cur.isoformat()
                reassigned.append(u)
                used += dur
                i += 1
            else:
                break
        cur = cur + timedelta(days=1)

    return before + reassigned

def _summarize_units_to_plan_df(units: List[Dict[str, object]]) -> pd.DataFrame:
    from collections import defaultdict

    class _T:
        __slots__ = ("WBS","Task_Name","Date","Duration","Status")
        def __init__(self, WBS, name, date_str, dur, status):
            self.WBS = WBS
            self.Task_Name = name
            self.Date = datetime.strptime(date_str, "%Y-%m-%d")
            self.Duration = int(dur) if str(dur).isdigit() else 0
            self.Status = status or "未着手"
        @property
        def Day(self):
            return DAY_ABBR[self.Date.weekday()]

    tasks = []
    for u in units:
        tasks.append(_T(
            u.get("WBS",""),
            u.get("Task",""),
            str(u.get("Date","")).strip(),
            u.get("Duration",0),
            u.get("Status","未着手"),
        ))

    grouped = defaultdict(list)
    for t in tasks:
        grouped[t.Date.date()].append(t)

    new_tasks = []
    for date in sorted(grouped.keys()):
        day_tasks = grouped[date]
        normal = [t for t in day_tasks if not _is_review_task(t.Task_Name)]
        review = [t for t in day_tasks if t not in normal]

        if len(normal) == 1:
            new_tasks.extend(normal)
        elif len(normal) > 1:
            first, last = normal[0], normal[-1]
            if "(2nd)" in first.Task_Name: lbl = "【2周】"
            elif "(3rd)" in first.Task_Name: lbl = "【3周】"
            elif "過去問" not in first.Task_Name and "レビュー" not in first.Task_Name: lbl = "【1周】"
            else: lbl = ""
            def clean(n): return n.replace("(2nd) ", "").replace("(3rd) ", "")
            combined = f"{lbl} {clean(first.Task_Name)} – {clean(last.Task_Name)}".strip()
            total = sum(t.Duration for t in normal)
            new_tasks.append(_T("", combined, date.isoformat(), total, "未着手"))
        new_tasks.extend(review)

    plan_df = pd.DataFrame([{
        "WBS": "",
        "Task Name": t.Task_Name,
        "Date": t.Date.strftime('%Y-%m-%d'),
        "Day": t.Day,
        "Duration": t.Duration,
        "Status": t.Status
    } for t in sorted(new_tasks, key=lambda x: x.Date)])
    if plan_df.empty:
        plan_df = pd.DataFrame(columns=["WBS","Task Name","Date","Day","Duration","Status"])
    else:
        plan_df.reset_index(drop=True, inplace=True)
        plan_df["WBS"] = [f"wbs{i}" for i in range(len(plan_df))]
    return plan_df

@app.post("/day_off", dependencies=[Depends(verify_api_key)])
def day_off(payload: dict = Body(...)):
    user_id = (payload.get("user_id") or "").strip()
    off_date_str = (payload.get("off_date") or "").strip()
    if not user_id or not off_date_str:
        return JSONResponse({"error": "user_id and off_date are required"}, status_code=400)

    weekday_minutes = int(payload.get("weekday_minutes", 60))
    weekend_minutes = int(payload.get("weekend_minutes", 120))
    rest_days = payload.get("rest_days") or []
    repeat_weekday = bool(payload.get("repeat_weekday", False))

    d0 = _parse_date(off_date_str)
    if not d0:
        return JSONResponse({"error": "off_date must be 'YYYY-MM-DD'"}, status_code=400)

    spreadsheet_id = get_user_spreadsheet_id(user_id)
    if not spreadsheet_id:
        return JSONResponse({"error": "spreadsheet not found"}, status_code=404)
    svc = get_user_sheets_service(user_id)
    if svc is None:
        return JSONResponse({"error": "Authorization required"}, status_code=401)

    raw_units = load_raw_plan_units_from_gcs(user_id, spreadsheet_id)
    if not raw_units:
        return JSONResponse(
            {"error": "raw units not found. Please /regenerate or /generate to create raw backup first."},
            status_code=409
        )

    new_units = _redistribute_units_after_day_off(
        raw_units=raw_units,
        off_date=d0,
        weekday_minutes=weekday_minutes,
        weekend_minutes=weekend_minutes,
        rest_days=rest_days,
        repeat_weekday=repeat_weekday
    )

    plan_df = _summarize_units_to_plan_df(new_units)

    try:
        write_tasks_to_sheet(spreadsheet_id, plan_df, user_id)
    except Exception as e:
        return JSONResponse({"error": f"Sheets error: {e}"}, status_code=500)

    try:
        raw_backup_uri = save_raw_plan_units_to_gcs(user_id, spreadsheet_id, new_units)
    except Exception as e:
        print("[warn] save raw units failed:", e)
        raw_backup_uri = None

    def minutes(xs):
        s = 0
        for u in xs:
            try:
                s += int(u.get("Duration", 0))
            except Exception:
                pass
        return s

    moved = [u for u in raw_units if _parse_date(u.get("Date","")) >= d0]
    return {
        "ok": True,
        "spreadsheet_id": spreadsheet_id,
        "raw_backup_uri": raw_backup_uri,
        "off_date": off_date_str,
        "repeat_weekday": repeat_weekday,
        "moved_units_count": len(moved),
        "moved_minutes_total": minutes(moved),
        "preview_head": plan_df.head(10).to_dict(orient="records")
    }


# ===== Acronyms =====
def _ac_load_from_gcs(force: bool = False):
    now = time.time()
    if not force and (now - _AC_CACHE["last"] < ACRONYM_REFRESH_SEC) and _AC_CACHE["terms"]:
        return

    blob = gcs().bucket(ACRONYM_BUCKET).blob(ACRONYM_PATH)
    try:
        blob.reload()
    except Exception:
        _AC_CACHE.update({"terms": {}, "last": now, "etag": None})
        return

    etag = getattr(blob, "etag", None)
    if not force and _AC_CACHE["etag"] and etag == _AC_CACHE["etag"]:
        _AC_CACHE["last"] = now
        return

    data = blob.download_as_text()
    obj = json.loads(data)  # { "DNS": {...}, ... }
    terms = {}
    for k, card in obj.items():
        key = (k or "").upper()
        if key:
            terms[key] = card
    _AC_CACHE.update({"terms": terms, "last": now, "etag": etag})

def _ac_get(term: str):
    _ac_load_from_gcs()
    return _AC_CACHE["terms"].get((term or "").upper())

@app.get("/acronyms/session", dependencies=[Depends(verify_api_key)],
         response_model=AcronymCardsResponseModel)
def get_acronym_session(count: int = 10, shuffle: bool = True):
    if count < 1:
        count = 1
    if count > 30:
        count = 30
    _ac_load_from_gcs()
    items = list(_AC_CACHE["terms"].values())
    if shuffle:
        random.shuffle(items)
    picked = items[:count]
    return {"cards": picked, "count": len(picked), "etag": _AC_CACHE["etag"]}

@app.post("/acronyms/batch", dependencies=[Depends(verify_api_key)],
          response_model=AcronymCardsResponseModel)
def get_acronym_batch(payload: dict = Body(...)):
    terms = payload.get("terms") or []
    if not isinstance(terms, list):
        return JSONResponse({"error": "terms must be an array"}, status_code=400)
    _ac_load_from_gcs()
    out = []
    for t in terms:
        c = _AC_CACHE["terms"].get((t or "").upper())
        if c:
            out.append(c)
    return {"cards": out, "count": len(out), "etag": _AC_CACHE["etag"]}

@app.get("/acronyms/term/{term}",
         dependencies=[Depends(verify_api_key)],
         response_model=AcronymCardModel)
def get_acronym_card(term: str):
    card = _ac_get(term)
    if not card:
        raise HTTPException(status_code=404, detail="Term not found")
    resp = JSONResponse(card)
    resp.headers["Cache-Control"] = "public, max-age=3600"
    if _AC_CACHE["etag"]:
        resp.headers["ETag"] = _AC_CACHE["etag"]
    return resp

@app.get("/acronyms/{term}", include_in_schema=False,
         dependencies=[Depends(verify_api_key)])
def acronyms_compat(term: str):
    if term in {"session", "batch", "term"}:
        raise HTTPException(status_code=404, detail="Not Found")
    return RedirectResponse(url=f"/acronyms/term/{term}", status_code=307)


# ===== Books Register (GCSに章データ保存) =====
@app.post("/books/register", dependencies=[Depends(verify_api_key)])
def register_book_chapters(payload: dict = Body(...)):
    book_keyword = (payload.get("book_keyword") or "").strip()
    if not book_keyword:
        return JSONResponse({"error": "book_keyword is required"}, status_code=400)

    try:
        items = _normalize_chapter_items(payload, book_keyword)
    except Exception as e:
        return JSONResponse({"error": f"chapter items error: {e}"}, status_code=400)

    overwrite = bool(payload.get("overwrite", False))
    bucket = gcs().bucket(BOOK_DATA_BUCKET)
    save_path = f"{BOOK_DATA_PREFIX.strip('/')}/{book_keyword}.json".strip("/")
    blob = bucket.blob(save_path or f"{book_keyword}.json")

    if blob.exists() and not overwrite:
        return JSONResponse({"error": "already exists. set overwrite=true to replace."}, status_code=409)

    try:
        blob.upload_from_string(json.dumps(items, ensure_ascii=False), content_type="application/json")
    except Exception as e:
        return JSONResponse({"error": f"save failed: {e}"}, status_code=500)

    return {"ok": True, "book_keyword": book_keyword, "gcs_uri": f"gs://{BOOK_DATA_BUCKET}/{save_path}", "count": len(items)}
