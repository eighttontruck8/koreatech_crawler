import re
import time
from dataclasses import dataclass
from datetime import datetime

import requests
import pandas as pd
from bs4 import BeautifulSoup
from dateutil import parser as dtparser


# ======================
# 설정
# ======================
LIST_URL = "https://portal.koreatech.ac.kr/ctt/bb/bulletin?b=14&ls=20&ln={page}&dm=l"
DETAIL_URL = "https://portal.koreatech.ac.kr/ctt/bb/bulletin?b=14&ls=20&ln=1&dm=r&p={post_id}"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
    ),
    "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
}

REQUEST_DELAY_SEC = 0.4  # 너무 빠르게 긁지 말기


# ======================
# 필터 기준
# ======================
@dataclass
class Criteria:
    # 결격(초과학기/휴학생/국가근로 등) 명시되면 제외
    # 단, "가능" 문맥이면 제외하지 않음. 애매하면 UNKNOWN/NO_CONDITION.
    exclude_if_disqualified: bool = True

    # 등록일 기준 필터
    posted_at_after: datetime | None = None   # inclusive lower bound
    posted_at_before: datetime | None = None  # exclusive upper bound

    # 마감일 기준 필터(원하면)
    deadline_after: datetime | None = None


# ✅ 기본: 2025년만
CRITERIA = Criteria(
    exclude_if_disqualified=True,
    posted_at_after=datetime(2025, 1, 1),
    posted_at_before=datetime(2026, 1, 1),
    deadline_after=None
)


# ======================
# 텍스트 정규화
# ======================
def norm(s: str) -> str:
    s = s.replace("\u3000", " ")
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


# ======================
# (핵심) 오탐 방지용: 가능/불가 문맥 판정
# ======================
RE_NEG = re.compile(r"(불가|제외|금지|제한|신청\s*불가|지원\s*불가|대상\s*아님|해당\s*없음|중복\s*불가)")
RE_POS = re.compile(r"(가능|허용|무관|상관\s*없|제한\s*없|포함|신청\s*가능|지원\s*가능)")

KW_OVERS = re.compile(r"(초과\s*학기(생)?|초과등록|초과수학)")
KW_LEAVE = re.compile(r"(휴학\s*생|휴학생)")
KW_GRAD = re.compile(r"(졸업\s*생|졸업생|수료생)")

KW_NATIONAL = re.compile(r"(국가\s*근로)")
KW_SEMESTER_WORK = re.compile(r"(학기\s*근로(생)?)")
KW_NIGHT_PATROL = re.compile(r"(야간\s*순찰)")
KW_MAX_40H = re.compile(r"(40\s*h|40시간|주\s*40\s*시간|최대\s*시간).{0,10}(초과)")
KW_TIMETABLE_CONFLICT = re.compile(r"(수강\s*시간표|수업\s*시간|시간표).{0,30}(중복|겹|충돌)|중복\s*불가.*\(온라인포함\)")

DISQUALIFY_KEYWORDS = {
    "초과학기": KW_OVERS,
    "휴학생": KW_LEAVE,
    "졸업/수료": KW_GRAD,
    "국가근로": KW_NATIONAL,
    "학기근로": KW_SEMESTER_WORK,
    "야간순찰": KW_NIGHT_PATROL,
    "최대시간40h": KW_MAX_40H,
    "시간표중복": KW_TIMETABLE_CONFLICT,
}

RE_NOTICE_BLOCK = re.compile(
    r"(※\s*유의사항|유의사항|지원대상|신청\s*자격|제한사항|불가\s*대상)\s*[:：]?\s*(.+)",
    re.IGNORECASE | re.DOTALL
)

def extract_notice_block(text: str) -> str:
    m = RE_NOTICE_BLOCK.search(text)
    if not m:
        # 못 찾으면 전체 검사(보수적)
        return text
    # 너무 길어도 오탐/성능 이슈라 일부만
    return m.group(0)[:2500]

def window_around(text: str, match: re.Match, radius: int = 55) -> str:
    s = match.start()
    e = match.end()
    return text[max(0, s - radius): min(len(text), e + radius)]

def classify_keyword(text: str, kw_pat: re.Pattern) -> bool | None:
    """
    return:
      True  = '불가/제외' 쪽으로 확실
      False = '가능/허용' 쪽으로 확실
      None  = 애매(UNKNOWN)
    """
    t = norm(text)
    matches = list(kw_pat.finditer(t))
    if not matches:
        return None

    saw_neg = False
    saw_pos = False

    for m in matches:
        w = window_around(t, m, radius=55)
        if RE_NEG.search(w):
            saw_neg = True
        if RE_POS.search(w):
            saw_pos = True

    if saw_pos and not saw_neg:
        return False
    if saw_neg and not saw_pos:
        return True
    return None

def disqualify_status(body_text: str) -> tuple[str, list[str]]:
    """
    returns:
      status: "PASS" | "BLOCK" | "UNKNOWN" | "NO_CONDITION"
      reasons: 매칭된 키워드 리스트
    """
    block = extract_notice_block(body_text)
    t = norm(block)

    reasons_block: list[str] = []
    reasons_unknown: list[str] = []
    any_keyword_seen = False

    for name, pat in DISQUALIFY_KEYWORDS.items():
        if pat.search(t):
            any_keyword_seen = True

        res = classify_keyword(block, pat)
        if res is True:
            reasons_block.append(name)
        elif res is None and pat.search(t):
            reasons_unknown.append(name)

    if reasons_block:
        return "BLOCK", reasons_block
    if reasons_unknown:
        return "UNKNOWN", reasons_unknown
    if not any_keyword_seen:
        return "NO_CONDITION", []
    return "PASS", []


# ======================
# 마감일 추출
# ======================
RE_DEADLINE = re.compile(
    r"(마감|접수|신청|모집)\s*(기간|일시|까지)?\s*[:\-]?\s*"
    r"(?P<date>"
    r"\d{4}[-./]\d{1,2}[-./]\d{1,2}(?:\s*\(?[월화수목금토일]\)?\s*)?(?:\s*\d{1,2}:\d{2})?"
    r"|"
    r"\d{1,2}[-./]\d{1,2}(?:\s*\(?[월화수목금토일]\)?\s*)?(?:\s*\d{1,2}:\d{2})?"
    r")"
)

def extract_deadline(text: str, default_year: int | None = None) -> datetime | None:
    m = RE_DEADLINE.search(text)
    if not m:
        return None

    raw = m.group("date").strip().replace(".", "-").replace("/", "-")
    if default_year and re.match(r"^\d{1,2}-\d{1,2}", raw) and not re.match(r"^\d{4}-", raw):
        raw = f"{default_year}-{raw}"
    try:
        return dtparser.parse(raw, fuzzy=True)
    except Exception:
        return None


# ======================
# 크롤링: 목록 파싱
# ======================
def fetch(session: requests.Session, url: str) -> str:
    r = session.get(url, headers=HEADERS, timeout=20)
    r.raise_for_status()
    return r.text

def parse_list(html: str) -> list[dict]:
    soup = BeautifulSoup(html, "lxml")
    items: list[dict] = []

    # 1) 테이블 기반 파싱 시도
    rows = soup.select("table tbody tr")
    if rows:
        for tr in rows:
            tds = tr.find_all("td")
            if len(tds) < 6:
                continue

            post_id = tds[0].get_text(strip=True)
            category = tds[1].get_text(strip=True)
            title = tds[2].get_text(" ", strip=True)
            posted_at = tds[3].get_text(strip=True)
            writer = tds[4].get_text(strip=True)

            if not post_id.isdigit():
                continue

            # 분류에 "근로"가 들어간 것만
            if "근로" not in category:
                continue

            link = DETAIL_URL.format(post_id=post_id)
            items.append({
                "post_id": post_id,
                "category": category,
                "title": title,
                "posted_at": posted_at,
                "writer": writer,
                "link": link,
            })

        if items:
            return items

    # 2) fallback: 텍스트에서 파싱
    text = soup.get_text("\n", strip=True)
    pattern = re.compile(
        r"(?m)^(?P<id>\d{5,})\s+(?P<cat>[^\n]+?)\s*\n(?P<title>[^\n]+?)\s*\n(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<writer>[^\s]+)"
    )

    for m in pattern.finditer(text):
        post_id = m.group("id")
        category = m.group("cat").strip()
        title = m.group("title").strip()
        posted_at = m.group("date").strip()
        writer = m.group("writer").strip()

        if "근로" not in category and "근로" not in title:
            continue

        link = DETAIL_URL.format(post_id=post_id)
        items.append({
            "post_id": post_id,
            "category": category,
            "title": title,
            "posted_at": posted_at,
            "writer": writer,
            "link": link,
        })

    uniq = {it["post_id"]: it for it in items}
    return list(uniq.values())


# ======================
# 상세 본문 텍스트 얻기
# ======================
def parse_detail_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")

    candidates = [
        ".bbs_view", ".board-view", ".view", ".content", "#content", ".article", ".cont"
    ]
    for sel in candidates:
        el = soup.select_one(sel)
        if el and el.get_text(strip=True):
            return el.get_text("\n", strip=True)

    return soup.get_text("\n", strip=True)


# ======================
# 필터 적용
# ======================
def passes(item: dict, body_text: str) -> tuple[bool, dict]:
    info: dict = {}

    # (1) 결격/UNKNOWN 판정
    status, reasons = disqualify_status(body_text)
    info["dq_status"] = status
    info["dq_reasons"] = reasons

    if CRITERIA.exclude_if_disqualified and status == "BLOCK":
        return False, info

    # (2) 등록일 필터
    posted_dt = None
    try:
        posted_dt = dtparser.parse(item["posted_at"])
        info["posted_dt"] = posted_dt
    except Exception:
        info["posted_dt"] = None

    if CRITERIA.posted_at_after and posted_dt:
        if posted_dt < CRITERIA.posted_at_after:
            return False, info

    if CRITERIA.posted_at_before and posted_dt:
        if posted_dt >= CRITERIA.posted_at_before:
            return False, info

    # (3) 마감일 필터(원하면)
    dl = extract_deadline(body_text, default_year=datetime.now().year)
    info["deadline"] = dl
    if CRITERIA.deadline_after and dl:
        if dl < CRITERIA.deadline_after:
            return False, info

    return True, info


# ======================
# 메인 크롤러
# ======================
def crawl(
    max_pages: int = 500,
    max_items: int = 5000,
    debug: bool = False,
    empty_page_stop: int = 10,  # 연속으로 "근로 글이 0개인 페이지"가 N번이면 종료
) -> pd.DataFrame:
    session = requests.Session()

    out: list[dict] = []
    seen: set[str] = set()
    empty_streak = 0

    for page in range(1, max_pages + 1):
        html = fetch(session, LIST_URL.format(page=page))
        items = parse_list(html)

        # 근로 글이 없는 페이지가 연속으로 너무 많으면 종료(사이트 끝/구간)
        if not items:
            empty_streak += 1
            if empty_streak >= empty_page_stop:
                if debug:
                    print(f"[STOP] empty pages streak reached {empty_page_stop}")
                break
            continue
        else:
            empty_streak = 0

        for it in items:
            if it["post_id"] in seen:
                continue
            seen.add(it["post_id"])

            time.sleep(REQUEST_DELAY_SEC)

            dhtml = fetch(session, it["link"])
            body = parse_detail_text(dhtml)

            ok, info = passes(it, body)

            if debug:
                print("제목:", it["title"])
                print("등록일:", it["posted_at"])
                print("판정:", info.get("dq_status"), "사유:", info.get("dq_reasons"))
                print("--------------------")

            if not ok:
                continue

            out.append({
                "글번호": it["post_id"],
                "제목": it["title"],
                "등록일": it["posted_at"],
                "작성자": it["writer"],
                "링크": it["link"],
                "판정": info.get("dq_status", "PASS"),
                "사유": ",".join(info.get("dq_reasons", [])),
                "마감일추정": info.get("deadline"),
            })

            if len(out) >= max_items:
                break

        if len(out) >= max_items:
            break

    return pd.DataFrame(out, columns=["글번호", "제목", "등록일", "작성자", "링크", "판정", "사유", "마감일추정"])


if __name__ == "__main__":
    # 로컬 테스트용
    df = crawl(max_pages=50, debug=True)

    if not df.empty:
        df["등록일_dt"] = pd.to_datetime(df["등록일"], errors="coerce")
        df = df.sort_values("등록일_dt", ascending=False).drop(columns=["등록일_dt"])

    print(df.head(30).to_string(index=False))
