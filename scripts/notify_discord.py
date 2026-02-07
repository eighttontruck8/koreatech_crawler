import json
import os
import sys
from pathlib import Path
from zoneinfo import ZoneInfo
import pandas as pd
import requests

# 너가 만든 크롤러 파일에서 crawl을 import 하도록 경로 맞춰줘
# 예) from crawler import crawl
sys.path.append(str(Path(__file__).resolve().parent.parent))

from koreatech_crawler import crawl

STATE_PATH = Path("state.json")
WEBHOOK_URL = os.environ["DISCORD_WEBHOOK_URL"]

# ✅ 알림 대상 판정(원하는대로 바꿔도 됨)
# ALLOWED_STATUS = {"PASS"}        # PASS만 알림
ALLOWED_STATUS = {"PASS", "NO_CONDITION", "UNKNOWN"}  # 전부 알림

def load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {"last_seen_post_id": 0}

def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

def post_discord(posts: list[dict]) -> None:
    # 너무 많이 보내면 스팸이니 한 번에 묶어서 보내기(10개씩)
    for chunk_start in range(0, len(posts), 10):
        chunk = posts[chunk_start:chunk_start+10]
        lines = []
        for p in chunk:
            lines.append(f"• **{p['제목']}** ({p['등록일']})\n  {p['링크']}")
        content = "📌 **새 근로장학생 모집 글**\n" + "\n".join(lines)

        r = requests.post(WEBHOOK_URL, json={"content": content}, timeout=20)
        r.raise_for_status()

def main():
    state = load_state()
    last_seen = int(state.get("last_seen_post_id", 0))

    df: pd.DataFrame = crawl(max_pages=500, max_items=5000)

    # 글번호 숫자화
    df["글번호_int"] = pd.to_numeric(df["글번호"], errors="coerce")
    df = df.dropna(subset=["글번호_int"]).copy()
    df["글번호_int"] = df["글번호_int"].astype(int)

# ✅ 상태 필터(PASS만 등)
    if "판정" in df.columns:
        df = df[df["판정"].isin(ALLOWED_STATUS)].copy()
        
        
    # ✅ “새 글”만 (번호가 증가한다는 전제)
    new_df = df[df["글번호_int"] > last_seen].sort_values("글번호_int")

    if new_df.empty:
        print("No new posts.")
        return

    posts = new_df[["글번호", "제목", "등록일", "링크"]].to_dict(orient="records")
    post_discord(posts)

    # ✅ 알림 성공 후 state 갱신
    new_last_seen = int(new_df["글번호_int"].max())
    state["last_seen_post_id"] = new_last_seen
    save_state(state)

    print(f"Updated last_seen_post_id => {new_last_seen}")

if __name__ == "__main__":
    main()
