from fastapi import FastAPI, APIRouter, HTTPException
import uvicorn
import sys
from pathlib import Path

# 상대 경로로 import
sys.path.insert(0, str(Path(__file__).parent))
from bs_demo.bugsmusic import crawl_bugs_chart

# 서브라우터 생성
crawler_router = APIRouter(prefix="/crawler", tags=["crawler"])

@crawler_router.get("/")
async def crawler_root():
    return {"message": "Crawler Service", "status": "running"}

@crawler_router.get("/bugsmusic")
async def get_bugs_music_chart():
    """
    벅스뮤직 실시간 차트를 크롤링하여 반환
    """
    try:
        chart_data = crawl_bugs_chart()
        
        if not chart_data:
            raise HTTPException(status_code=500, detail="차트 데이터를 가져올 수 없습니다.")
        
        result = {
            "chart_type": "bugs_realtime",
            "total_count": len(chart_data),
            "songs": chart_data
        }
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"크롤링 중 오류 발생: {str(e)}")

app = FastAPI(
    title="Crawler Service API",
    description="Crawler 서비스 API 문서",
    version="1.0.0"
)

# 서브라우터를 앱에 포함
app.include_router(crawler_router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9001)

