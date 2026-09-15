import os
import shutil
import uuid
import traceback
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import text, or_, and_, desc
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from geoalchemy2.shape import to_shape
from geoalchemy2.elements import WKTElement

from app.database import engine, Base, get_db
import app.models as models

# -------------------------------------------------------------
# 1. データベース自動初期化（PostGIS有効化 ＆ 全テーブル作成）
# -------------------------------------------------------------
def init_db():
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS postgis;"))
    except Exception as e:
        print(f"[DB Init] Note on postgis extension: {e}")

    try:
        models.Base.metadata.create_all(bind=engine)
        print("[DB Init] All database tables created/verified successfully.")
    except Exception as e:
        print(f"[DB Init Error] Failed to create tables: {e}")

init_db()

# -------------------------------------------------------------
# 2. セキュリティ & JWT 設定
# -------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "travel-log-production-secret-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7日間

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# -------------------------------------------------------------
# 3. アプリ本体 & CORS / 静的ファイル
# -------------------------------------------------------------
app = FastAPI(title="Travel Log", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = os.path.join("static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# -------------------------------------------------------------
# 4. スキーマ
# -------------------------------------------------------------
class UserRegister(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    display_name: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class DmCreate(BaseModel):
    recipient_username: str
    content: str

from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

def get_current_user(token: Optional[str] = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> models.User:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="認証が必要です")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="無効なトークンです")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="トークンの検証に失敗しました")
    
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="ユーザーが存在しません")
    return user

def get_current_user_maybe(token: Optional[str] = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Optional[models.User]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username:
            return db.query(models.User).filter(models.User.username == username).first()
    except Exception:
        return None
    return None

# -------------------------------------------------------------
# 5. 認証ルート
# -------------------------------------------------------------
@app.post("/auth/register")
def register(user_in: UserRegister, db: Session = Depends(get_db)):
    clean_username = user_in.username.strip().lower()
    existing = db.query(models.User).filter(models.User.username == clean_username).first()
    if existing:
        raise HTTPException(status_code=400, detail="そのユーザーIDは既に使用されています")
    
    new_user = models.User(
        username=clean_username,
        display_name=user_in.display_name.strip() if user_in.display_name else clean_username,
        email=user_in.email.strip() if user_in.email else None,
        hashed_password=get_password_hash(user_in.password),
        bio="旅の記録をはじめました。",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    access_token = create_access_token({"sub": new_user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "display_name": new_user.display_name,
            "bio": new_user.bio,
            "avatar_url": new_user.avatar_url,
            "cover_url": new_user.cover_url
        }
    }

@app.post("/auth/login")
def login(user_in: UserLogin, db: Session = Depends(get_db)):
    clean_username = user_in.username.strip().lower()
    user = db.query(models.User).filter(models.User.username == clean_username).first()
    if not user or not verify_password(user_in.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="ユーザー名またはパスワードが間違っています")
    
    access_token = create_access_token({"sub": user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "bio": user.bio,
            "avatar_url": user.avatar_url,
            "cover_url": user.cover_url
        }
    }

@app.get("/auth/me")
def get_me(current_user: models.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "display_name": current_user.display_name,
        "email": current_user.email,
        "bio": current_user.bio,
        "avatar_url": current_user.avatar_url,
        "cover_url": current_user.cover_url
    }

# -------------------------------------------------------------
# 6. スポット（旅ログ）
# -------------------------------------------------------------
@app.get("/spots")
def get_spots(
    feed_type: str = "all",
    target_date: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_current_user_maybe)
):
    try:
        query = db.query(models.Spot)

        if feed_type == "following" and current_user:
            followed_ids = db.query(models.Follow.followed_id).filter(models.Follow.follower_id == current_user.id).subquery()
            query = query.filter(models.Spot.user_id.in_(followed_ids))

        if target_date:
            try:
                d = datetime.strptime(target_date, "%Y-%m-%d")
                start = datetime(d.year, d.month, d.day, 0, 0, 0)
                end = datetime(d.year, d.month, d.day, 23, 59, 59)
                query = query.filter(models.Spot.visited_at >= start, models.Spot.visited_at <= end)
            except ValueError:
                pass

        spots = query.order_by(desc(models.Spot.visited_at)).all()

        result = []
        for s in spots:
            lat = 0.0
            lng = 0.0
            try:
                point = to_shape(s.geom)
                lat = float(point.y)
                lng = float(point.x)
            except Exception:
                pass

            likes_count = db.query(models.Like).filter(models.Like.spot_id == s.id).count()
            is_liked = False
            if current_user:
                is_liked = db.query(models.Like).filter(models.Like.spot_id == s.id, models.Like.user_id == current_user.id).first() is not None

            author = s.author
            result.append({
                "id": s.id,
                "name": s.name,
                "memo": s.memo,
                "media_url": s.media_url,
                "media_type": s.media_type,
                "visited_at": s.visited_at.isoformat() if s.visited_at else datetime.utcnow().isoformat(),
                "latitude": lat,
                "longitude": lng,
                "google_map_url": f"https://www.google.com/maps/search/?api=1&query={lat},{lng}",
                "user_id": s.user_id,
                "username": author.username if author else "anonymous",
                "display_name": author.display_name if author else "Traveler",
                "author_avatar_url": author.avatar_url if author else None,
                "likes_count": likes_count,
                "is_liked": is_liked
            })
        return result
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to fetch spots: {str(e)}")

@app.post("/spots/upload")
def create_spot(
    name: str = Form(...),
    latitude: float = Form(...),
    longitude: float = Form(...),
    memo: Optional[str] = Form(None),
    visited_at: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_current_user_maybe)
):
    try:
        media_url = None
        media_type = None

        if file and file.filename:
            ext = os.path.splitext(file.filename)[1].lower()
            fname = f"{uuid.uuid4()}{ext}"
            path = os.path.join(UPLOAD_DIR, fname)
            with open(path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            media_url = f"/static/uploads/{fname}"
            media_type = "video" if ext in [".mp4", ".mov", ".webm"] else "image"

        visit_time = datetime.utcnow()
        if visited_at:
            try:
                visit_time = datetime.fromisoformat(visited_at)
            except Exception:
                pass

        spot = models.Spot(
            name=name.strip(),
            memo=memo.strip() if memo else None,
            media_url=media_url,
            media_type=media_type,
            visited_at=visit_time,
            geom=WKTElement(f"POINT({longitude} {latitude})", srid=4326),
            user_id=current_user.id if current_user else None
        )
        db.add(spot)
        db.commit()
        db.refresh(spot)
        return {"status": "success", "id": spot.id}
    except Exception as e:
        db.rollback()
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to upload spot: {str(e)}")

@app.post("/spots/{spot_id}/like")
def toggle_spot_like(spot_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    like = db.query(models.Like).filter(models.Like.spot_id == spot_id, models.Like.user_id == current_user.id).first()
    if like:
        db.delete(like)
        db.commit()
        liked = False
    else:
        db.add(models.Like(spot_id=spot_id, user_id=current_user.id))
        db.commit()
        liked = True

    count = db.query(models.Like).filter(models.Like.spot_id == spot_id).count()
    return {"liked": liked, "likes_count": count}

@app.delete("/spots/{spot_id}")
def delete_spot(spot_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    spot = db.query(models.Spot).filter(models.Spot.id == spot_id).first()
    if not spot:
        raise HTTPException(status_code=404, detail="スポットが見つかりません")
    if spot.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="自分の投稿のみ削除できます")
    db.delete(spot)
    db.commit()
    return {"status": "deleted"}

# -------------------------------------------------------------
# 7. プロフィール & フォロー & 検索
# -------------------------------------------------------------
@app.get("/users/search")
def search_users(q: str = Query(""), db: Session = Depends(get_db)):
    clean_q = q.strip()
    if not clean_q:
        return []
    users = db.query(models.User).filter(
        or_(
            models.User.username.ilike(f"%{clean_q}%"),
            models.User.display_name.ilike(f"%{clean_q}%")
        )
    ).limit(10).all()
    return [{
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "avatar_url": u.avatar_url
    } for u in users]

@app.get("/users/{username}")
def get_profile(username: str, db: Session = Depends(get_db), current_user: Optional[models.User] = Depends(get_current_user_maybe)):
    target = db.query(models.User).filter(models.User.username == username.strip().lower()).first()
    if not target:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")
    
    following_count = db.query(models.Follow).filter(models.Follow.follower_id == target.id).count()
    followers_count = db.query(models.Follow).filter(models.Follow.followed_id == target.id).count()
    
    is_following = False
    if current_user:
        is_following = db.query(models.Follow).filter(
            models.Follow.follower_id == current_user.id,
            models.Follow.followed_id == target.id
        ).first() is not None

    return {
        "id": target.id,
        "username": target.username,
        "display_name": target.display_name,
        "bio": target.bio,
        "avatar_url": target.avatar_url,
        "cover_url": target.cover_url,
        "following_count": following_count,
        "followers_count": followers_count,
        "is_following": is_following
    }

@app.post("/users/{username}/follow")
def toggle_follow(username: str, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    target = db.query(models.User).filter(models.User.username == username.strip().lower()).first()
    if not target:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")
    if target.id == current_user.id:
        raise HTTPException(status_code=400, detail="自分自身はフォローできません")
    
    rel = db.query(models.Follow).filter(
        models.Follow.follower_id == current_user.id,
        models.Follow.followed_id == target.id
    ).first()
    
    if rel:
        db.delete(rel)
        db.commit()
        return {"following": False}
    else:
        db.add(models.Follow(follower_id=current_user.id, followed_id=target.id))
        db.commit()
        return {"following": True}

@app.post("/users/profile")
def update_profile(
    display_name: Optional[str] = Form(None),
    bio: Optional[str] = Form(None),
    avatar: Optional[UploadFile] = File(None),
    cover: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    if display_name is not None:
        current_user.display_name = display_name.strip()
    if bio is not None:
        current_user.bio = bio.strip()
        
    if avatar and avatar.filename:
        ext = os.path.splitext(avatar.filename)[1].lower()
        fname = f"avatar_{uuid.uuid4()}{ext}"
        path = os.path.join(UPLOAD_DIR, fname)
        with open(path, "wb") as buffer:
            shutil.copyfileobj(avatar.file, buffer)
        current_user.avatar_url = f"/static/uploads/{fname}"

    if cover and cover.filename:
        ext = os.path.splitext(cover.filename)[1].lower()
        fname = f"cover_{uuid.uuid4()}{ext}"
        path = os.path.join(UPLOAD_DIR, fname)
        with open(path, "wb") as buffer:
            shutil.copyfileobj(cover.file, buffer)
        current_user.cover_url = f"/static/uploads/{fname}"

    db.commit()
    db.refresh(current_user)
    return {
        "id": current_user.id,
        "username": current_user.username,
        "display_name": current_user.display_name,
        "bio": current_user.bio,
        "avatar_url": current_user.avatar_url,
        "cover_url": current_user.cover_url
    }

# -------------------------------------------------------------
# 8. DM (ダイレクトメッセージ)
# -------------------------------------------------------------
@app.get("/messages/conversations")
def get_conversations(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    msgs = db.query(models.Message).filter(
        or_(models.Message.sender_id == current_user.id, models.Message.recipient_id == current_user.id)
    ).order_by(desc(models.Message.created_at)).all()

    partner_ids = []
    for m in msgs:
        pid = m.recipient_id if m.sender_id == current_user.id else m.sender_id
        if pid not in partner_ids:
            partner_ids.append(pid)

    users = db.query(models.User).filter(models.User.id.in_(partner_ids)).all()
    return [{
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "avatar_url": u.avatar_url
    } for u in users]

@app.get("/messages/{partner_username}")
def get_messages(partner_username: str, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    partner = db.query(models.User).filter(models.User.username == partner_username.strip().lower()).first()
    if not partner:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")

    msgs = db.query(models.Message).filter(
        or_(
            and_(models.Message.sender_id == current_user.id, models.Message.recipient_id == partner.id),
            and_(models.Message.sender_id == partner.id, models.Message.recipient_id == current_user.id)
        )
    ).order_by(models.Message.created_at.asc()).all()

    return [{
        "id": m.id,
        "sender_username": current_user.username if m.sender_id == current_user.id else partner.username,
        "content": m.content,
        "created_at": m.created_at.isoformat()
    } for m in msgs]

@app.post("/messages")
def send_message(payload: DmCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    recipient = db.query(models.User).filter(models.User.username == payload.recipient_username.strip().lower()).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="送信先ユーザーが見つかりません")

    msg = models.Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        content=payload.content.strip()
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return {"status": "sent", "id": msg.id}

# -------------------------------------------------------------
# 9. トップページ (index.html)
# -------------------------------------------------------------
@app.get("/")
def serve_index():
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Travel Log API is running. static/index.html was not found."}