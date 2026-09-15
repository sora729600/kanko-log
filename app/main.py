import os
import shutil
import uuid
import traceback
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Query, Request
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
# 1. データベース自動修復 & 初期化
# -------------------------------------------------------------
def init_and_fix_db():
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS postgis;"))
            conn.execute(text("""
                DO $$
                BEGIN
                    -- follows テーブルの修復
                    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'follows') THEN
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'follows' AND column_name = 'followed_id') THEN
                            ALTER TABLE follows ADD COLUMN followed_id UUID;
                        END IF;
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'follows' AND column_name = 'follower_id') THEN
                            ALTER TABLE follows ADD COLUMN follower_id UUID;
                        END IF;
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'follows' AND column_name = 'status') THEN
                            ALTER TABLE follows ADD COLUMN status VARCHAR(20) DEFAULT 'accepted';
                        END IF;
                    END IF;

                    -- users テーブルに is_private 追加
                    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') THEN
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'is_private') THEN
                            ALTER TABLE users ADD COLUMN is_private BOOLEAN DEFAULT FALSE;
                        END IF;
                    END IF;

                    -- notifications テーブルの確認
                    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'notifications') THEN
                        CREATE TABLE notifications (
                            id UUID PRIMARY KEY,
                            recipient_id UUID NOT NULL,
                            sender_id UUID NOT NULL,
                            type VARCHAR(50) NOT NULL,
                            message VARCHAR(255) NOT NULL,
                            is_read BOOLEAN DEFAULT FALSE,
                            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc')
                        );
                    END IF;
                END $$;
            """))
            print("[DB Migration] Schema patched successfully.")
    except Exception as e:
        print(f"[DB Migration Note]: {e}")

    try:
        models.Base.metadata.create_all(bind=engine)
        print("[DB Init] All tables verified/created.")
    except Exception as e:
        print(f"[DB Init Error]: {e}")

init_and_fix_db()

# -------------------------------------------------------------
# 2. セキュリティ & JWT
# -------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "travel-log-production-secret-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

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
# 3. アプリ本体 & 静的ファイル
# -------------------------------------------------------------
app = FastAPI(title="Travel Log", version="1.2.1")

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
# 4. 認証ヘルパー
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

class PrivacyUpdate(BaseModel):
    is_private: bool

class FollowDecision(BaseModel):
    target_username: str
    action: str  # 'accept' or 'decline'

def get_current_user_maybe(request: Request, db: Session = Depends(get_db)) -> Optional[models.User]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username:
            clean = username.strip()
            return db.query(models.User).filter(
                or_(models.User.username == clean, models.User.username.ilike(clean))
            ).first()
    except Exception:
        return None
    return None

def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    user = get_current_user_maybe(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="認証が必要です")
    return user

# -------------------------------------------------------------
# 5. 認証エンドポイント
# -------------------------------------------------------------
@app.post("/auth/register")
def register(user_in: UserRegister, db: Session = Depends(get_db)):
    clean_username = user_in.username.strip()
    existing = db.query(models.User).filter(
        or_(models.User.username == clean_username, models.User.username.ilike(clean_username))
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="そのユーザーIDは既に使用されています")
    
    new_user = models.User(
        id=uuid.uuid4(),
        username=clean_username,
        display_name=user_in.display_name.strip() if user_in.display_name else clean_username,
        email=user_in.email.strip() if user_in.email else None,
        hashed_password=get_password_hash(user_in.password),
        bio="旅の記録をはじめました。",
        is_private=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    access_token = create_access_token({"sub": new_user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": str(new_user.id),
            "username": new_user.username,
            "display_name": new_user.display_name,
            "bio": new_user.bio,
            "avatar_url": new_user.avatar_url,
            "cover_url": new_user.cover_url,
            "is_private": new_user.is_private
        }
    }

@app.post("/auth/login")
def login(user_in: UserLogin, db: Session = Depends(get_db)):
    clean_username = user_in.username.strip()
    user = db.query(models.User).filter(
        or_(models.User.username == clean_username, models.User.username.ilike(clean_username))
    ).first()
    if not user or not verify_password(user_in.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="ユーザー名またはパスワードが間違っています")
    
    access_token = create_access_token({"sub": user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "username": user.username,
            "display_name": user.display_name,
            "bio": user.bio,
            "avatar_url": user.avatar_url,
            "cover_url": user.cover_url,
            "is_private": user.is_private or False
        }
    }

@app.get("/auth/me")
def get_me(current_user: models.User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "display_name": current_user.display_name,
        "email": current_user.email,
        "bio": current_user.bio,
        "avatar_url": current_user.avatar_url,
        "cover_url": current_user.cover_url,
        "is_private": current_user.is_private or False
    }

# -------------------------------------------------------------
# 6. ストーリーバー（フォロー中ユーザー）
# -------------------------------------------------------------
@app.get("/users/following/stories")
def get_following_stories(db: Session = Depends(get_db), current_user: Optional[models.User] = Depends(get_current_user_maybe)):
    if not current_user:
        return []

    try:
        follows = db.query(models.Follow).filter(
            models.Follow.follower_id == current_user.id,
            models.Follow.status == "accepted"
        ).all()
        followed_ids = [f.followed_id for f in follows if f.followed_id is not None]
        if not followed_ids:
            return []

        users = db.query(models.User).filter(models.User.id.in_(followed_ids)).all()
        res = []
        for u in users:
            latest_spot = db.query(models.Spot).filter(models.Spot.user_id == u.id).order_by(desc(models.Spot.visited_at)).first()
            res.append({
                "id": str(u.id),
                "username": u.username,
                "display_name": u.display_name or u.username,
                "avatar_url": u.avatar_url,
                "has_recent_spot": latest_spot is not None
            })
        return res
    except Exception as e:
        print(f"[Stories Error]: {e}")
        return []

# -------------------------------------------------------------
# 7. スポット（旅ログ）投稿 & フィード
# -------------------------------------------------------------
@app.get("/spots")
def get_spots(
    feed_type: str = "all",
    target_username: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_current_user_maybe)
):
    try:
        query = db.query(models.Spot)

        if target_username:
            clean_name = target_username.strip()
            target_user = db.query(models.User).filter(
                or_(models.User.username == clean_name, models.User.username.ilike(clean_name))
            ).first()
            if target_user:
                query = query.filter(models.Spot.user_id == target_user.id)
            else:
                return []
        elif feed_type == "following" and current_user:
            follows = db.query(models.Follow).filter(
                models.Follow.follower_id == current_user.id,
                models.Follow.status == "accepted"
            ).all()
            followed_ids = [f.followed_id for f in follows if f.followed_id is not None]
            if not followed_ids:
                return []
            query = query.filter(models.Spot.user_id.in_(followed_ids))

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

            likes_count = 0
            is_liked = False
            try:
                likes_count = db.query(models.Like).filter(models.Like.spot_id == s.id).count()
                if current_user:
                    is_liked = db.query(models.Like).filter(models.Like.spot_id == s.id, models.Like.user_id == current_user.id).first() is not None
            except Exception:
                pass

            author = s.author
            result.append({
                "id": str(s.id),
                "name": s.name,
                "memo": s.memo,
                "media_url": s.media_url,
                "media_type": s.media_type,
                "visited_at": s.visited_at.isoformat() if s.visited_at else datetime.utcnow().isoformat(),
                "latitude": lat,
                "longitude": lng,
                "google_map_url": f"https://www.google.com/maps/search/?api=1&query={lat},{lng}",
                "user_id": str(s.user_id) if s.user_id else None,
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
            id=uuid.uuid4(),
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

        if current_user:
            try:
                followers = db.query(models.Follow).filter(
                    models.Follow.followed_id == current_user.id,
                    models.Follow.status == "accepted"
                ).all()
                for f in followers:
                    notif = models.Notification(
                        id=uuid.uuid4(),
                        recipient_id=f.follower_id,
                        sender_id=current_user.id,
                        type="new_post",
                        message=f"@{current_user.username} さんが新しい思い出「{spot.name}」を投稿しました！"
                    )
                    db.add(notif)
                db.commit()
            except Exception as notif_err:
                print(f"[Notification Note]: {notif_err}")

        return {"status": "success", "id": str(spot.id)}
    except Exception as e:
        db.rollback()
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to upload spot: {str(e)}")

@app.post("/spots/{spot_id}/like")
def toggle_spot_like(spot_id: str, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    try:
        spot_uuid = uuid.UUID(spot_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="無効なスポットIDです")

    like = db.query(models.Like).filter(models.Like.spot_id == spot_uuid, models.Like.user_id == current_user.id).first()
    if like:
        db.delete(like)
        db.commit()
        liked = False
    else:
        db.add(models.Like(id=uuid.uuid4(), spot_id=spot_uuid, user_id=current_user.id))
        db.commit()
        liked = True

    count = db.query(models.Like).filter(models.Like.spot_id == spot_uuid).count()
    return {"liked": liked, "likes_count": count}

@app.delete("/spots/{spot_id}")
def delete_spot(spot_id: str, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    try:
        spot_uuid = uuid.UUID(spot_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="無効なスポットIDです")

    spot = db.query(models.Spot).filter(models.Spot.id == spot_uuid).first()
    if not spot:
        raise HTTPException(status_code=404, detail="スポットが見つかりません")
    if spot.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="自分の投稿のみ削除できます")
    db.delete(spot)
    db.commit()
    return {"status": "deleted"}

# -------------------------------------------------------------
# 8. プロフィール & フォロー（修正完了）
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
        "id": str(u.id),
        "username": u.username,
        "display_name": u.display_name,
        "avatar_url": u.avatar_url
    } for u in users]

@app.get("/users/{username}")
def get_profile(username: str, db: Session = Depends(get_db), current_user: Optional[models.User] = Depends(get_current_user_maybe)):
    try:
        clean_user = username.strip()
        target = db.query(models.User).filter(
            or_(models.User.username == clean_user, models.User.username.ilike(clean_user))
        ).first()
        if not target:
            raise HTTPException(status_code=404, detail="ユーザーが見つかりません")
        
        following_count = 0
        followers_count = 0
        follow_status = "none"

        try:
            following_count = db.query(models.Follow).filter(
                models.Follow.follower_id == target.id,
                models.Follow.status == "accepted"
            ).count()
            followers_count = db.query(models.Follow).filter(
                models.Follow.followed_id == target.id,
                models.Follow.status == "accepted"
            ).count()

            if current_user:
                rel = db.query(models.Follow).filter(
                    models.Follow.follower_id == current_user.id,
                    models.Follow.followed_id == target.id
                ).first()
                if rel:
                    follow_status = "following" if rel.status == "accepted" else "pending"
        except Exception as fe:
            print(f"[Profile Follow Count Note]: {fe}")

        return {
            "id": str(target.id),
            "username": target.username,
            "display_name": target.display_name or target.username,
            "bio": target.bio or "旅の記録をはじめました。",
            "avatar_url": target.avatar_url,
            "cover_url": target.cover_url,
            "is_private": target.is_private or False,
            "following_count": following_count,
            "followers_count": followers_count,
            "follow_status": follow_status
        }
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"プロフィール取得エラー: {str(e)}")

@app.post("/users/{username}/follow")
def toggle_follow(username: str, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    try:
        clean_user = username.strip()
        target = db.query(models.User).filter(
            or_(models.User.username == clean_user, models.User.username.ilike(clean_user))
        ).first()
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
            return {"follow_status": "none"}
        else:
            if target.is_private:
                new_rel = models.Follow(
                    id=uuid.uuid4(),
                    follower_id=current_user.id,
                    followed_id=target.id,
                    status="pending"
                )
                notif_msg = f"@{current_user.username} さんからフォロー申請が届きました！"
                notif_type = "follow_request"
                result_status = "pending"
            else:
                new_rel = models.Follow(
                    id=uuid.uuid4(),
                    follower_id=current_user.id,
                    followed_id=target.id,
                    status="accepted"
                )
                notif_msg = f"@{current_user.username} さんにフォローされました！"
                notif_type = "follow"
                result_status = "following"

            db.add(new_rel)
            try:
                notif = models.Notification(
                    id=uuid.uuid4(),
                    recipient_id=target.id,
                    sender_id=current_user.id,
                    type=notif_type,
                    message=notif_msg
                )
                db.add(notif)
            except Exception as ne:
                print(f"[Follow Notif Note]: {ne}")

            db.commit()
            return {"follow_status": result_status}
    except Exception as e:
        db.rollback()
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"フォロー処理に失敗しました: {str(e)}")

# 申請中（自分が送信した保留中の申請一覧）
@app.get("/friends/outgoing-requests")
def get_outgoing_requests(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    reqs = db.query(models.Follow).filter(
        models.Follow.follower_id == current_user.id,
        models.Follow.status == "pending"
    ).all()
    target_ids = [r.followed_id for r in reqs]
    users = db.query(models.User).filter(models.User.id.in_(target_ids)).all() if target_ids else []
    return [{
        "id": str(u.id),
        "username": u.username,
        "display_name": u.display_name,
        "avatar_url": u.avatar_url
    } for u in users]

# 承認待ち（自分宛に届いた保留中の申請一覧）
@app.get("/friends/incoming-requests")
def get_incoming_requests(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    reqs = db.query(models.Follow).filter(
        models.Follow.followed_id == current_user.id,
        models.Follow.status == "pending"
    ).all()
    sender_ids = [r.follower_id for r in reqs]
    users = db.query(models.User).filter(models.User.id.in_(sender_ids)).all() if sender_ids else []
    return [{
        "id": str(u.id),
        "username": u.username,
        "display_name": u.display_name,
        "avatar_url": u.avatar_url
    } for u in users]

# 申請の承認・拒否
@app.post("/friends/decision")
def handle_follow_decision(payload: FollowDecision, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    clean_target = payload.target_username.strip()
    sender = db.query(models.User).filter(
        or_(models.User.username == clean_target, models.User.username.ilike(clean_target))
    ).first()
    if not sender:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")

    rel = db.query(models.Follow).filter(
        models.Follow.follower_id == sender.id,
        models.Follow.followed_id == current_user.id,
        models.Follow.status == "pending"
    ).first()

    if not rel:
        raise HTTPException(status_code=404, detail="対象のフォロー申請がありません")

    if payload.action == "accept":
        rel.status = "accepted"
        try:
            notif = models.Notification(
                id=uuid.uuid4(),
                recipient_id=sender.id,
                sender_id=current_user.id,
                type="follow_accepted",
                message=f"@{current_user.username} さんへのフォロー申請が承認されました！"
            )
            db.add(notif)
        except Exception:
            pass
        db.commit()
        return {"status": "accepted"}
    else:
        db.delete(rel)
        db.commit()
        return {"status": "declined"}

# 鍵アカウント設定
@app.post("/users/privacy")
def update_privacy(payload: PrivacyUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    current_user.is_private = payload.is_private
    db.commit()
    return {"status": "ok", "is_private": current_user.is_private}

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
        "id": str(current_user.id),
        "username": current_user.username,
        "display_name": current_user.display_name,
        "bio": current_user.bio,
        "avatar_url": current_user.avatar_url,
        "cover_url": current_user.cover_url,
        "is_private": current_user.is_private
    }

# -------------------------------------------------------------
# 9. 通知（Notifications）
# -------------------------------------------------------------
@app.get("/notifications")
def get_notifications(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    try:
        notifs = db.query(models.Notification).filter(
            models.Notification.recipient_id == current_user.id
        ).order_by(desc(models.Notification.created_at)).limit(30).all()

        res = []
        for n in notifs:
            sender = n.sender
            res.append({
                "id": str(n.id),
                "type": n.type,
                "message": n.message,
                "is_read": n.is_read,
                "created_at": n.created_at.isoformat(),
                "sender_username": sender.username if sender else "someone",
                "sender_avatar_url": sender.avatar_url if sender else None
            })
        return res
    except Exception as e:
        print(f"[Notification Fetch Error]: {e}")
        return []

@app.post("/notifications/read")
def mark_notifications_read(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    try:
        db.query(models.Notification).filter(
            models.Notification.recipient_id == current_user.id,
            models.Notification.is_read == False
        ).update({"is_read": True})
        db.commit()
    except Exception:
        pass
    return {"status": "ok"}

# -------------------------------------------------------------
# 10. DM (ダイレクトメッセージ)
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
        "id": str(u.id),
        "username": u.username,
        "display_name": u.display_name,
        "avatar_url": u.avatar_url
    } for u in users]

@app.get("/messages/{partner_username}")
def get_messages(partner_username: str, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    clean_name = partner_username.strip()
    partner = db.query(models.User).filter(
        or_(models.User.username == clean_name, models.User.username.ilike(clean_name))
    ).first()
    if not partner:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")

    msgs = db.query(models.Message).filter(
        or_(
            and_(models.Message.sender_id == current_user.id, models.Message.recipient_id == partner.id),
            and_(models.Message.sender_id == partner.id, models.Message.recipient_id == current_user.id)
        )
    ).order_by(models.Message.created_at.asc()).all()

    return [{
        "id": str(m.id),
        "sender_username": current_user.username if m.sender_id == current_user.id else partner.username,
        "content": m.content,
        "created_at": m.created_at.isoformat()
    } for m in msgs]

@app.post("/messages")
def send_message(payload: DmCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    clean_name = payload.recipient_username.strip()
    recipient = db.query(models.User).filter(
        or_(models.User.username == clean_name, models.User.username.ilike(clean_name))
    ).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="送信先ユーザーが見つかりません")

    msg = models.Message(
        id=uuid.uuid4(),
        sender_id=current_user.id,
        recipient_id=recipient.id,
        content=payload.content.strip()
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return {"status": "sent", "id": str(msg.id)}

# -------------------------------------------------------------
# 11. トップページ
# -------------------------------------------------------------
@app.get("/")
def serve_index():
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Travel Log API is running. static/index.html was not found."}