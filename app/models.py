import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, UniqueConstraint, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from geoalchemy2 import Geometry
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    display_name = Column(String(100), nullable=True)
    email = Column(String(120), unique=True, index=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    bio = Column(Text, nullable=True)
    avatar_url = Column(String(255), nullable=True)
    cover_url = Column(String(255), nullable=True)
    is_private = Column(Boolean, default=False)  # 鍵アカウント設定（Trueならフォロー承認制）
    created_at = Column(DateTime, default=datetime.utcnow)

    spots = relationship("Spot", back_populates="author", cascade="all, delete-orphan")
    likes = relationship("Like", back_populates="user", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="recipient", cascade="all, delete-orphan", foreign_keys="Notification.recipient_id")


class Spot(Base):
    __tablename__ = "spots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String(100), nullable=False)
    memo = Column(Text, nullable=True)
    media_url = Column(String(255), nullable=True)
    media_type = Column(String(20), nullable=True)
    visited_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    geom = Column(Geometry(geometry_type='POINT', srid=4326), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    author = relationship("User", back_populates="spots")
    likes = relationship("Like", back_populates="spot", cascade="all, delete-orphan")


class Like(Base):
    __tablename__ = "likes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    spot_id = Column(UUID(as_uuid=True), ForeignKey("spots.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint('user_id', 'spot_id', name='unique_user_spot_like'),)

    user = relationship("User", back_populates="likes")
    spot = relationship("Spot", back_populates="likes")


class Follow(Base):
    __tablename__ = "follows"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    follower_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    followed_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(20), default="accepted")  # 'accepted' または 'pending' (承認待ち)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint('follower_id', 'followed_id', name='unique_follow_relation'),)


class Message(Base):
    __tablename__ = "messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    sender_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    recipient_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    recipient_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    sender_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    type = Column(String(50), nullable=False)  # 'follow', 'follow_request', 'follow_accepted', 'new_post'
    message = Column(String(255), nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="notifications")
    sender = relationship("User", foreign_keys=[sender_id])