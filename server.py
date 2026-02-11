from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId
import socketio

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'eduexpo_qatar')]

# JWT Settings
SECRET_KEY = os.environ.get('SECRET_KEY', 'eduexpo-qatar-secret-key-2026')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBearer()

# Create the main app
app = FastAPI(title="EduExpo Qatar API")

# Socket.IO setup
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
socket_app = socketio.ASGIApp(sio, app)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== MODELS ====================

class UserBase(BaseModel):
    full_name: str
    email: EmailStr
    role: str = "guest"  # guest, speaker, exhibitor, sponsor, organizer
    bio: Optional[str] = ""
    organization: Optional[str] = ""
    position: Optional[str] = ""
    avatar: Optional[str] = ""

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    full_name: str
    email: str
    role: str
    bio: Optional[str] = ""
    organization: Optional[str] = ""
    position: Optional[str] = ""
    avatar: Optional[str] = ""
    connections: List[str] = []
    created_at: datetime

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    bio: Optional[str] = None
    organization: Optional[str] = None
    position: Optional[str] = None
    avatar: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class ConnectionRequest(BaseModel):
    to_user_id: str

class ConnectionResponse(BaseModel):
    id: str
    from_user_id: str
    to_user_id: str
    status: str  # pending, accepted, rejected
    created_at: datetime
    from_user: Optional[UserResponse] = None
    to_user: Optional[UserResponse] = None

class MessageCreate(BaseModel):
    to_user_id: str
    content: str

class MessageResponse(BaseModel):
    id: str
    from_user_id: str
    to_user_id: str
    content: str
    read: bool = False
    created_at: datetime
    from_user: Optional[UserResponse] = None

class ConversationResponse(BaseModel):
    user: UserResponse
    last_message: Optional[MessageResponse] = None
    unread_count: int = 0

# ==================== HELPER FUNCTIONS ====================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise credentials_exception
    return user

def user_to_response(user: dict) -> UserResponse:
    return UserResponse(
        id=str(user["_id"]),
        full_name=user["full_name"],
        email=user["email"],
        role=user.get("role", "guest"),
        bio=user.get("bio", ""),
        organization=user.get("organization", ""),
        position=user.get("position", ""),
        avatar=user.get("avatar", ""),
        connections=user.get("connections", []),
        created_at=user.get("created_at", datetime.utcnow())
    )

# ==================== AUTH ENDPOINTS ====================

@api_router.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email})
    print('login')
    if not user or not verify_password(user_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    access_token = create_access_token(data={"sub": str(user["_id"])})
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=user_to_response(user)
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return user_to_response(current_user)

# ==================== USER ENDPOINTS ====================

@api_router.get("/users", response_model=List[UserResponse])
async def get_users(current_user: dict = Depends(get_current_user)):
    users = await db.users.find({"_id": {"$ne": current_user["_id"]}}).to_list(1000)
    return [user_to_response(user) for user in users]

@api_router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, current_user: dict = Depends(get_current_user)):
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user_to_response(user)

@api_router.put("/users/me", response_model=UserResponse)
async def update_user(user_update: UserUpdate, current_user: dict = Depends(get_current_user)):
    update_data = {k: v for k, v in user_update.dict().items() if v is not None}
    if update_data:
        await db.users.update_one(
            {"_id": current_user["_id"]},
            {"$set": update_data}
        )
    updated_user = await db.users.find_one({"_id": current_user["_id"]})
    return user_to_response(updated_user)

# ==================== CONNECTION ENDPOINTS ====================

@api_router.post("/connections/request", response_model=ConnectionResponse)
async def send_connection_request(request: ConnectionRequest, current_user: dict = Depends(get_current_user)):
    to_user_id = request.to_user_id
    from_user_id = str(current_user["_id"])
    
    # Check if user exists
    to_user = await db.users.find_one({"_id": ObjectId(to_user_id)})
    if not to_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if connection already exists
    existing = await db.connections.find_one({
        "$or": [
            {"from_user_id": from_user_id, "to_user_id": to_user_id},
            {"from_user_id": to_user_id, "to_user_id": from_user_id}
        ]
    })
    if existing:
        raise HTTPException(status_code=400, detail="Connection already exists")
    
    connection = {
        "from_user_id": from_user_id,
        "to_user_id": to_user_id,
        "status": "pending",
        "created_at": datetime.utcnow()
    }
    result = await db.connections.insert_one(connection)
    connection["_id"] = result.inserted_id
    
    return ConnectionResponse(
        id=str(connection["_id"]),
        from_user_id=from_user_id,
        to_user_id=to_user_id,
        status="pending",
        created_at=connection["created_at"],
        from_user=user_to_response(current_user),
        to_user=user_to_response(to_user)
    )

@api_router.get("/connections", response_model=List[ConnectionResponse])
async def get_connections(current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    connections = await db.connections.find({
        "$and": [
            {"status": "accepted"},
            {"$or": [
                {"from_user_id": user_id},
                {"to_user_id": user_id}
            ]}
        ]
    }).to_list(1000)
    
    result = []
    for conn in connections:
        other_user_id = conn["to_user_id"] if conn["from_user_id"] == user_id else conn["from_user_id"]
        other_user = await db.users.find_one({"_id": ObjectId(other_user_id)})
        if other_user:
            result.append(ConnectionResponse(
                id=str(conn["_id"]),
                from_user_id=conn["from_user_id"],
                to_user_id=conn["to_user_id"],
                status=conn["status"],
                created_at=conn["created_at"],
                to_user=user_to_response(other_user) if conn["from_user_id"] == user_id else None,
                from_user=user_to_response(other_user) if conn["to_user_id"] == user_id else None
            ))
    return result

@api_router.get("/connections/pending", response_model=List[ConnectionResponse])
async def get_pending_connections(current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    connections = await db.connections.find({
        "to_user_id": user_id,
        "status": "pending"
    }).to_list(1000)
    
    result = []
    for conn in connections:
        from_user = await db.users.find_one({"_id": ObjectId(conn["from_user_id"])})
        if from_user:
            result.append(ConnectionResponse(
                id=str(conn["_id"]),
                from_user_id=conn["from_user_id"],
                to_user_id=conn["to_user_id"],
                status=conn["status"],
                created_at=conn["created_at"],
                from_user=user_to_response(from_user)
            ))
    return result

@api_router.get("/connections/sent", response_model=List[ConnectionResponse])
async def get_sent_connections(current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    connections = await db.connections.find({
        "from_user_id": user_id,
        "status": "pending"
    }).to_list(1000)
    
    result = []
    for conn in connections:
        to_user = await db.users.find_one({"_id": ObjectId(conn["to_user_id"])})
        if to_user:
            result.append(ConnectionResponse(
                id=str(conn["_id"]),
                from_user_id=conn["from_user_id"],
                to_user_id=conn["to_user_id"],
                status=conn["status"],
                created_at=conn["created_at"],
                to_user=user_to_response(to_user)
            ))
    return result

@api_router.put("/connections/{connection_id}/accept")
async def accept_connection(connection_id: str, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    connection = await db.connections.find_one({"_id": ObjectId(connection_id)})
    
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    if connection["to_user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    await db.connections.update_one(
        {"_id": ObjectId(connection_id)},
        {"$set": {"status": "accepted"}}
    )
    
    # Add to both users' connections list
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$addToSet": {"connections": connection["from_user_id"]}}
    )
    await db.users.update_one(
        {"_id": ObjectId(connection["from_user_id"])},
        {"$addToSet": {"connections": user_id}}
    )
    
    return {"message": "Connection accepted"}

@api_router.put("/connections/{connection_id}/reject")
async def reject_connection(connection_id: str, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    connection = await db.connections.find_one({"_id": ObjectId(connection_id)})
    
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    if connection["to_user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    await db.connections.delete_one({"_id": ObjectId(connection_id)})
    return {"message": "Connection rejected"}

@api_router.get("/connections/status/{user_id}")
async def get_connection_status(user_id: str, current_user: dict = Depends(get_current_user)):
    my_id = str(current_user["_id"])
    
    connection = await db.connections.find_one({
        "$or": [
            {"from_user_id": my_id, "to_user_id": user_id},
            {"from_user_id": user_id, "to_user_id": my_id}
        ]
    })
    
    if not connection:
        return {"status": "none", "connection_id": None}
    
    return {
        "status": connection["status"],
        "connection_id": str(connection["_id"]),
        "is_sender": connection["from_user_id"] == my_id
    }

# ==================== MESSAGE ENDPOINTS ====================

@api_router.post("/messages", response_model=MessageResponse)
async def send_message(message: MessageCreate, current_user: dict = Depends(get_current_user)):
    from_user_id = str(current_user["_id"])
    to_user_id = message.to_user_id
    
    # Check if users are connected
    connection = await db.connections.find_one({
        "status": "accepted",
        "$or": [
            {"from_user_id": from_user_id, "to_user_id": to_user_id},
            {"from_user_id": to_user_id, "to_user_id": from_user_id}
        ]
    })
    
    if not connection:
        raise HTTPException(status_code=403, detail="You must be connected to send messages")
    
    msg = {
        "from_user_id": from_user_id,
        "to_user_id": to_user_id,
        "content": message.content,
        "read": False,
        "created_at": datetime.utcnow()
    }
    result = await db.messages.insert_one(msg)
    msg["_id"] = result.inserted_id
    
    # Emit socket event for real-time
    await sio.emit(f'message_{to_user_id}', {
        "id": str(msg["_id"]),
        "from_user_id": from_user_id,
        "to_user_id": to_user_id,
        "content": message.content,
        "read": False,
        "created_at": msg["created_at"].isoformat()
    })
    
    return MessageResponse(
        id=str(msg["_id"]),
        from_user_id=from_user_id,
        to_user_id=to_user_id,
        content=message.content,
        read=False,
        created_at=msg["created_at"],
        from_user=user_to_response(current_user)
    )

@api_router.get("/messages/{user_id}", response_model=List[MessageResponse])
async def get_messages(user_id: str, current_user: dict = Depends(get_current_user)):
    my_id = str(current_user["_id"])
    
    messages = await db.messages.find({
        "$or": [
            {"from_user_id": my_id, "to_user_id": user_id},
            {"from_user_id": user_id, "to_user_id": my_id}
        ]
    }).sort("created_at", 1).to_list(1000)
    
    # Mark messages as read
    await db.messages.update_many(
        {"from_user_id": user_id, "to_user_id": my_id, "read": False},
        {"$set": {"read": True}}
    )
    
    result = []
    for msg in messages:
        from_user = await db.users.find_one({"_id": ObjectId(msg["from_user_id"])})
        result.append(MessageResponse(
            id=str(msg["_id"]),
            from_user_id=msg["from_user_id"],
            to_user_id=msg["to_user_id"],
            content=msg["content"],
            read=msg.get("read", False),
            created_at=msg["created_at"],
            from_user=user_to_response(from_user) if from_user else None
        ))
    return result

@api_router.get("/conversations", response_model=List[ConversationResponse])
async def get_conversations(current_user: dict = Depends(get_current_user)):
    my_id = str(current_user["_id"])
    
    # Get all connections
    connections = await db.connections.find({
        "status": "accepted",
        "$or": [
            {"from_user_id": my_id},
            {"to_user_id": my_id}
        ]
    }).to_list(1000)
    
    result = []
    for conn in connections:
        other_user_id = conn["to_user_id"] if conn["from_user_id"] == my_id else conn["from_user_id"]
        other_user = await db.users.find_one({"_id": ObjectId(other_user_id)})
        
        if other_user:
            # Get last message
            last_msg = await db.messages.find_one(
                {"$or": [
                    {"from_user_id": my_id, "to_user_id": other_user_id},
                    {"from_user_id": other_user_id, "to_user_id": my_id}
                ]},
                sort=[("created_at", -1)]
            )
            
            # Get unread count
            unread_count = await db.messages.count_documents({
                "from_user_id": other_user_id,
                "to_user_id": my_id,
                "read": False
            })
            
            result.append(ConversationResponse(
                user=user_to_response(other_user),
                last_message=MessageResponse(
                    id=str(last_msg["_id"]),
                    from_user_id=last_msg["from_user_id"],
                    to_user_id=last_msg["to_user_id"],
                    content=last_msg["content"],
                    read=last_msg.get("read", False),
                    created_at=last_msg["created_at"]
                ) if last_msg else None,
                unread_count=unread_count
            ))
    
    # Sort by last message time
    result.sort(key=lambda x: x.last_message.created_at if x.last_message else datetime.min, reverse=True)
    return result

# ==================== EVENT ENDPOINTS ====================

@api_router.get("/event")
async def get_event_details():
    return {
        "name": "Qatar Education Expo 2026",
        "tagline": "Join the Region's Most Impactful Education Expo",
        "dates": "April 18-19, 2026",
        "venue": {
            "name": "Sheraton Grand Doha Resort & Convention Hotel",
            "address": "Doha, Qatar",
            "map_url": ""
        },
        "organizer": "Student Diwan",
        "stats": {
            "attendees": "4,000+",
            "universities": "80+",
            "speakers": "120+",
            "exhibitors": "80+",
            "partners": "20+",
            "countries": "25+"
        },
        "description": "Qatar Education Expo 2026 is the leading international education expo and university fair in the GCC. A premier platform for study abroad options in the Middle East, meet top universities, and discover your future.",
        "schedule": [
            {
                "day": "Day 1 - April 18, 2026",
                "events": [
                    {"time": "09:00 - 10:00", "title": "Registration & Welcome", "location": "Main Hall"},
                    {"time": "10:00 - 11:00", "title": "Opening Ceremony & Keynote", "location": "Grand Ballroom"},
                    {"time": "11:00 - 13:00", "title": "Exhibition & Networking", "location": "Exhibition Hall"},
                    {"time": "13:00 - 14:00", "title": "Lunch Break", "location": "Dining Area"},
                    {"time": "14:00 - 16:00", "title": "Panel Discussions", "location": "Conference Rooms"},
                    {"time": "16:00 - 18:00", "title": "University Fair", "location": "Exhibition Hall"}
                ]
            },
            {
                "day": "Day 2 - April 19, 2026",
                "events": [
                    {"time": "09:00 - 10:00", "title": "Networking Breakfast", "location": "Dining Area"},
                    {"time": "10:00 - 12:00", "title": "Workshops & Seminars", "location": "Conference Rooms"},
                    {"time": "12:00 - 14:00", "title": "Exhibition & One-on-One Sessions", "location": "Exhibition Hall"},
                    {"time": "14:00 - 15:00", "title": "Lunch Break", "location": "Dining Area"},
                    {"time": "15:00 - 17:00", "title": "Career Counseling Sessions", "location": "Meeting Rooms"},
                    {"time": "17:00 - 18:00", "title": "Closing Ceremony & Awards", "location": "Grand Ballroom"}
                ]
            }
        ]
    }

@api_router.get("/speakers")
async def get_speakers():
    return [
        {
            "id": "1",
            "name": "Maya Ezzo",
            "position": "Principal",
            "organization": "English Modern School",
            "image": "https://res.cloudinary.com/dj3vhocuf/image/upload/f_auto,q_auto/v1767349743/Untitled_design_-_2026-01-02T155850.918_ofboxy.webp",
            "linkedin": ""
        },
        {
            "id": "2",
            "name": "Amer Bazerbachi",
            "position": "Partner",
            "organization": "KPMG",
            "topic": "Business & Finance",
            "image": "https://res.cloudinary.com/dj3vhocuf/image/upload/f_auto,q_auto/v1761477009/Untitled_design_-_2025-10-26T163955.545_ufmkhs.webp",
            "linkedin": "https://www.linkedin.com/in/amer-bazerbachi/"
        },
        {
            "id": "3",
            "name": "Michael Trick",
            "position": "Dean",
            "organization": "Carnegie Mellon University in Doha",
            "image": "https://res.cloudinary.com/dj3vhocuf/image/upload/f_auto,q_auto/v1768164193/Untitled_design_-_2026-01-12T021223.118_cqr8rh.webp",
            "linkedin": "https://www.linkedin.com/in/michael-trick-a101b71/"
        },
        {
            "id": "4",
            "name": "Dr Shaker Lashuel",
            "position": "Executive Director",
            "organization": "Global Studies Institute - Arkansas State University-Qatar",
            "topic": "Assessment & Analytics",
            "image": "https://res.cloudinary.com/dj3vhocuf/image/upload/f_auto,q_auto/v1768168509/Gemini_Generated_Image_bfu391bfu391bfu3_bxe9sp.webp",
            "linkedin": "https://www.linkedin.com/in/shaker-lashuel-8646985"
        },
        {
            "id": "5",
            "name": "Dr. Mirela-Dana Palimariu",
            "position": "Founding Director",
            "organization": "Little-Montessori-School",
            "topic": "Education Leadership",
            "image": "https://res.cloudinary.com/dj3vhocuf/image/upload/f_auto,q_auto/v1761476343/Untitled_design_-_2025-10-26T162847.853_geyb8t.webp",
            "linkedin": "https://www.linkedin.com/in/dr-mirela-dana-palimariu-phd-86132b4a/"
        },
        {
            "id": "6",
            "name": "Mrs Natasha Hilton",
            "position": "Vice Principal",
            "organization": "Park House English School",
            "image": "https://res.cloudinary.com/dj3vhocuf/image/upload/f_auto,q_auto/v1768153586/Untitled_design_-_2026-01-11T230542.858_axk4eh.webp",
            "linkedin": "https://www.linkedin.com/in/natasha-hilton-27802871/"
        },
        {
            "id": "7",
            "name": "Riyam B Chaar",
            "position": "Vice Principal",
            "organization": "Heritage International Academy",
            "topic": "Student Development",
            "image": "https://res.cloudinary.com/dj3vhocuf/image/upload/f_auto,q_auto/v1767348710/Untitled_design_-_2026-01-02T154136.698_mtg0vb.webp",
            "linkedin": "https://www.linkedin.com/in/riyam-chaar-65691a275"
        },
        {
            "id": "8",
            "name": "Dr Riz Pirzada",
            "position": "Programme Leader",
            "organization": "QFBA-Northumbria University",
            "topic": "AI in Education",
            "image": "https://res.cloudinary.com/dj3vhocuf/image/upload/f_auto,q_auto/v1767344398/1660474818703_ghwvng.webp",
            "linkedin": "https://www.linkedin.com/in/rizpirzada/"
        }
    ]

# ==================== ADMIN ENDPOINTS (for creating users) ====================

@api_router.post("/admin/users", response_model=UserResponse)
async def create_user(user: UserCreate):
    # Check if email already exists
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_dict = user.dict()
    user_dict["password"] = hash_password(user.password)
    user_dict["connections"] = []
    user_dict["created_at"] = datetime.utcnow()
    
    result = await db.users.insert_one(user_dict)
    user_dict["_id"] = result.inserted_id
    
    return user_to_response(user_dict)

# Root endpoint
@api_router.get("/")
async def root():
    return {"message": "EduExpo Qatar API", "version": "1.0"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Socket.IO events
@sio.event
async def connect(sid, environ):
    logger.info(f"Client connected: {sid}")

@sio.event
async def disconnect(sid):
    logger.info(f"Client disconnected: {sid}")

@sio.event
async def join_room(sid, data):
    room = data.get('user_id')
    if room:
        sio.enter_room(sid, room)
        logger.info(f"Client {sid} joined room {room}")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# For running with Socket.IO
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(socket_app, host="0.0.0.0", port=8001)
