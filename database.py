from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from motor.motor_asyncio import AsyncIOMotorClient
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base

DATABASE_URL = "postgresql://narathip1598:9ikwIhTrHhO7gfZZCt6qL8t9BBCOOHnA@dpg-ctobfjpopnds73fguf2g-a/quizapplication"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False,autoflush=False, bind=engine)
Base = declarative_base()

MONGO_URI = "mongodb+srv://Narathip1150z:Narathip1150z@cluster0.pmp1a.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = AsyncIOMotorClient(MONGO_URI)
db = client.note_ledger