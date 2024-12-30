from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Annotated
from fastapi.middleware.cors import CORSMiddleware
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jwt.exceptions import InvalidTokenError

app = FastAPI()

SECRET_KEY = "202354ebc91097d85a22f02ec4569d66ed4fe716227c42e505e3b54c9bf7b130"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://frontend-ledger.vercel.app"], 
    allow_credentials=True, 
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Welcome to FastAPI Hello"}

models.Base.metadata.create_all(bind=engine)

class ChoiceBase(BaseModel):
    choice_text: str
    is_correct: bool

class QuestionBase(BaseModel):
    question_text: str
    choices: List[ChoiceBase]
    
class Answer(BaseModel):
    question_id: int
    choice_id: int
    
class LoginRequest(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: str | None = None

class UserInDB(User):
    hashed_password: str
    
# Utility Functions
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()
    
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency = Annotated[Session, Depends(get_db)]

@app.post("/questions/")
async def create_questions(question: QuestionBase, db: db_dependency):
    db_question = models.Questions(question_text=question.question_text)
    db.add(db_question)
    db.commit()
    db.refresh(db_question)
    for choice in question.choices:
        db_choice = models.Choices(choice_text=choice.choice_text, is_correct=choice.is_correct, question_id=db_question.id)
        db.add(db_choice)
    db.commit()
    
@app.get("/questions")
def read_questions(db: Session = Depends(get_db)):
    questions = db.query(models.Questions).all()
    results = []
    for question in questions:
        choices = db.query(models.Choices).filter(models.Choices.question_id == question.id).all()
        results.append({
            "id": question.id,
            "question_text": question.question_text,
            "choices": [{"id": c.id, "choice_text": c.choice_text, "is_correct": c.is_correct} for c in choices]
        })
    return results

@app.get("/choices/{question_id}")
async def read_choices(question_id:int, db: db_dependency):
    result = db.query(models.Choices).filter(models.Choices.question_id == question_id).all()
    if not result:
        raise HTTPException(status_code=404, detail='Choices is not found')
    return result

@app.post("/submit-answers")
async def submit_answers(answers: List[Answer], db: db_dependency):
    for answer in answers:
        db_answer = models.Answers(
            question_id=answer.question_id,
            choice_id=answer.choice_id
        )
        db.add(db_answer)
    db.commit()
    return {"message": "Answers saved successfully"}

@app.post("/check-answers")
async def check_answers(answers: List[Answer], db: db_dependency):
    results = []
    
    for answer in answers:
        # Check if the selected choice is correct
        choice = db.query(models.Choices).filter(models.Choices.id == answer.choice_id).first()
        if choice is None:
            raise HTTPException(status_code=404, detail=f"Choice {answer.choice_id} not found.")
        
        # Get the correct answer for the question
        correct_choice = db.query(models.Choices).filter(
            models.Choices.question_id == answer.question_id, 
            models.Choices.is_correct == True
        ).first()
        
        if correct_choice is None:
            raise HTTPException(status_code=404, detail=f"No correct choice found for question {answer.question_id}.")
        
        # Compare the selected choice with the correct answer
        is_correct = choice.id == correct_choice.id
        
        # Store the result for the user
        results.append({
            "question_id": answer.question_id,
            "selected_choice": choice.choice_text,
            "correct_choice": correct_choice.choice_text,
            "is_correct": is_correct
        })
    
    return {"results": results}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # OAuth2PasswordRequestForm provides `username` and `password`
    user = get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


# Assuming you already have a database connection setup like get_db, get_user_by_email, etc.

@app.post("/register")
def register(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # Check if the email already exists
    existing_user = get_user_by_email(db, email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the password before saving
    hashed_password = get_password_hash(password)

    # Create the new user
    new_user = models.User(email=email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully"}