from dataclasses import Field
from fastapi import Depends, FastAPI, Request, Form, HTTPException,Header,Security,Depends,Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel,Field
from auth.jwt_handler import signJWT
from auth.jwt_handler import decodeJWT
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from starlette.responses import JSONResponse
from typing import Optional
MIN_TOKEN_LENGTH=50

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Database Configuration
DATABASE_URL = "postgresql://postgres:root@localhost:5432/login"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Define your database model
class AuthModel(Base):
    __tablename__ = "auth"
    userid = Column(String(256), primary_key=True)
    pas = Column(String(256))

Base.metadata.create_all(bind=engine)



class EmpModel(Base):
    __tablename__ = "employee"
    empname = Column(String(256), primary_key=True)
    empid = Column(String(256))
    empage = Column(String(256))
    empsalaray = Column(String(256))

Base.metadata.create_all(bind=engine)


class EmpRegistration(BaseModel):
    employeename: str
    employeeid: str
    employeeage: str
    employeesalary: str


# Pydantic model for user registration
class UserRegistration(BaseModel):
    username: str
    password: str
    repeat_password: str


class UserSchema(BaseModel):
    name: str= Field(default=None)
    password :str=Field(default=None)
    class config:
        the_schema={
            "user_demo":{
                "name":"Akash",
                "password":"123"
            }
        }

class UserLoginSchema(BaseModel):
    name :str =Field(default=None)
    password :str=Field(default=None)
    class config:
        the_schema={
            "user_demo":{
                "name":"admin",
                "password":"admin"
            }
        }

class UserLoginJSON(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None



async def get_current_user(token: str = Depends(decodeJWT)):
    if not token:
        raise HTTPException(status_code=401, detail="Invalid token")
    return token


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



# Dependency to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# @app.get("/")
# async def root(request: Request):
#     return {"Welcome to the page"}



@app.post("/submitted", tags=["user"], response_model=dict)
async def login_user(
    user_data: UserLoginJSON = None,
    authorization: str = Header(...),  # Require the Authorization header
    db: Session = Depends(get_db),
):
    # Check if the Authorization header is in the correct format
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token format in Authorization header")

    # Extract the token value
    token_value = authorization[len("Bearer "):].strip()

    # Validate the token length
    if len(token_value) < MIN_TOKEN_LENGTH:
        raise HTTPException(status_code=401, detail="Invalid token length")

    try:
        # Validate the token
        current_user = get_current_user(token_value)

        # If the token is valid, return a message
        return {"message": "Successful Login!!!"}
    except HTTPException as e:
        # If there is an exception, handle it
        if e.status_code == 401:
            # If it's a 401 status code, return a message indicating no access
            raise HTTPException(status_code=401, detail="No access to login")
        else:
            # Otherwise, re-raise the exception
            raise
@app.post("/register", tags=["user"], response_model=dict)
async def register_user(
    user_data: UserRegistration,  # Use the modified model for JSON data
    db: Session = Depends(get_db)
):
    existing_user = db.query(AuthModel).filter(AuthModel.userid == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    if user_data.password != user_data.repeat_password:
        raise HTTPException(status_code=400, detail="Password and Repeat password do not match")

    new_user = AuthModel(userid=user_data.username, pas=user_data.password)
    db.add(new_user)
    db.commit()

    # Generate a JWT token for the registered user
    access_token = signJWT(new_user.userid)

    return {"message": "Registration successful", "access_token": access_token}










    

@app.post("/register_employee", tags=["employee"])
async def register_employee(
    user1: EmpRegistration,
    db: Session = Depends(get_db)
):
    # Check if an employee with the same employeeid already exists
    existing_employee = db.query(EmpModel).filter(EmpModel.empid == user1.employeeid).first()
    if existing_employee:
        return {"message": "Employee with the same ID already exists"}

    # If the employee doesn't exist, add them to the database
    new_employee = EmpModel(
        empname=user1.employeename,
        empid=user1.employeeid,
        empage=user1.employeeage,
        empsalaray=user1.employeesalary
    )
    db.add(new_employee)
    db.commit()

    # Generate and return the access token
    access_token = signJWT(user1.employeeid)
    return {"access_token": access_token, "message": "Employee registration successful"}



@app.delete("/delete_employee/{emp_id}", tags=["employee"])
async def delete_employee_data(emp_id: str, db: Session = Depends(get_db)):
    employee = db.query(EmpModel).filter(EmpModel.empid == emp_id).first()
    if employee:
        db.delete(employee)
        db.commit()
        return {"message": "Employee data deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Employee not found")

# Update get_employee_by_id endpoint
@app.get("/get_employee/{emp_id}", response_class=Response, tags=["employee"])
async def get_employee_by_id(emp_id: str, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="Access token is missing")

    # Your additional authorization logic can go here

    employee = db.query(EmpModel).filter(EmpModel.empid == emp_id).first()

    if employee:
        employee_data = {
            "empname": employee.empname,
            "empid": employee.empid,
            "empage": employee.empage,
            "empsalaray": employee.empsalaray,
        }
        return JSONResponse(content=employee_data)
    else:
        return JSONResponse(content={"message": "Employee not present"}, status_code=404)


@app.put("/update_employee/{emp_id}", tags=["employee"])
async def update_employee_details(emp_id: str, employee_data: EmpRegistration, db: Session = Depends(get_db)):
    # Check if the employee with the specified empid exists
    existing_employee = db.query(EmpModel).filter(EmpModel.empid == emp_id).first()
    if existing_employee:
        # Update the employee's data with the provided values
        existing_employee.empname = employee_data.employeename
        existing_employee.empage = employee_data.employeeage
        existing_employee.empsalaray = employee_data.employeesalary
        db.commit()
        return {"message": "Employee details updated successfully"}
    else:
        raise HTTPException(status_code=404, detail="Employee not found")