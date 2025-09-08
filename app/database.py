from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

SQLALCHEMY_DATABASE_URL = "psql 'postgresql://neondb_owner:npg_7kFQ8VyTgmPh@ep-calm-sunset-adkilvcl-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'"


engine = create_engine(SQLALCHEMY_DATABASE_URL)

Sessionlocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = Sessionlocal()
    try:
        yield db
    finally:
        db.close()
