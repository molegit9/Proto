from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    GEMINI_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    GMAIL_CREDENTIALS_PATH: str = ""
    DATABASE_URL: str = "sqlite:///./security_logs.db"
    RAG_DATASET_PATH: str = "./data/merged_security_dataset.csv"
    CHROMA_DB_PATH: str = "./chroma_db"

    class Config:
        env_file = ".env"

settings = Settings()
