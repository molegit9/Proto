from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    GEMINI_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    GMAIL_CREDENTIALS_PATH: str = ""
    DATABASE_URL: str = "sqlite:///./security_logs.db"
    RAG_DATASET_PATH: str = "./data/merged_security_dataset.csv"
    RAG_DATASET_PATHS: list[str] = [
        "./data/merged_security_dataset.csv",
        "./data/phishing_dataset.csv"
    ]
    CHROMA_DB_PATH: str = "./chroma_db"
    GEMINI_PRIMARY_MODEL: str = "gemini-3.5-flash-lite"
    GEMINI_SECONDARY_MODEL: str = "gemini-3.1-flash-lite"
    GEMINI_FALLBACK_MODEL: str = "gemma-4-31b-it"
    GEMINI_SUMMARY_MODEL: str = "gemma-4-31b-it"
    PLAYWRIGHT_USE_NEW_HEADLESS: bool = True
    PLAYWRIGHT_CAPTURE_SCREENSHOT: bool = True
    PLAYWRIGHT_MAX_CONCURRENT_CONTEXTS: int = 3

    class Config:
        env_file = ".env"

settings = Settings()
