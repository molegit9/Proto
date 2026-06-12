import os
import pandas as pd
import chromadb
from chromadb.utils import embedding_functions
from tqdm import tqdm
from app.core.config import settings

collection = None

def init_vector_db(csv_path: str = None, sample_size: int = 10000):
    global collection
    
    if csv_path is None:
        csv_path = settings.RAG_DATASET_PATH
        
    db_path = settings.CHROMA_DB_PATH

    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} not found. Skipping vector DB init.")
        return

    print(f"[1/4] Loading dataset from {csv_path}...")
    try:
        df = pd.read_csv(csv_path).dropna(subset=['content'])
        print(f"[Info] Total loaded rows: {len(df)}")

        if len(df) > sample_size:
            print(f"[Info] To prevent hours of indexing, drawing a stratified sample of {sample_size} records...")
            df = df.groupby('label', group_keys=False).apply(lambda x: x.sample(min(len(x), sample_size // 5), random_state=42))
            print(f"[Info] Final sample size: {len(df)}")

        print("[2/4] Initializing Korean Embedding Model and ChromaDB...")
        emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="jhgan/ko-sroberta-multitask")
        
        client = chromadb.PersistentClient(path=db_path)
        collection = client.get_or_create_collection(name="security_texts", embedding_function=emb_fn)

        # 이미 데이터가 들어가 있다면 벡터화 과정을 건너뜀 (서버 재시작 속도 대폭 향상)
        if collection.count() > 0:
            print(f"[3/4] Database already initialized! Skipping embedding. (Count: {collection.count()})")
            print(f"[4/4] Vector Database successfully loaded at {db_path}")
            return

        print("[3/4] Vectorizing texts into the database (this might take a few minutes)...")
        batch_size = 500
        total_batches = (len(df) // batch_size) + 1

        for i in tqdm(range(total_batches), desc="Processing Batches"):
            batch_df = df.iloc[i * batch_size : (i + 1) * batch_size]
            if batch_df.empty:
                break
            
            documents = batch_df['content'].astype(str).tolist()
            metadatas = [{"label": str(row['label']), "source": str(row.get('source', 'unknown'))} for _, row in batch_df.iterrows()]
            ids = [f"doc_{idx}" for idx in batch_df.index]
            
            collection.upsert(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )

        print(f"[4/4] Vector Database successfully initialized at {db_path}")
        print(f"Total documents inside DB: {collection.count()}")
    except Exception as e:
        print(f"Vector DB init error: {e}")

async def query_rag(text: str, n_results: int = 3) -> list[str]:
    """하위호환용: 문서 텍스트 리스트만 반환"""
    meta_result = await query_rag_with_meta(text, n_results)
    return [item["document"] for item in meta_result]


async def query_rag_with_meta(text: str, n_results: int = 3) -> list[dict]:
    """
    RAG 검색 결과를 메타데이터(label, source, distance)와 함께 반환.
    시연용 Done Criteria: 어떤 판례를 참조했는지 눈에 보이게 제공.
    반환 형식:
        [{"document": str, "label": str, "source": str, "distance": float}, ...]
    """
    global collection
    if collection is None:
        return []

    try:
        results = collection.query(
            query_texts=[text],
            n_results=n_results,
            include=["documents", "metadatas", "distances"],
        )
        if not (results and "documents" in results and results["documents"]):
            return []

        docs      = results["documents"][0]
        metas     = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        enriched = []
        for i, doc in enumerate(docs):
            meta = metas[i] if i < len(metas) else {}
            dist = distances[i] if i < len(distances) else 1.0
            enriched.append({
                "document": doc,
                "label":    str(meta.get("label", "unknown")),
                "source":   str(meta.get("source", "unknown")),
                "distance": round(float(dist), 4),
            })
        return enriched
    except Exception as e:
        print(f"RAG Query Error: {e}")
        return []
