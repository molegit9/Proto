import os
import asyncio
import pandas as pd
import chromadb
from chromadb.utils import embedding_functions
from tqdm import tqdm
from app.core.config import settings

collection = None

def init_vector_db(csv_path: str = None, sample_size: int = 10000):
    global collection
    
    db_path = settings.CHROMA_DB_PATH

    # Determine which CSV files to load
    csv_paths = []
    if csv_path is not None:
        csv_paths = [csv_path]
    else:
        if hasattr(settings, "RAG_DATASET_PATHS") and settings.RAG_DATASET_PATHS:
            csv_paths = settings.RAG_DATASET_PATHS
        else:
            csv_paths = [settings.RAG_DATASET_PATH]

    # Filter out non-existent files
    valid_csv_paths = [path for path in csv_paths if os.path.exists(path)]
    if not valid_csv_paths:
        print(f"Error: No valid datasets found in {csv_paths}. Skipping vector DB init.")
        return

    print(f"[1/4] Loading datasets from {valid_csv_paths}...")
    try:
        dfs = []
        for path in valid_csv_paths:
            df_temp = pd.read_csv(path)
            
            # Standardize columns:
            # We map 'text' -> 'content', 'phishing_type' -> 'source'
            if 'content' not in df_temp.columns and 'text' in df_temp.columns:
                df_temp = df_temp.rename(columns={'text': 'content'})
            
            if 'source' not in df_temp.columns and 'phishing_type' in df_temp.columns:
                df_temp = df_temp.rename(columns={'phishing_type': 'source'})
            elif 'source' not in df_temp.columns:
                df_temp['source'] = os.path.basename(path)
            
            # Drop null content
            df_temp = df_temp.dropna(subset=['content'])
            dfs.append(df_temp)
            print(f"[Info] Loaded {len(df_temp)} rows from {path}")

        if not dfs:
            print("Error: No data loaded. Skipping vector DB init.")
            return

        # Concatenate and reset index to ensure unique sequential index
        df = pd.concat(dfs, ignore_index=True)
        print(f"[Info] Total combined rows: {len(df)}")

        # Stratified sampling across label and source to ensure fair representation
        if len(df) > sample_size:
            print(f"[Info] Drawing a stratified sample of {sample_size} records...")
            groups = df.groupby(['label', 'source'])
            num_groups = groups.ngroups
            samples_per_group = max(1, sample_size // num_groups)
            
            sampled_indices = []
            for _, group in groups:
                sampled_indices.extend(group.sample(min(len(group), samples_per_group), random_state=42).index)
                
            df = df.loc[sampled_indices].reset_index(drop=True)
            print(f"[Info] Final sample size: {len(df)}")

        print("[2/4] Initializing Korean Embedding Model and ChromaDB...")
        emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="jhgan/ko-sroberta-multitask")
        
        client = chromadb.PersistentClient(path=db_path)
        collection = client.get_or_create_collection(name="security_texts", embedding_function=emb_fn)

        # Check if database has already been initialized
        is_initialized = False
        if collection.count() > 0:
            if csv_path is not None:
                # If specific path was provided (e.g. for testing), assume initialized
                is_initialized = True
            else:
                # Default behavior: verify if the new dataset (which has label "0") is indexed
                try:
                    res = collection.get(where={"label": "0"}, limit=1)
                    if res and res.get("ids"):
                        is_initialized = True
                except Exception as e:
                    print(f"[Warning] Failed to verify DB contents: {e}")

        if is_initialized:
            print(f"[3/4] Database already initialized! Skipping embedding. (Count: {collection.count()})")
            print(f"[4/4] Vector Database successfully loaded at {db_path}")
            return

        # If not fully initialized with the new dataset, recreate/clear the collection
        print("[Info] Re-initializing vector database to include all datasets...")
        try:
            client.delete_collection(name="security_texts")
        except Exception:
            pass
        collection = client.get_or_create_collection(name="security_texts", embedding_function=emb_fn)

        print("[3/4] Vectorizing texts into the database (this might take a few minutes)...")
        batch_size = 500
        total_batches = (len(df) // batch_size) + 1

        for i in tqdm(range(total_batches), desc="Processing Batches"):
            batch_df = df.iloc[i * batch_size : (i + 1) * batch_size]
            if batch_df.empty:
                break
            
            documents = batch_df['content'].astype(str).tolist()
            
            # Populate metadata dict with optional severity & confidence fields
            metadatas = []
            for _, row in batch_df.iterrows():
                meta = {
                    "label": str(row['label']),
                    "source": str(row.get('source', 'unknown')),
                }
                if 'severity' in row and pd.notna(row['severity']):
                    meta['severity'] = str(row['severity'])
                if 'confidence' in row and pd.notna(row['confidence']):
                    meta['confidence'] = str(row['confidence'])
                metadatas.append(meta)
                
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


async def query_rag_with_meta(
    text: str,
    n_results: int = 3,
    max_distance: float = 0.55,
) -> list[dict]:
    """
    RAG 검색 결과를 메타데이터(label, source, distance)와 함께 반환.
    - asyncio.to_thread()로 동기 CPU 임베딩(ko-sroberta)을 스레드풀로 분리하여
      FastAPI 이벤트 루프 블로킹을 원천 제거합니다.
    - max_distance 임계값 미만인 유의미한 유사 판례만 반환합니다.
    """
    global collection
    if collection is None or not text or not text.strip():
        return []

    def _sync_query():
        return collection.query(
            query_texts=[text],
            n_results=n_results,
            include=["documents", "metadatas", "distances"],
        )

    try:
        results = await asyncio.to_thread(_sync_query)
        if not (results and "documents" in results and results["documents"]):
            return []

        docs      = results["documents"][0]
        metas     = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        enriched = []
        for i, doc in enumerate(docs):
            meta = metas[i] if i < len(metas) else {}
            dist = float(distances[i]) if i < len(distances) else 1.0
            if max_distance is not None and dist > max_distance:
                continue
            enriched.append({
                "document": doc,
                "label":    str(meta.get("label", "unknown")),
                "source":   str(meta.get("source", "unknown")),
                "distance": round(dist, 4),
            })
        return enriched
    except Exception as e:
        print(f"RAG Query Error: {e}")
        return []
