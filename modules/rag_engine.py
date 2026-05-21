# modules/rag_engine.py
import chromadb
from chromadb.utils import embedding_functions
from pathlib import Path
from datetime import datetime

class RAGEngine:
    def __init__(self):
        self.db_path = Path("knowledge_base/chroma")
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        # Faster embedding model
        self.embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        
        self.client = chromadb.PersistentClient(path=str(self.db_path))
        
        self.collection = self.client.get_or_create_collection(
            name="whisperward_cases",
            embedding_function=self.embedding_function,
            metadata={"hnsw:space": "cosine"}   # Better similarity search
        )

    def add_case_data(self, case_id: str, target_id: int, documents: list, metadata: dict = None):
        """Add documents to knowledge base"""
        if not documents:
            return

        ids = [f"{case_id}_{target_id}_{i}" for i in range(len(documents))]
        
        metadatas = [metadata or {"case_id": case_id, "target_id": str(target_id)} for _ in documents]

        self.collection.add(
            documents=documents,
            ids=ids,
            metadatas=metadatas
        )
        print(f"    ✅ RAG: Stored {len(documents)} documents for case {case_id}")

    def query(self, query_text: str, n_results: int = 5, case_id: str = None):
        """Optimized semantic search"""
        try:
            if case_id:
                # Filter by case for better relevance and speed
                results = self.collection.query(
                    query_texts=[query_text],
                    n_results=n_results,
                    where={"case_id": case_id},
                    include=["documents", "metadatas"]
                )
            else:
                results = self.collection.query(
                    query_texts=[query_text],
                    n_results=n_results,
                    include=["documents", "metadatas"]
                )
            return results
        except Exception as e:
            print(f"    ⚠️ RAG query error: {e}")
            return {"documents": [[]], "metadatas": [[]]}

    def get_case_context(self, case_id: str, limit: int = 8):
        """Get all relevant context for a specific case"""
        try:
            results = self.collection.get(
                where={"case_id": case_id},
                limit=limit
            )
            return results.get("documents", [])
        except:
            return []