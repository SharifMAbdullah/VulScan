import json
from sentence_transformers import SentenceTransformer
import faiss
import os

class VectorIndex:
    def __init__(self, index_path="index", model_name="all-MiniLM-L6-v2"):
        self.index_path = index_path
        self.model = SentenceTransformer(model_name)

        if os.path.exists(index_path):
            self.index = faiss.read_index(index_path)
            with open(f"{index_path}_metadata.json", "r") as f:
                self.metadata = json.load(f)
        else:
            self.index = faiss.IndexFlatL2(384)  # Embedding dimensions
            self.metadata = []

    def add_to_index(self, data):
        """
        Add new data to the index. Data should be a list of dictionaries:
        {'text': ..., 'metadata': ...}.
        """
        texts = [item["text"] for item in data]
        embeddings = self.model.encode(texts, show_progress_bar=True)
        self.index.add(embeddings)
        self.metadata.extend([item["metadata"] for item in data])

    def search(self, query, top_k=5):
        """
        Search the index for the top_k most relevant matches.
        """
        query_embedding = self.model.encode([query])
        distances, indices = self.index.search(query_embedding, top_k)
        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx < len(self.metadata):
                results.append({"metadata": self.metadata[idx], "distance": dist})
        return results

    def save_index(self):
        faiss.write_index(self.index, self.index_path)
        with open(f"{self.index_path}_metadata.json", "w") as f:
            json.dump(self.metadata, f)

    def load_kb_to_index(self, kb_path):
        """
        Load knowledge base (KB.json) and index it based on `func_before`.
        """
        with open(kb_path, "r") as f:
            knowledge_base = json.load(f)

        data = []
        for item in knowledge_base:
            data.append({
                "text": item["func_before"],  # Function before fix
                "metadata": item  # Entire KB entry
            })
        self.add_to_index(data)
        self.save_index()
