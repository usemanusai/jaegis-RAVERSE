## 2025-10-25 - Fix execute_query returning None in DatabaseManager
**Learning:** `DatabaseManager.execute_query` was implemented without a return value, causing silent failures/cache misses in components depending on it like `MultiLevelCache` (L3 postgres caching) and `SemanticSearchEngine`. A method executing arbitrary queries needs to handle fetching and returning results when applicable (e.g. SELECT, RETURNING).
**Action:** When working on generic database execution methods, make sure to consider if the method needs to fetch and return data. Ensure methods like `execute_query` handle cursor descriptions to return `fetchall()` data appropriately, ideally using `RealDictCursor` for dictionary mapping to avoid unpacking issues in downstream consumers.
## 2025-10-25 - N+1 Query in Vector Embeddings Insert
**Learning:** Inserting multiple embeddings via a loop with individual INSERT RETURNING statements caused an N+1 query problem, slowing down batch processing.
**Action:** Use `psycopg2.extras.execute_values` to send a single multi-row INSERT statement for batched database operations.
