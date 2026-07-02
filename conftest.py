# Root conftest.py
# Its presence tells pytest to add the repository root to sys.path, so tests in
# tests/ can import the project modules (risk_engine, correlation_engine,
# modules.*, database.*) exactly as the application code does. Keep this file
# even though it is empty of fixtures.
