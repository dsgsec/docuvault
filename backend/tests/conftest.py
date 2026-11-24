import os

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["FILE_STORAGE_PATH"] = "test-files"
os.environ["SEED_DEMO"] = "false"
