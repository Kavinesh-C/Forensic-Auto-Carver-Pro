Running background worker and ephemeral test DBs

1) Start Redis (used by RQ worker)

- If you have Docker installed, you can use the included docker-compose to start Redis (and Postgres/Mongo for integration tests):

  docker-compose up -d redis

- Or install Redis locally and make it available as `redis://localhost:6379/0`.

2) Start an RQ worker to process upload jobs

- Install requirements (already in requirements.txt):

  python -m pip install -r requirements.txt

- Start the worker (from project root):

  # On PowerShell
  setx REDIS_URL "redis://localhost:6379/0"
  rq worker --url $env:REDIS_URL

3) Use the PowerShell helper to create ephemeral test DBs

  .\scripts\setup_test_dbs.ps1

It will print recommended environment variables to point pytest at the test DBs.

Notes
- The upload endpoint will enqueue large uploads (default threshold 10 MB) to the RQ queue specified by `EXPLORER_RQ_QUEUE` using the `REDIS_URL` environment variable or `redis://localhost:6379/0` by default.
- You can change the threshold via `app.config['EXPLORER_UPLOAD_ASYNC_THRESHOLD_BYTES']` in `app.py`.
