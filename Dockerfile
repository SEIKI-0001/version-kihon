# 1) ベース
FROM python:3.11-slim

# 2) ランタイム環境
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# （任意）タイムゾーン系を使うなら tzdata を入れておくと楽
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && \
    rm -rf /var/lib/apt/lists/*

# 3) 作業ディレクトリ
WORKDIR /app

# 4) 依存
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# 5) アプリ本体
COPY app.py /app/app.py

# 6) 起動（$PORT を尊重する）
# shell 形式にして環境変数展開を有効化。--proxy-headers も付与。
CMD bash -lc 'exec uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080} --proxy-headers --log-level info'
