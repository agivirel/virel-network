# 1. Базовый образ Python
FROM python:3.11-slim

# 2. Установка рабочей директории внутри контейнера
WORKDIR /app

# 3. Копирование файла зависимостей и их установка
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Копирование всего кода нашего приложения
COPY ./app /app/app

# 5. Порт, который "слушает" наше приложение
EXPOSE 8000

# 6. Команда для запуска. 
# --reload следит за изменениями кода (hot-reload)
# --host 0.0.0.0 делает его доступным извне контейнера
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]