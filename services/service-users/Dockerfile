FROM python:3.11-slim

WORKDIR /app

# Установка зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование кода приложения
COPY ./app /app/app

# *** ИСПРАВЛЕНИЕ: ДОБАВЛЕНИЕ EXPOSE ***
# Сообщаем Docker и Render, что приложение слушает порт 8000
EXPOSE 8000

# Команда запуска Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
