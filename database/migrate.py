#!/usr/bin/env python3
"""
Скрипт для выполнения SQL миграций базы данных
"""
import asyncio
import sys
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.logging import setup_logging
from database.connection import db_connection


async def run_migrations():
    """Выполнить все SQL миграции"""
    setup_logging()
    
    try:
        # Подключаемся к БД
        print("Connecting to database...")
        await db_connection.connect()
        
        # Читаем и выполняем миграции
        migrations_dir = Path(__file__).parent / "migrations"
        
        for migration_file in sorted(migrations_dir.glob("*.sql")):
            print(f"Running migration: {migration_file.name}")
            
            with open(migration_file, 'r') as f:
                sql = f.read()
            
            await db_connection.execute_migration(sql)
            print(f"✓ {migration_file.name} completed")
        
        print("\nAll migrations completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {str(e)}")
        sys.exit(1)
    finally:
        await db_connection.disconnect()


if __name__ == "__main__":
    asyncio.run(run_migrations())