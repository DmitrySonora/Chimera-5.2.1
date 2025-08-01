#!/usr/bin/env python3
"""
Быстрая проверка производительности PostgreSQL Event Store
Занимает ~1 минуту вместо полного стресс-теста
"""
import asyncio
import time
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from actors.events import BaseEvent, PostgresEventStore
from database.connection import db_connection
from config.logging import setup_logging


async def quick_performance_check():
    """Быстрая проверка ключевых метрик производительности"""
    
    print("\n🚀 PostgreSQL Event Store - Quick Performance Check")
    print("="*50)
    
    # Инициализация
    setup_logging()
    store = PostgresEventStore()
    await store.initialize()
    
    try:
        # Очистка тестовых данных
        await db_connection.execute("DELETE FROM events WHERE stream_id LIKE 'perf_check_%'")
        
        # 1. Проверка единичной записи
        print("\n1️⃣ Single Write Test (100 events)...")
        latencies = []
        
        for i in range(100):
            event = BaseEvent.create(
                stream_id="perf_check_single",
                event_type="PerfCheckEvent",
                data={"index": i, "timestamp": datetime.now().isoformat()},
                version=i
            )
            
            start = time.perf_counter()
            await store.append_event(event)
            latency = (time.perf_counter() - start) * 1000
            latencies.append(latency)
        
        await store._flush_buffer()
        avg_write = sum(latencies) / len(latencies)
        print(f"   Average write latency: {avg_write:.2f}ms")
        print(f"   Target: < 5ms {'✅ PASS' if avg_write < 5 else '❌ FAIL'}")
        
        # 2. Проверка батчевой записи
        print("\n2️⃣ Batch Write Test (10 batches x 100 events)...")
        batch_times = []
        
        for batch in range(10):
            start = time.perf_counter()
            
            for i in range(100):
                event = BaseEvent.create(
                    stream_id=f"perf_check_batch_{batch}",
                    event_type="BatchEvent",
                    data={"batch": batch, "index": i},
                    version=i
                )
                await store.append_event(event)
            
            await store._flush_buffer()
            batch_time = (time.perf_counter() - start) * 1000
            batch_times.append(batch_time)
        
        avg_batch = sum(batch_times) / len(batch_times)
        print(f"   Average batch flush time: {avg_batch:.2f}ms")
        print(f"   Target: < 50ms {'✅ PASS' if avg_batch < 50 else '❌ FAIL'}")
        
        # 3. Проверка чтения
        print("\n3️⃣ Read Test (100 events x 10 reads)...")
        read_times = []
        
        for i in range(10):
            start = time.perf_counter()
            events = await store.get_stream("perf_check_single")
            read_time = (time.perf_counter() - start) * 1000
            read_times.append(read_time)
        
        avg_read = sum(read_times) / len(read_times)
        print(f"   Average read latency: {avg_read:.2f}ms")
        print(f"   Events read: {len(events)}")
        print(f"   Target: < 10ms {'✅ PASS' if avg_read < 10 else '❌ FAIL'}")
        
        # 4. Проверка конкурентности
        print("\n4️⃣ Concurrency Test (10 parallel writers)...")
        
        async def concurrent_writer(writer_id: int):
            times = []
            for i in range(50):
                event = BaseEvent.create(
                    stream_id=f"perf_check_concurrent_{writer_id}",
                    event_type="ConcurrentEvent",
                    data={"writer": writer_id, "index": i},
                    version=i
                )
                
                start = time.perf_counter()
                await store.append_event(event)
                times.append((time.perf_counter() - start) * 1000)
            
            return sum(times) / len(times)
        
        start_concurrent = time.perf_counter()
        avg_latencies = await asyncio.gather(*[concurrent_writer(i) for i in range(10)])
        total_concurrent_time = time.perf_counter() - start_concurrent
        
        overall_avg = sum(avg_latencies) / len(avg_latencies)
        throughput = (10 * 50) / total_concurrent_time  # events/sec
        
        print(f"   Average concurrent write latency: {overall_avg:.2f}ms")
        print(f"   Throughput: {throughput:.0f} events/sec")
        print(f"   Target: > 1000 events/sec {'✅ PASS' if throughput > 1000 else '❌ FAIL'}")
        
        # 5. Метрики Event Store
        print("\n5️⃣ Event Store Metrics:")
        metrics = store.get_metrics()
        print(f"   Total appends: {metrics['total_appends']}")
        print(f"   Total reads: {metrics['total_reads']}")
        print(f"   Version conflicts: {metrics['version_conflicts']}")
        print(f"   Buffer size: {metrics['buffer_size']}")
        print(f"   Batch writes: {metrics['batch_writes']}")
        
        # Итоговая оценка
        print("\n" + "="*50)
        print("📊 SUMMARY:")
        
        all_pass = all([
            avg_write < 5,
            avg_batch < 50,
            avg_read < 10,
            throughput > 1000
        ])
        
        if all_pass:
            print("✅ All performance targets met!")
            print("   PostgreSQL Event Store is ready for production.")
        else:
            print("❌ Some performance targets not met.")
            print("   Review PostgreSQL configuration and hardware.")
        
    finally:
        # Очистка
        await db_connection.execute("DELETE FROM events WHERE stream_id LIKE 'perf_check_%'")
        await store.close()
        # НЕ закрываем db_connection


if __name__ == "__main__":
    import os
    
    if not os.getenv("POSTGRES_DSN"):
        print("❌ Error: POSTGRES_DSN environment variable not set")
        print("Set: export POSTGRES_DSN='postgresql://user:pass@localhost/db'")
        sys.exit(1)
    
    asyncio.run(quick_performance_check())