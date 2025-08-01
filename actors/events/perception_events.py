"""
События для PerceptionActor и анализа эмоций
"""
from typing import List, Dict, Optional
from actors.events.base_event import BaseEvent


class EmotionDetectedEvent(BaseEvent):
    """Событие обнаружения эмоций в сообщении пользователя"""
    
    @classmethod
    def create(cls,
               user_id: str,
               dominant_emotions: List[str],
               emotion_scores: Dict[str, float],
               text_preview: str = "",
               correlation_id: Optional[str] = None) -> 'EmotionDetectedEvent':
        """
        Создать событие обнаружения эмоций
        
        Args:
            user_id: ID пользователя
            dominant_emotions: Топ-3 доминирующие эмоции
            emotion_scores: Полный вектор эмоций (28 значений)
            text_preview: Первые 50 символов текста
            correlation_id: ID корреляции
        """
        # Обрезаем превью текста
        text_preview = text_preview[:50] if text_preview else ""
        
        # Вычисляем эмоциональную интенсивность
        emotional_intensity = sum(emotion_scores.values()) if emotion_scores else 0.0
        
        return cls(
            stream_id=f"emotions_{user_id}",
            event_type="EmotionDetectedEvent",
            data={
                "user_id": user_id,
                "dominant_emotions": dominant_emotions,
                "emotion_scores": emotion_scores,
                "emotional_intensity": emotional_intensity,
                "text_preview": text_preview
            },
            version=0,  # Версия устанавливается EventVersionManager
            correlation_id=correlation_id
        )