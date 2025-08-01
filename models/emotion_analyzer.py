"""
Модуль для анализа эмоций в русскоязычных текстах с помощью DeBERTa-v1
"""
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from typing import List, Dict, Union, Optional
from config.logging import get_logger
from config.settings import (
    EMOTION_MODEL_NAME,
    EMOTION_MODEL_DEVICE,
    EMOTION_MODEL_CACHE_DIR,
    EMOTION_MODEL_MAX_LENGTH,
    EMOTION_LOG_PREDICTIONS,
    EMOTION_LOG_THRESHOLD,
    EMOTION_THRESHOLDS,
    EMOTION_LABELS,
    EMOTION_LABELS_RU
)


class EmotionAnalyzer:
    """
    Анализатор эмоций на основе DeBERTa-v1 для русского языка.
    Поддерживает 28 категорий эмоций с индивидуальными порогами.
    """
    
    def __init__(self, device: Optional[str] = None):
        """
        Инициализация анализатора с загрузкой модели.
        
        Args:
            device: Устройство для выполнения ('cpu' или 'cuda'). 
                   Если None, берется из конфига.
        """
        self.logger = get_logger("emotion_analyzer")
        self.device = device or EMOTION_MODEL_DEVICE
        
        # Проверка доступности CUDA
        if self.device == "cuda" and not torch.cuda.is_available():
            self.logger.warning("CUDA requested but not available, falling back to CPU")
            self.device = "cpu"
        
        self.logger.info(f"Initializing EmotionAnalyzer on {self.device}")
        
        try:
            # Загрузка токенизатора и модели
            self.tokenizer = AutoTokenizer.from_pretrained(
                EMOTION_MODEL_NAME,
                cache_dir=EMOTION_MODEL_CACHE_DIR
            )
            
            self.model = AutoModelForSequenceClassification.from_pretrained(
                EMOTION_MODEL_NAME,
                cache_dir=EMOTION_MODEL_CACHE_DIR
            )
            
            # Перемещение модели на устройство
            self.model = self.model.to(self.device)
            self.model.eval()  # Режим inference
            
            self.logger.info("EmotionAnalyzer initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load emotion model: {str(e)}")
            self.model = None
            self.tokenizer = None
            raise
    
    def analyze_text(self, text: str, return_all: bool = False) -> Union[List[str], Dict[str, float]]:
        """
        Анализирует эмоции в тексте.
        
        Args:
            text: Текст для анализа (автоматически обрезается до 128 токенов)
            return_all: Если True, возвращает все эмоции с вероятностями.
                       Если False, только превысившие индивидуальные пороги.
        
        Returns:
            При return_all=False: список доминирующих эмоций (строки)
            При return_all=True: словарь всех эмоций с вероятностями
            
        Examples:
            >>> analyzer = EmotionAnalyzer()
            >>> analyzer.analyze_text("Обожаю вашу кофейню!")
            ['admiration', 'love']
            >>> analyzer.analyze_text("Это отвратительно", return_all=True)
            {'admiration': 0.012, 'disgust': 0.823, ...}
        """
        if not self.model or not self.tokenizer:
            self.logger.error("Model not loaded, returning empty result")
            return [] if not return_all else {}
        
        try:
            # Токенизация с автоматической обрезкой
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=EMOTION_MODEL_MAX_LENGTH,
                padding=True
            )
            
            # Перемещение на устройство
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Получение предсказаний
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits[0]  # Берем первый элемент батча
                
                # Применяем sigmoid для получения вероятностей
                probabilities = torch.sigmoid(logits).cpu().numpy()
            
            # Формирование результата
            if return_all:
                # Возвращаем полный словарь
                result = {
                    label: round(float(prob), 3)
                    for label, prob in zip(EMOTION_LABELS, probabilities)
                }
            else:
                # Фильтруем по индивидуальным порогам
                detected_emotions = []
                for i, (label, prob, threshold) in enumerate(
                    zip(EMOTION_LABELS, probabilities, EMOTION_THRESHOLDS)
                ):
                    if prob > threshold:
                        detected_emotions.append((label, float(prob)))
                
                # Сортируем по убыванию вероятности
                detected_emotions.sort(key=lambda x: x[1], reverse=True)
                result = [emotion[0] for emotion in detected_emotions]
            
            # Логирование предсказаний если включено
            if EMOTION_LOG_PREDICTIONS and not return_all:
                high_prob_emotions = [
                    (label, prob) for label, prob in zip(EMOTION_LABELS, probabilities)
                    if prob > EMOTION_LOG_THRESHOLD
                ]
                if high_prob_emotions:
                    self.logger.debug(
                        f"Emotions for '{text[:50]}...': {high_prob_emotions}"
                    )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing text: {str(e)}")
            return [] if not return_all else {}
    
    def get_emotion_vector(self, text: str) -> Dict[str, float]:
        """
        Получает полный вектор эмоций для текста.
        
        Args:
            text: Текст для анализа
            
        Returns:
            Словарь из 28 эмоций с вероятностями (округлено до 3 знаков)
            
        Example:
            >>> analyzer = EmotionAnalyzer()
            >>> vector = analyzer.get_emotion_vector("Спасибо за помощь!")
            >>> vector['gratitude']
            0.756
        """
        return self.analyze_text(text, return_all=True)
    
    def get_russian_emotions(self, text: str) -> List[str]:
        """
        Анализирует эмоции и возвращает русские названия.
        
        Args:
            text: Текст для анализа
            
        Returns:
            Список доминирующих эмоций на русском языке
        """
        english_emotions = self.analyze_text(text, return_all=False)
        return [EMOTION_LABELS_RU.get(emotion, emotion) for emotion in english_emotions]