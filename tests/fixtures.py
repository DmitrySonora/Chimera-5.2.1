from typing import Optional

from actors.base_actor import BaseActor
from actors.messages import ActorMessage, MESSAGE_TYPES


class EchoActor(BaseActor):
    """Тестовый актор, который отвечает PONG на PING"""
    
    async def initialize(self):
        self.processed_count = 0
        self.logger.info("EchoActor initialized")
        
    async def shutdown(self):
        self.logger.info(f"EchoActor shutdown, processed {self.processed_count} messages")
        
    async def handle_message(self, message: ActorMessage) -> Optional[ActorMessage]:
        self.processed_count += 1
        
        if message.message_type == MESSAGE_TYPES['PING']:
            return ActorMessage.create(
                sender_id=self.actor_id,
                message_type=MESSAGE_TYPES['PONG'],
                payload={'echo': message.payload}
            )
        return None