import keyboard
from keyboard import KeyboardEvent
import time


def test_keyboard(logger):
    def on_keypress(event: KeyboardEvent):
        logger.info("keyboard event!!!!")

    keyboard.on_press(callback=on_keypress)
    logger.info("Waiting 60sec for keypress events")
    time.sleep(60)
