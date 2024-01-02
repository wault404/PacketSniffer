import time
import pyautogui

def scroll_down():
    pyautogui.scroll(-200)  # Scroll down

if __name__ == "__main__":
    try:
        while True:
            # Scroll for 1 second
            start_time = time.time()
            while time.time() - start_time < 1:
                scroll_down()
                time.sleep(0.1)  # Adjust sleep duration if needed

            # Stop for 3 seconds
            time.sleep(3)

    except KeyboardInterrupt:
        print("\nScrolling stopped.")
