'Libraries used :'
'time : used for stopping the scrolling using time.sleep'
'pyautogui : python library used for controlling the mouse and keyboard via code'
import time
import pyautogui

'scroll_down :'
'using the scroll method from pyautogui simulates a scroll down input simulating a real user'
def scroll_down():
    pyautogui.scroll(-200)

'Main Execution'
'scrolling action is controled in a loop' \
'while True : infinite loop until a keyboard interrupt'
if __name__ == "__main__":
    try:
        while True:
            'start_time = time.time : records current time'
            start_time = time.time()
            while time.time() - start_time < 1:
                'while time.time() - start_time < 1 : checking the start_time and time difference'
                scroll_down()
                time.sleep(0.1)
                'time.sleep(0.1) : used for controlling scrolling action, the movement wasnt right'

            time.sleep(3)
            'time.sleep(3) : delay between scrolls'

    except KeyboardInterrupt:
        print("\nScrolling stopped.")
