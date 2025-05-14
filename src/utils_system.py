#!/usr/bin/env python3
'''
Created on April 24, 2025

@author: 


# pip install NA
sudo apt install libheif-examples exiftool



'''


#======================================================================
#
def print_runtime(label=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            duration = time.perf_counter() - start
            name = label or func.__name__
            logger.info(f"[{name}] completed in {duration:.3f} seconds")
            return result
        return wrapper
    return decorator


_timer_state = {"last": None}

def start_timer(label):
    """
    Starts or resets the global timer.
    """
    logger.info(f"{label}")

    _timer_state["last"] = time.perf_counter()

def print_timer(label):
    """
    Prints elapsed time since last start or print, and resets the timer.
    """
    now = time.perf_counter()
    last = _timer_state.get("last")
    if last is None:
        logger.info(f"[{label}] timer not started")
    else:
        duration = now - last
        logger.info(f"[{label}] completed in {duration:.3f} seconds")
    _timer_state["last"] = now
