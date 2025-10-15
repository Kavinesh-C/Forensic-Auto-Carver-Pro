import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# The file to touch when a change is detected
WSGI_FILE = 'run.wsgi'
# The directory to watch for changes
WATCH_DIRECTORY = '.'

class ReloadHandler(FileSystemEventHandler):
    """Handles file system events to trigger a reload."""

    def on_any_event(self, event):
        # Only care about Python files
        if event.src_path.endswith('.py'):
            # Make sure both app.py and fast_patch.py changes reload Apache
            changed_file = os.path.basename(event.src_path)
            print(f"🐍 Change detected in: {changed_file}. Touching {WSGI_FILE} to reload server.")
            try:
                os.utime(WSGI_FILE, None)
            except Exception as e:
                print(f"Error touching WSGI file: {e}")

if __name__ == "__main__":
    event_handler = ReloadHandler()
    observer = Observer()
    
    # Watch the project directory recursively
    observer.schedule(event_handler, WATCH_DIRECTORY, recursive=True)
    
    print(f"🚀 Starting development watcher for directory: '{WATCH_DIRECTORY}'")
    print(f"Will touch '{WSGI_FILE}' on any .py file change (including fast_patch.py).")
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nWatcher stopped.")
    observer.join()
