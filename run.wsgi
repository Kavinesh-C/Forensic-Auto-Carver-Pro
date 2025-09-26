import sys
import os

# Add your project's directory to the Python path
project_home = os.path.dirname(os.path.abspath(__file__))
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Import your app and the patch module
import app as orig_app
import fast_patch

# Apply the optimizations (hashing, carving, strings, deleted-scan)
fast_patch.apply_monkey_patches()

# Expose the Flask app object to Apache
application = orig_app.app
