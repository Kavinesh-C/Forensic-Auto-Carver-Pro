import sys
import os
import traceback

# Minimal, robust WSGI loader for Apache/mod_wsgi. Keeps import-time side-effects
# to a minimum and performs best-effort diagnostics to files so the developer
# can inspect problems without introducing complex dispatching logic here.

# Add project directory to Python path
project_home = os.path.dirname(os.path.abspath(__file__))
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Ensure logs directory exists
logs_dir = os.path.join(project_home, 'logs')
os.makedirs(logs_dir, exist_ok=True)

_log_path = os.path.join(logs_dir, 'wsgi_import_errors.log')

try:
    # Import the application module and optional fast_patch
    import app as orig_app
    try:
        import fast_patch
    except Exception:
        # fast_patch is optional; log and continue
        with open(_log_path, 'a', encoding='utf-8') as _f:
            _f.write('\n' + '='*80 + '\n')
            _f.write('fast_patch import failed:\n')
            _f.write(traceback.format_exc())

    # Apply monkey patches if available
    try:
        if 'fast_patch' in globals():
            fast_patch.apply_monkey_patches()
    except Exception:
        with open(_log_path, 'a', encoding='utf-8') as _f:
            _f.write('\n' + '='*80 + '\n')
            _f.write('fast_patch.apply_monkey_patches() raised an exception:\n')
            _f.write(traceback.format_exc())

    # Expose the Flask WSGI application object
    application = getattr(orig_app, 'app', None)
    if application is None:
        raise RuntimeError('Imported app module does not define "app" (Flask instance)')

    # Write lightweight diagnostics: module file and url rules (best-effort)
    try:
        _info_path = os.path.join(logs_dir, 'run_imported_app_file.log')
        with open(_info_path, 'a', encoding='utf-8') as _f:
            _f.write('\n' + '='*80 + '\n')
            _f.write(f'Imported app module file: {getattr(orig_app, "__file__", "<unknown>")}\n')
            try:
                for rule in getattr(orig_app.app, 'url_map', []).iter_rules():
                    _f.write(f"{list(rule.methods)} {rule.rule} -> {rule.endpoint}\n")
            except Exception as _e:
                _f.write('Error enumerating url_map: ' + str(_e) + '\n')
    except Exception:
        # Best-effort; do not break application startup
        pass

    # Also write a simple WSGI loaded log with timestamp
    try:
        _loaded_log = os.path.join(logs_dir, 'wsgi_loaded.log')
        from datetime import datetime
        with open(_loaded_log, 'a', encoding='utf-8') as _lf:
            _lf.write('\n' + '='*80 + '\n')
            _lf.write(f'WSGI loaded at: {repr(datetime.now())}\n')
    except Exception:
        pass

except Exception:
    # If importing the app failed, write the full traceback to the log file
    with open(_log_path, 'a', encoding='utf-8') as _f:
        _f.write('\n' + '='*80 + '\n')
        _f.write('WSGI import failure (when loading run.wsgi):\n')
        _f.write(traceback.format_exc())
    # Re-raise so Apache/mod_wsgi can capture the error
    raise
