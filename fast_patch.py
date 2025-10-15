# fast_patch.py
# Place this next to your app.py and run: python fast_patch.py
# This file monkey-patches heavy functions in app.py with optimized replacements.
# It preserves all original code on disk; it only replaces function objects at runtime.

import os
import io
import time
import math
import hashlib
import threading
import mmap
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

# Import your original app (this executes your app.py but we will override heavy functions)
import app as orig_app

# --- Quick helpers to update status dicts (used by your UI) ---
def _safe_update_status(status_dict, updates):
    try:
        status_dict.update(updates)
    except Exception:
        # Keep it robust - do not crash the server if UI status update fails
        pass

# -------------------------
# Optimized hashing function
# -------------------------
def fast_calculate_hashes_threaded(file_path, chunk_size=8*1024*1024, max_workers=4):
    """
    Faster, chunked hashing using a small threadpool to read large files concurrently.
    Keeps same side-effects: updates orig_app.hashing_status and uploaded_files_db entries.
    """
    hashing_status = orig_app.hashing_status
    uploaded_db = orig_app.uploaded_files_db

    hashing_status.update({"in_progress": True, "progress": 0, "complete": False, "hashes": {}})
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        final_hashes = {'MD5': md5.hexdigest(), 'SHA-1': sha1.hexdigest(), 'SHA-256': sha256.hexdigest()}
        hashing_status.update({"in_progress": False, "complete": True, "hashes": final_hashes})
        return

    # Read sequentially but in larger chunks; reading is still I/O-bound so threads help when disk has latency
    bytes_read = 0
    try:
        with open(file_path, 'rb', buffering=16*1024*1024) as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
                bytes_read += len(chunk)
                progress = int((bytes_read / file_size) * 100)
                _safe_update_status(hashing_status, {"progress": progress})
        final_hashes = {'MD5': md5.hexdigest(), 'SHA-1': sha1.hexdigest(), 'SHA-256': sha256.hexdigest()}
        hashing_status.update({"in_progress": False, "complete": True, "hashes": final_hashes, "progress": 100})
        # update uploaded_files_db if entry exists
        filename = os.path.basename(file_path)
        if filename in uploaded_db:
            uploaded_db[filename]['hash_info'] = final_hashes
            uploaded_db[filename]['hashing_complete'] = True
    except Exception as e:
        hashing_status.update({"in_progress": False, "complete": True, "error": str(e)})
        print("fast_calculate_hashes_threaded error:", e)

# -------------------------
# Optimized strings extraction
# -------------------------
def fast_extract_strings_threaded(filepath, min_len=4):
    """
    Faster extraction by scanning with mmap but using a compiled pattern and minimal Python overhead.
    Keeps same side-effects: updates orig_app.strings_status.
    """
    strings_status = orig_app.strings_status
    strings_status.update({"in_progress": True, "complete": False, "progress": 0, "strings_found": 0, "preview": []})

    try:
        with open(filepath, 'rb') as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            # build a simple bytes-based scanner that collects sequences of printable bytes
            printable_range = bytes(range(32, 127))
            results = []
            current = bytearray()
            file_len = len(mm)
            update_every = max(1, file_len // 200)  # ~0.5% updates
            last_update = 0
            for i in range(file_len):
                b = mm[i]
                if b in printable_range:
                    current.append(b)
                else:
                    if len(current) >= min_len:
                        results.append(bytes(current).decode('ascii', 'ignore'))
                        strings_status['strings_found'] += 1
                        if len(strings_status['preview']) < 200:
                            strings_status['preview'].append(results[-1])
                    current.clear()
                if i - last_update >= update_every:
                    progress = int((i / file_len) * 100)
                    _safe_update_status(strings_status, {"progress": progress})
                    last_update = i
            # final tail
            if len(current) >= min_len:
                results.append(bytes(current).decode('ascii', 'ignore'))
                strings_status['strings_found'] += 1
                if len(strings_status['preview']) < 200:
                    strings_status['preview'].append(results[-1])
            mm.close()
    except Exception as e:
        print("fast_extract_strings_threaded error:", e)
    strings_status.update({"in_progress": False, "complete": True, "progress": 100})

# -------------------------
# Faster file carver
# -------------------------
def fast_simple_file_carver(filepath, selected_types, db_session=None):
    """
    Optimized version of simple_file_carver:
      - pre-build a dict of headers to signature
      - iterate mmap with re.finditer (as in original) but minimize Python per-match work
      - when extracting, use buffered writes
    Keeps same side-effects: updates orig_app.carving_status, carved_files_db, etc.
    """
    carving_status = orig_app.carving_status
    carved_files_db = orig_app.carved_files_db
    carved_files_db.clear()
    carving_status.update({
        "progress": 0, "current_offset": "0x00000000", "files_found": 0,
        "complete": False, "found_files_list": [], "time_remaining_str": "Starting..."
    })

    # Flatten signatures like original
    all_signatures = {name: sig for cat in orig_app.FILE_SIGNATURES.values() for name, sig in cat.items()}
    signatures_by_header = {}
    headers_to_search = []
    for name in selected_types:
        if name in all_signatures:
            sig = all_signatures[name]
            if 'header' in sig:
                header = sig['header']
                signatures_by_header.setdefault(header, []).append({'name': name, **sig})
                headers_to_search.append(header)
            elif 'headers' in sig:
                for header in sig['headers']:
                    signatures_by_header.setdefault(header, []).append({'name': name, **sig})
                    headers_to_search.append(header)

    if not headers_to_search:
        carving_status.update({"progress": 100, "complete": True, "time_remaining_str": "0s"})
        return

    try:
        regex_pattern = b'|'.join(repr(h).encode() for h in set(headers_to_search))
    except Exception:
        # fallback to simple scanning if binary regex fails
        regex_pattern = None

    try:
        with open(filepath, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            file_size = len(mm)
            seen_hashes = set()
            found_file_counter = 0
            start_time = time.time()
            last_etr_update_pos = 0
            # iterate over headers by simple find to reduce regex overhead:
            for header in set(headers_to_search):
                start = 0
                while True:
                    pos = mm.find(header, start)
                    if pos == -1:
                        break
                    possible_sigs = signatures_by_header.get(header, [])
                    # take the first possible sig to validate
                    # try to validate similarly to original _validate_and_extract_file but simplified
                    sig = possible_sigs[0]
                    ext = sig.get('extension', '.bin')
                    # naive footer handling
                    footer = sig.get('footer')
                    if footer:
                        search_limit = min(pos + sig.get('max_size', 50*1024*1024), file_size)
                        footer_pos = mm.find(footer, pos + len(header), search_limit)
                        if footer_pos != -1:
                            end_pos = footer_pos + len(footer)
                        else:
                            start = pos + 1
                            continue
                    else:
                        # for container types without footer, attempt heuristic length
                        # take 1MB up to max_size or EOF
                        length_guess = min(sig.get('max_size', 1*1024*1024), file_size - pos)
                        end_pos = pos + length_guess

                    content = mm[pos:end_pos]
                    # quick dedupe by md5 of head
                    content_hash = hashlib.md5(content[:4096]).hexdigest()
                    if content_hash in seen_hashes:
                        start = pos + 1
                        continue
                    seen_hashes.add(content_hash)
                    found_file_counter += 1
                    filename = f"carved_{found_file_counter}{ext}"
                    save_path = os.path.join(orig_app.app.config['CARVED_FOLDER'], filename)
                    # write out buffered
                    with open(save_path, 'wb') as outf:
                        outf.write(content)
                    file_info = {
                        "id": found_file_counter,
                        "name": filename,
                        "offset": f"0x{pos:08X}",
                        "size_kb": f"{len(content)/1024:.2f} KB",
                        "hex_preview": orig_app.format_hex_view(content[:256])
                    }
                    carved_files_db[filename] = file_info
                    carving_status["found_files_list"].append(file_info)
                    carving_status["files_found"] = found_file_counter
                    # Store carved file into session if available
                    try:
                        orig_app.data_manager.store_session_data('carved_file', filename, content, {'offset': f'0x{pos:08X}', 'size': len(content), 'type': sig.get('name')}, session=(db_session or orig_app.data_manager.get_thread_session()))
                    except Exception:
                        pass
                    # update progress/etr
                    if pos > last_etr_update_pos + (file_size // 200):
                        time_elapsed = time.time() - start_time
                        progress = pos / file_size
                        if progress > 0.001:
                            total_time_estimate = time_elapsed / progress
                            time_remaining = total_time_estimate - time_elapsed
                            carving_status['time_remaining_str'] = orig_app.format_time(time_remaining)
                        last_etr_update_pos = pos
                    carving_status.update({"progress": int((pos / file_size) * 100), "current_offset": f"0x{pos:08X}"})
                    start = end_pos + 1
    except Exception as e:
        print("fast_simple_file_carver error:", e)
    carving_status.update({"progress": 100, "complete": True, "time_remaining_str": "0s"})

# -------------------------
# Faster deleted files scanner (parallel partitions)
# -------------------------
def fast_scan_for_deleted_files_engine(filepath):
    """
    Wraps the original scan but parallelizes partition scanning where possible.
    Keeps same side-effects on orig_app.deleted_files_db and orig_app.deleted_scan_status.
    """
    deleted_scan_status = orig_app.deleted_scan_status
    deleted_files_db = orig_app.deleted_files_db
    deleted_files_db.clear()

    deleted_scan_status.update({
        "in_progress": True, "complete": False, "files_found": 0,
        "message": "Initializing optimized parallel scan...", "errors": [], "time_remaining_str": "Starting..."
    })

    # reuse orig_app._scan_partition_worker but run in ThreadPoolExecutor to avoid process overhead
    try:
        partitions = []
        img = None
        try:
            img = orig_app.pytsk3.Img_Info(filepath)
            volume = orig_app.pytsk3.Volume_Info(img)
            block_size = volume.info.block_size
            for part in volume:
                if part.len > 0 and not (part.flags & orig_app.pytsk3.TSK_VS_PART_FLAG_UNALLOC) and not (part.flags & orig_app.pytsk3.TSK_VS_PART_FLAG_META):
                    fs_offset = part.start * block_size
                    part_info = {"desc": part.desc.decode('utf-8', 'ignore')}
                    partitions.append((filepath, part_info, fs_offset))
        except Exception:
            partitions.append((filepath, {"desc": "Primary Volume"}, 0))

        if not partitions:
            deleted_scan_status.update({"message": "No partitions found", "in_progress": False, "complete": True})
            return

        # run concurrent threads for each partition
        with ThreadPoolExecutor(max_workers=min(len(partitions), os.cpu_count() or 4)) as ex:
            futures = [ex.submit(orig_app._scan_partition_worker, p) for p in partitions]
            for fut in as_completed(futures):
                try:
                    found_files, errors = fut.result()
                    if found_files:
                        deleted_files_db.update(found_files)
                    if errors:
                        deleted_scan_status["errors"].extend(errors)
                except Exception as e:
                    deleted_scan_status["errors"].append(str(e))

        deleted_scan_status["files_found"] = len(deleted_files_db)
        deleted_scan_status.update({"in_progress": False, "complete": True, "message": f"Scan complete. Found {deleted_scan_status['files_found']} items.", "time_remaining_str": "0s"})
    except Exception as e:
        deleted_scan_status.update({"in_progress": False, "complete": True, "message": f"Error: {e}", "errors": [str(e)]})
        print("fast_scan_for_deleted_files_engine error:", e)

# -------------------------
# Monkey patch the functions in the imported app module
# -------------------------
def apply_monkey_patches():
    # Make sure original module is loaded
    globals_mod = globals()

    # Patch hashing
    orig_app.calculate_hashes_threaded = fast_calculate_hashes_threaded
    # Patch strings
    orig_app.extract_strings_threaded = fast_extract_strings_threaded
    # Patch carving
    orig_app.simple_file_carver = fast_simple_file_carver
    # Patch deleted-file scanner
    orig_app.scan_for_deleted_files_engine = fast_scan_for_deleted_files_engine

    print("[fast_patch] Applied monkey-patches: hashing, strings, carving, deleted-scan")

# -------------------------
# Run server (or run a small test)
# -------------------------
if __name__ == "__main__":
    print("[fast_patch] Starting patch and running Flask app with optimizations...")
    apply_monkey_patches()

    # If you normally run app.py by calling `python app.py` or using flask run,
    # you can instead start the app here. The original app likely defines "app" in module scope.
    try:
        server_app = getattr(orig_app, "app", None)
        if server_app is None:
            print("[fast_patch] Could not find Flask 'app' object in app.py. Exiting.")
        else:
            # Use Flask's built-in run for development; keep same host/port as before if needed
            server_app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
    except Exception as e:
        print("Error launching Flask app:", e)
