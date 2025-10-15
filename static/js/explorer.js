// explorer.js - extracted from inline template
(function(){
  const rootSelect = document.getElementById('root-select');
  const address = document.getElementById('address');
  const list = document.getElementById('explorer-list');
  const status = document.getElementById('status-bar');
  const quick = document.getElementById('quick-list');
  const fileInput = document.getElementById('file-input');
  const favContainer = document.getElementById('favorites');
  const selectAll = document.getElementById('select-all');
  const bulkDeleteBtn = document.getElementById('btn-bulk-delete');
  const bulkStatusSelect = document.getElementById('bulk-status-select');
  const bulkStatusApply = document.getElementById('bulk-status-apply');

  // Read global config from data attributes on the root container to avoid
  // embedding Jinja into JS files (editor/linter friendly). Falls back to
  // previously injected global constants for compatibility.
  const facRoot = document.getElementById('fac-explorer');
  let FAC_CSRF_TOKEN = null;
  let FAC_PYEWF_AVAILABLE = false;
  try{
    if(facRoot && facRoot.dataset){
      FAC_CSRF_TOKEN = facRoot.dataset.csrf ? JSON.parse(facRoot.dataset.csrf) : null;
      FAC_PYEWF_AVAILABLE = facRoot.dataset.pyewfAvailable ? JSON.parse(facRoot.dataset.pyewfAvailable) : false;
    }
  }catch(e){
    // ignore parse errors
  }
  // fallback to global variables if defined (older pages)
  if(typeof FAC_CSRF_TOKEN === 'undefined' || FAC_CSRF_TOKEN === null){ try{ FAC_CSRF_TOKEN = (typeof FAC_CSRF_TOKEN !== 'undefined') ? FAC_CSRF_TOKEN : null; }catch(e){} }
  if(typeof FAC_PYEWF_AVAILABLE === 'undefined'){ try{ FAC_PYEWF_AVAILABLE = (typeof FAC_PYEWF_AVAILABLE !== 'undefined') ? FAC_PYEWF_AVAILABLE : false; }catch(e){} }

  let historyStack = [], historyIdx = -1;

  function formatSize(n){ if(n===0) return '0 B'; if(n<1024) return n+ ' B'; if(n<1024*1024) return (n/1024).toFixed(2)+' KB'; if(n<1024*1024*1024) return (n/(1024*1024)).toFixed(2)+' MB'; return (n/(1024*1024*1024)).toFixed(2)+' GB'; }
  function timeStr(ts){ try{ const d=new Date(ts*1000); return d.toLocaleString(); }catch(e){return ''} }

  function pushHistory(root, path){ historyStack = historyStack.slice(0, historyIdx+1); historyStack.push({root, path}); historyIdx = historyStack.length-1; }
  function goBack(){ if(historyIdx>0){ historyIdx--; const s = historyStack[historyIdx]; rootSelect.value = s.root; load(s.root, s.path); } }
  function goForward(){ if(historyIdx < historyStack.length-1){ historyIdx++; const s = historyStack[historyIdx]; rootSelect.value = s.root; load(s.root, s.path); } }

  async function load(root, path){
    if(!root) return alert('Select a root');
    const rel = path||'';
    try{
      if(typeof address !== 'undefined' && address && 'value' in address){
        address.value = rel? (root + '/' + rel) : root;
      }
    }catch(e){ /* defensive: some pages may not include the address input */ }
    pushHistory(root, rel);
    const res = await fetch('/api/fs/list?root='+encodeURIComponent(root)+'&path='+encodeURIComponent(rel));
    const obj = await res.json();
    if(obj.error) return alert(obj.message || obj.error);
    renderList(obj.items || [], root, obj.path || rel);
  }

  function makeElem(tag,cls,txt){ const e=document.createElement(tag); if(cls) e.className=cls; if(txt!==undefined) e.textContent=txt; return e; }

  async function renderList(items, root, relPath){
    list.innerHTML='';
    const folders = items.filter(i=>i.is_dir);
    const files = items.filter(i=>!i.is_dir);

    function appendRow(name, isDir, meta){
  const row = makeElem('div','row flex items-center gap-2 p-2 border-b border-gray-700');
  try{ if(meta) row.dataset.meta = JSON.stringify(meta); }catch(e){}
      const sel = makeElem('input','row-select'); sel.type='checkbox'; row.appendChild(sel);
      const icon = makeElem('div','icon w-8 text-center'); icon.textContent = isDir ? '📁' : '📄'; row.appendChild(icon);
      // try to fetch thumbnail for files
      if(!isDir){
        fetch('/api/fs/info?root='+encodeURIComponent(root)+'&path='+encodeURIComponent((relPath? relPath + '/' : '') + name))
          .then(r=>r.json()).then(j=>{ if(j && j.thumbnail){ icon.textContent = ''; const img = document.createElement('img'); img.src = j.thumbnail; img.style.width='32px'; img.style.height='32px'; img.style.objectFit='cover'; icon.appendChild(img); } }).catch(()=>{});
      }
  // filename element with custom tooltip and click-to-expand
  const nm = makeElem('div','name flex-1 fac-tooltip', '');
  const nmText = document.createElement('span'); nmText.textContent = name; nm.appendChild(nmText);
  // status badge (if provided by server)
  try{
    if(meta && meta.status){
      const badge = document.createElement('span'); badge.className = 'status-badge'; badge.textContent = meta.status; badge.style.marginLeft='8px'; badge.style.fontSize='12px'; badge.style.padding='2px 6px'; badge.style.borderRadius='6px'; badge.style.background = meta.status === 'saved' ? '#1f8f4a' : (meta.status === 'processing' ? '#f59e0b' : (meta.status === 'waiting' ? '#3b82f6' : (meta.status === 'paused' ? '#9ca3af' : '#6b7280'))); badge.style.color='white'; nm.appendChild(badge);
      try{
        // add a small dropdown to change status
        const sel = document.createElement('select'); sel.style.marginLeft='6px'; sel.style.fontSize='12px'; sel.style.padding='2px 4px'; sel.title = 'Change status';
        const opts = ['saved','processing','waiting','paused'];
        for(const o of opts){ const opt = document.createElement('option'); opt.value = o; opt.textContent = o; if(o === meta.status) opt.selected = true; sel.appendChild(opt); }
        sel.addEventListener('change', async function(){ try{ const fd = new URLSearchParams(); fd.append('file_id', String(meta.id)); fd.append('status', this.value); fd.append('csrf_token', FAC_CSRF_TOKEN); const r = await fetch('/api/file_status',{method:'POST', headers: {'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token': FAC_CSRF_TOKEN}, body: fd}); const j = await r.json(); if(j.error) return alert(j.error||j.message); badge.textContent = this.value; badge.style.background = this.value === 'saved' ? '#1f8f4a' : (this.value === 'processing' ? '#f59e0b' : (this.value === 'waiting' ? '#3b82f6' : (this.value === 'paused' ? '#9ca3af' : '#6b7280'))); }catch(e){ alert('Status update failed: '+e.message); } });
        nm.appendChild(sel);
      }catch(e){}
    }
  }catch(e){}
  const nmTip = document.createElement('span'); nmTip.className = 'fac-tooltip-text'; nmTip.textContent = name; nmTip.setAttribute('role','tooltip'); nmTip.setAttribute('aria-hidden','true'); nm.appendChild(nmTip);
  // accessibility: keyboard focus and ARIA
  nm.tabIndex = 0; nm.setAttribute('role','button'); nm.setAttribute('aria-label', name);
  nm.addEventListener('focus', function(){ nm.classList.add('fac-show'); nmTip.setAttribute('aria-hidden','false'); });
  nm.addEventListener('blur', function(){ nm.classList.remove('fac-show'); nmTip.setAttribute('aria-hidden','true'); });
  nm.addEventListener('keydown', function(ev){ if(ev.key === 'Enter' || ev.key === ' '){ ev.preventDefault(); nm.click(); } });
  nm.addEventListener('click', function(ev){ ev.stopPropagation(); const existing = document.getElementById('fac-inline-fullname'); if(existing) existing.remove(); const popup = document.createElement('div'); popup.id = 'fac-inline-fullname'; popup.className = 'fac-inline-fullname'; popup.textContent = name; document.body.appendChild(popup); const rect = nm.getBoundingClientRect(); popup.style.left = (rect.left + window.scrollX) + 'px'; popup.style.top = (rect.bottom + window.scrollY + 6) + 'px'; function removePopup(){ try{ popup.remove(); }catch(e){} window.removeEventListener('click', removePopup); } setTimeout(()=>{ window.addEventListener('click', removePopup, {once:true}); }, 20); setTimeout(removePopup, 8000); });
  row.appendChild(nm);
      row.appendChild(makeElem('div','size w-32 text-right', isDir ? '' : formatSize(meta.size) ));
      row.appendChild(makeElem('div','mtime w-40 text-right', timeStr(meta.mtime) ));
      const actions = makeElem('div','actions w-48 text-right');
      if(isDir){ const openBtn = makeElem('button','btn-small btn-open','Open'); openBtn.addEventListener('click', ()=>load(root, (relPath? relPath + '/' : '') + name)); actions.appendChild(openBtn); }
      else{ const viewBtn = makeElem('button','btn-small btn-view','Preview'); viewBtn.addEventListener('click', ()=> doPreview(root, (relPath? relPath + '/' : '') + name)); actions.appendChild(viewBtn);
        const dlBtn = makeElem('button','btn-small btn-download','Download'); dlBtn.addEventListener('click', ()=> window.open('/serve_fs_file?root='+encodeURIComponent(root)+'&path='+encodeURIComponent((relPath? relPath + '/' : '') + name), '_blank')); actions.appendChild(dlBtn);
      }
  // Rename removed from Explorer UI
      const delBtn = makeElem('button','btn-small btn-delete','Delete'); delBtn.addEventListener('click', ()=> doDelete(root, (relPath? relPath + '/' : '') + name, isDir)); actions.appendChild(delBtn);
      // If the current root is a user-upload/encrypted/decrypted area, ensure no "Load" action
      // is presented (safety / UX requirement). This will silently remove any button whose
      // visible text is exactly "Load" (case-insensitive) from the actions container.
      try{
        const forbiddenRoots = ['Upload Files','Encrypted Files','Decrypted Files'];
        if(forbiddenRoots.includes(root)){
          Array.from(actions.querySelectorAll('button')).forEach(b => {
            try{ if(b.textContent && b.textContent.trim().toLowerCase() === 'load') b.remove(); }catch(e){}
          });
        }
      }catch(e){}

      row.appendChild(actions);
      list.appendChild(row);

        // keyboard navigation
        row.tabIndex = 0;
        row.addEventListener('keydown', (ev)=>{
          if(ev.key === 'Enter'){
            if(isDir) load(root, (relPath? relPath + '/' : '') + name);
            else doPreview(root, (relPath? relPath + '/' : '') + name);
          }
        });

      // right-click context
      row.addEventListener('contextmenu', (ev)=>{ ev.preventDefault(); showContextMenu(ev.pageX, ev.pageY, root, (relPath? relPath + '/' : '') + name, isDir); });
    }

    for(const f of folders) appendRow(f.name, true, f);
    for(const f of files) appendRow(f.name, false, f);

    status.textContent = 'Items: '+items.length;
    try{ ensureTruncationToggle(); }catch(e){}
    try{ ensureResizeHandles(); }catch(e){}
  }

  // Truncation toggle
  function ensureTruncationToggle(){
    if(document.getElementById('fac-trunc-toggle')) return;
    const container = document.createElement('div'); container.style.display='flex'; container.style.alignItems='center'; container.style.gap='8px'; container.style.marginBottom='8px';
    const toggle = document.createElement('button'); toggle.id='fac-trunc-toggle'; toggle.className='btn-small'; toggle.textContent = localStorage.getItem('fac_trunc') === 'wrap' ? 'Wrap filenames' : 'Truncate filenames';
    toggle.addEventListener('click', ()=>{
      const cur = document.body.classList.contains('fac-wrap') ? 'wrap' : 'truncate';
      if(cur === 'truncate'){
        document.body.classList.remove('fac-truncate'); document.body.classList.add('fac-wrap'); localStorage.setItem('fac_trunc','wrap'); toggle.textContent='Wrap filenames';
      } else {
        document.body.classList.remove('fac-wrap'); document.body.classList.add('fac-truncate'); localStorage.setItem('fac_trunc','truncate'); toggle.textContent='Truncate filenames';
      }
    });
    const explorerContainer = document.getElementById('explorer-container'); explorerContainer.insertBefore(container, document.getElementById('explorer-list'));
    container.appendChild(toggle);
    if(localStorage.getItem('fac_trunc') === 'wrap'){ document.body.classList.add('fac-wrap'); } else { document.body.classList.add('fac-truncate'); }
  }

  // Column resize helpers
  function ensureResizeHandles(){
    if(document.getElementById('fac-resize-handle')) return;
    const header = document.createElement('div'); header.id='fac-resize-handle'; header.style.display='flex'; header.style.alignItems='center'; header.style.gap='8px'; header.style.marginBottom='6px';
    const info = document.createElement('div'); info.style.fontSize='12px'; info.style.color='#9CA3AF'; info.textContent='Drag handles to resize columns'; header.appendChild(info);
    const explorerContainer = document.getElementById('explorer-container'); explorerContainer.insertBefore(header, document.getElementById('explorer-list'));

    // create two handles: between name|size and size|mtime
    const handleSize = document.createElement('div'); handleSize.className='col-resize-handle'; handleSize.style.width='12px'; handleSize.style.height='18px'; handleSize.style.cursor='col-resize'; handleSize.title='Resize Size column'; handleSize.style.background='transparent';
    const handleMtime = document.createElement('div'); handleMtime.className='col-resize-handle'; handleMtime.style.width='12px'; handleMtime.style.height='18px'; handleMtime.style.cursor='col-resize'; handleMtime.title='Resize MTime column'; handleMtime.style.background='transparent';
    const wrapper = document.createElement('div'); wrapper.style.display='flex'; wrapper.style.alignItems='center'; wrapper.style.gap='6px'; wrapper.appendChild(handleSize); wrapper.appendChild(handleMtime); header.appendChild(wrapper);

    // apply saved widths if available
    const savedSize = parseInt(localStorage.getItem('fac_col_width_size') || '0', 10);
    const savedMtime = parseInt(localStorage.getItem('fac_col_width_mtime') || '0', 10);
    if(savedSize > 0){ document.querySelectorAll('.row .size').forEach(el=>{ el.style.flex = '0 0 '+savedSize+'px'; el.style.maxWidth = savedSize+'px'; }); }
    if(savedMtime > 0){ document.querySelectorAll('.row .mtime').forEach(el=>{ el.style.flex = '0 0 '+savedMtime+'px'; el.style.maxWidth = savedMtime+'px'; }); }

    function attachDrag(handle, targetSelector, minWidth, storageKey){
      let dragging=false, startX=0, startW=0;
      handle.addEventListener('mousedown', function(e){ e.preventDefault(); dragging = true; startX = e.clientX; const el = document.querySelector('.row '+targetSelector); if(el) startW = el.getBoundingClientRect().width; });
      window.addEventListener('mousemove', function(e){ if(!dragging) return; const dx = e.clientX - startX; const newW = Math.max(minWidth, Math.round(startW + dx)); document.querySelectorAll('.row '+targetSelector).forEach(el=>{ el.style.flex = '0 0 '+newW+'px'; el.style.maxWidth = newW+'px'; }); });
      window.addEventListener('mouseup', function(){ if(dragging){ // persist final width of first element
        const el = document.querySelector('.row '+targetSelector); if(el){ const w = Math.round(el.getBoundingClientRect().width); try{ localStorage.setItem(storageKey, String(w)); }catch(e){} }
        dragging = false; } });
    }

    attachDrag(handleSize, '.size', 48, 'fac_col_width_size');
    attachDrag(handleMtime, '.mtime', 80, 'fac_col_width_mtime');
  }

  // context menu
  let ctxMenu = null;
  function showContextMenu(x,y,root,path,isDir){
    if(ctxMenu) ctxMenu.remove();
    ctxMenu = makeElem('div','ctx-menu'); ctxMenu.style.position='absolute'; ctxMenu.style.left = x+'px'; ctxMenu.style.top = y+'px'; ctxMenu.style.background='#111'; ctxMenu.style.border='1px solid #333'; ctxMenu.style.padding='6px';
    const addFav = makeElem('div','ctx-item','Add to favorites'); addFav.style.cursor='pointer'; addFav.onclick = ()=>{ addFavorite(path); ctxMenu.remove(); };
    const del = makeElem('div','ctx-item','Delete'); del.style.cursor='pointer'; del.onclick = ()=>{ doDelete(root, path, isDir); ctxMenu.remove(); };
  ctxMenu.appendChild(addFav); ctxMenu.appendChild(del);
    document.body.appendChild(ctxMenu);
    setTimeout(()=> document.addEventListener('click', ()=> { if(ctxMenu) ctxMenu.remove(); ctxMenu=null; }, {once:true}), 10);
  }

  // favorites
  function loadFavorites(){ try{ const f=JSON.parse(localStorage.getItem('fac_favorites')||'[]'); favContainer.innerHTML=''; for(const it of f){ const a = makeElem('a','fav-item', it); a.href='#'; a.onclick=(e)=>{ e.preventDefault(); rootSelect.value = it.split('/')[0]||rootSelect.value; load(rootSelect.value, it.split('/').slice(1).join('/')); }; favContainer.appendChild(a);} }catch(e){} }
  function addFavorite(path){ try{ const arr = JSON.parse(localStorage.getItem('fac_favorites')||'[]'); if(!arr.includes(path)) arr.push(path); localStorage.setItem('fac_favorites', JSON.stringify(arr)); loadFavorites(); }catch(e){} }

  // actions
  // Rename removed from Explorer client-side script
  async function doDelete(root, target, isDir){ if(!confirm('Delete '+target+' ?')) return; const r = await fetch('/api/fs/delete',{method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token': FAC_CSRF_TOKEN}, body:new URLSearchParams({root, path: target, csrf_token: FAC_CSRF_TOKEN})}); const j = await r.json(); if(j.error) alert(j.error||j.message); else { load(root, address.value.replace(root + '/', '')); }
  }
  async function doPreview(root, target){ const r = await fetch('/api/fs/preview?root='+encodeURIComponent(root)+'&path='+encodeURIComponent(target)); const j = await r.json(); if(j.error) return alert(j.error||j.message); showPreviewModal(j); }

  // upload
  // connect upload area (supports multiple files selection and upload button)
  try{
    const uploadInput = document.getElementById('upload-file-input');
    const selectedList = document.getElementById('selected-files-list');
    const fileInfoContainer = document.getElementById('file-info');
    const clearSelectionBtn = document.getElementById('clear-selection');
    const uploadForm = document.getElementById('upload-form');
    const uploadButton = document.getElementById('upload-button');

    function updateFileInfo(){
      try{
        const files = uploadInput.files || [];
        if(!files.length){ selectedList.innerHTML = ''; fileInfoContainer.classList.add('hidden'); return; }
        fileInfoContainer.classList.remove('hidden'); selectedList.innerHTML = '';
        for(const f of files){ const div = document.createElement('div'); div.textContent = f.name + ' (' + formatSize(f.size) + ')'; selectedList.appendChild(div); }
      }catch(e){ }
    }

    if(uploadInput){ uploadInput.addEventListener('change', updateFileInfo); }
    if(clearSelectionBtn){ clearSelectionBtn.addEventListener('click', ()=>{ try{ uploadInput.value = ''; updateFileInfo(); }catch(e){} }); }

    // Auto-refresh toggle (persist in localStorage)
    try{
      const autoCheckbox = document.getElementById('upload-auto-refresh');
      const stored = localStorage.getItem('fac_auto_refresh');
      if(autoCheckbox){
        try{ autoCheckbox.checked = stored === '1'; }catch(e){}
        autoCheckbox.addEventListener('change', function(){ try{ localStorage.setItem('fac_auto_refresh', this.checked ? '1' : '0'); }catch(e){} });
      }
    }catch(e){}

  // show/hide root warning based on selection
  function updateUploadRootWarning(){ try{ const warn = document.getElementById('upload-root-warning'); const rd = getRootAndDest(); if(warn){ if(!rd || !rd.root) warn.classList.remove('hidden'); else warn.classList.add('hidden'); } }catch(e){} }
  try{ if(typeof rootSelect !== 'undefined' && rootSelect){ rootSelect.addEventListener('change', updateUploadRootWarning); } updateUploadRootWarning(); }catch(e){}

    // Track the current active XHR so uploads can be aborted
    const currentUpload = { xhr: null, aborted: false };
    // Helper: determine current root and destination safely (fall back to 'Upload Files')
    function getRootAndDest(){
      const root = (typeof rootSelect !== 'undefined' && rootSelect && rootSelect.value) ? rootSelect.value : 'Upload Files';
      const addrVal = (typeof address !== 'undefined' && address && address.value) ? address.value : root;
      const dest = (addrVal && addrVal.startsWith(root + '/')) ? addrVal.replace(root + '/', '') : '';
      return { root, dest };
    }

    // Ensure we have a CSRF token available in FAC_CSRF_TOKEN; fetch from server if needed
    async function ensureCsrfToken(){
      if(typeof FAC_CSRF_TOKEN !== 'undefined' && FAC_CSRF_TOKEN) return FAC_CSRF_TOKEN;
      try{
        const resp = await fetch('/api/get_csrf');
        if(resp.ok){ const j = await resp.json(); if(j && j.csrf){ FAC_CSRF_TOKEN = j.csrf; return FAC_CSRF_TOKEN; } }
      }catch(e){}
      return null;
    }

    // Toast helpers
    function ensureToastContainer(){
      let c = document.getElementById('fac-toast-container');
      if(!c){ c = document.createElement('div'); c.id = 'fac-toast-container'; c.className = 'fac-toast-container'; document.body.appendChild(c); }
      return c;
    }
    function showToast(message, type='info', timeout=4200){
      try{
        const container = ensureToastContainer();
        const toast = document.createElement('div'); toast.className = 'fac-toast '+(type || 'info')+' show'; toast.textContent = message;
        container.appendChild(toast);
        setTimeout(()=>{ try{ toast.classList.remove('show'); toast.classList.add('hide'); setTimeout(()=>{ try{ toast.remove(); }catch(e){} }, 300); }catch(e){} }, timeout);
      }catch(e){}
    }

    // Floating refresh card helpers
    function ensureRefreshCard(){
      let c = document.getElementById('fac-refresh-card');
      if(!c){
        c = document.createElement('div'); c.id = 'fac-refresh-card'; c.className = 'fac-refresh-card';
        const msg = document.createElement('div'); msg.className = 'msg'; msg.textContent = 'New uploaded files are available in Currently Loaded Evidence.';
        const actions = document.createElement('div'); actions.className = 'actions';
        const refreshBtn = document.createElement('button'); refreshBtn.className = 'btn-refresh'; refreshBtn.textContent = 'Refresh Now';
        const dismissBtn = document.createElement('button'); dismissBtn.className = 'btn-dismiss'; dismissBtn.textContent = 'Dismiss';
        actions.appendChild(refreshBtn); actions.appendChild(dismissBtn);
        c.appendChild(msg); c.appendChild(actions);
        document.body.appendChild(c);
        refreshBtn.addEventListener('click', async ()=>{ try{ const rd = getRootAndDest(); await load(rd.root, rd.dest); removeRefreshCard(); }catch(e){ showToast('Refresh failed: '+e, 'info'); } });
        dismissBtn.addEventListener('click', ()=>{ removeRefreshCard(); });
      }
      return c;
    }
    function showRefreshCard(){ try{ ensureRefreshCard(); const c = document.getElementById('fac-refresh-card'); if(c) c.style.display = 'flex'; setTimeout(()=>{ try{ const cc = document.getElementById('fac-refresh-card'); if(cc) cc.style.display = 'flex'; }catch(e){} }, 20); }catch(e){} }
    function removeRefreshCard(){ try{ const c = document.getElementById('fac-refresh-card'); if(c) c.remove(); }catch(e){} }

    // Helper: upload a single file via XHR so we can get progress events and support aborting
    function uploadSingleFileXHR(file, root, dest, onProgress){
      return new Promise((resolve, reject)=>{
        try{
          const xhr = new XMLHttpRequest();
          currentUpload.xhr = xhr; currentUpload.aborted = false;
          const fd = new FormData();
          fd.append('root', root);
          fd.append('path', dest);
          fd.append('file', file);
          // determine CSRF token at send-time (read from fac-explorer dataset as fallback)
          let token = FAC_CSRF_TOKEN;
          try{ const fr = document.getElementById('fac-explorer'); if(fr && fr.dataset && fr.dataset.csrf){ try{ token = JSON.parse(fr.dataset.csrf); }catch(e){ token = fr.dataset.csrf; } } }catch(e){}
          if(token) fd.append('csrf_token', token);
          xhr.open('POST', '/api/fs/upload');
          try{ if(token) xhr.setRequestHeader('X-CSRF-Token', token); }catch(e){}
          xhr.upload.addEventListener('progress', function(e){ if(e.lengthComputable && typeof onProgress === 'function'){ onProgress(e.loaded, e.total); } else if(typeof onProgress === 'function'){ onProgress(e.loaded, null); } });
          xhr.onreadystatechange = function(){
            if(xhr.readyState === 4){
              currentUpload.xhr = null;
              if(currentUpload.aborted){ reject(new Error('Upload aborted')); return; }
              if(xhr.status >= 200 && xhr.status < 300){
                try{ const j = JSON.parse(xhr.responseText || '{}'); resolve(j); }catch(e){ resolve({}); }
              } else {
                try{ const j = JSON.parse(xhr.responseText || '{}'); reject(j); }catch(e){ reject(new Error('Upload failed with status '+xhr.status)); }
              }
            }
          };
          xhr.onerror = function(){ currentUpload.xhr = null; reject(new Error('Network error during upload')); };
          xhr.onabort = function(){ currentUpload.xhr = null; currentUpload.aborted = true; reject(new Error('Upload aborted')); };
          xhr.send(fd);
        }catch(err){ currentUpload.xhr = null; reject(err); }
      });
    }

  if(uploadButton){
    uploadButton.addEventListener('click', async function(e){
      e.preventDefault();
      try{
        const files = uploadInput.files || [];
        if(!files.length){ alert('No file selected'); return; }
        const rd = getRootAndDest();
        const dest = rd.dest;
        if(!rd || !rd.root){ try{ const warn = document.getElementById('upload-root-warning'); if(warn) warn.classList.remove('hidden'); }catch(e){} alert('Please select a destination root before uploading.'); return; }

        // ensure CSRF token available
        await ensureCsrfToken();
        const progressContainer = document.getElementById('upload-progress-container');
        const progressBar = document.getElementById('upload-progress-bar');
        const progressText = document.getElementById('upload-progress-text');
        const percentEl = document.getElementById('upload-percent');
        const filenameEl = document.getElementById('upload-filename');
        const speedEl = document.getElementById('upload-speed');
        const timingEl = document.getElementById('upload-timing');

        if(progressContainer) progressContainer.classList.remove('hidden');

        for(const f of files){
          try{
            if(filenameEl) filenameEl.textContent = f.name;
            const start = Date.now();
            let lastLoaded = 0;
            await uploadSingleFileXHR(f, rd.root, dest || rd.dest, (loaded, total)=>{
              try{
                const now = Date.now();
                const elapsed = Math.max(0.001, (now - start) / 1000);
                const uploaded = typeof loaded === 'number' ? loaded : 0;
                const tot = typeof total === 'number' ? total : (f.size || null);
                const pct = (tot ? Math.round((uploaded / tot) * 100) : 0);
                if(progressBar && typeof pct === 'number') progressBar.style.width = pct + '%';
                if(percentEl) percentEl.textContent = (tot ? pct + '%' : 'Uploading...');
                if(progressText) progressText.textContent = formatSize(uploaded) + (tot ? ' / ' + formatSize(tot) : '');
                const delta = uploaded - lastLoaded; lastLoaded = uploaded;
                const speed = Math.round(uploaded / elapsed);
                if(speedEl) speedEl.textContent = formatSize(speed) + '/s';
                if(timingEl){ const remaining = (tot && speed) ? Math.round((tot - uploaded) / speed) : null; timingEl.innerHTML = 'Elapsed: ' + Math.round(elapsed) + 's<br>Remaining: ' + (remaining === null ? 'Calculating...' : (remaining + 's')); }
              }catch(e){}
            });
          }catch(err){
            try{ if(err && err.message) alert('Upload failed: ' + err.message); else if(err && err.error) alert('Upload failed: ' + (err.error || err.message)); else alert('Upload failed'); }catch(e){}
            break;
          }
        }

        // finished
        if(progressContainer){ setTimeout(()=>{ try{ progressContainer.classList.add('hidden'); if(progressBar) progressBar.style.width = '0%'; if(percentEl) percentEl.textContent = '0%'; if(progressText) progressText.textContent = '0 B / 0 B'; if(speedEl) speedEl.textContent = '0 B/s'; if(timingEl) timingEl.innerHTML = 'Elapsed: 0s<br>Remaining: Calculating...'; }catch(e){} }, 800); }

        // Refresh explorer list and uploaded files card
        try{ await load(rd.root, dest); }catch(e){}
        try{ uploadInput.value = ''; updateFileInfo(); }catch(e){}

        try{
          const resp = await fetch('/api/uploaded_files');
          if(resp.ok){
            const j = await resp.json();
            if(!j.error && j.uploaded_files){
              const card = document.getElementById('currently-loaded-evidence-list');
              const prev = card ? Array.from(card.querySelectorAll('.font-mono')).map(n=>n.textContent.trim()) : [];
              let html = '';
              let idx = 0;
              const newFiles = [];
              for(const [name, info] of Object.entries(j.uploaded_files)){
                if(!prev.includes(name)) newFiles.push(name);
                html += `<div class="p-2 border-b border-gray-700" id="file-status-${idx}"><div class="flex justify-between items-center"><div><span class="font-mono">${name}</span> <span>(${(info.size_mb||0)} MB)</span><span id="decryption-badge-${idx}" class="ml-2">`;
                const es = info.encryption_status||{};
                if(es.decrypted_path) html += `<span class="decryption-badge">DECRYPTED</span>`;
                else if(es.decrypting) html += `<span class="decrypting-badge">DECRYPTING...</span>`;
                else if(es.encrypted) html += `<span class="encryption-badge">ENCRYPTED</span>`;
                html += `</span></div><div class="flex space-x-2"><a href="/remove_file?filename=${encodeURIComponent(name)}" class="btn-small btn-delete">Unload</a></div></div><div id="decryption-status-text-${idx}" class="text-xs text-gray-400 mt-2 pl-2">`;
                if(es.encrypted && !es.decrypted_path) html += `Encryption: ${es.description || ''} - <a href="/decryption?filename=${encodeURIComponent(name)}" class="text-blue-400 hover:underline">Go to Decryption Page</a>`;
                else if(es.decrypting) html += `<span class="text-yellow-400">Decryption in progress...</span>`;
                html += `</div></div>`;
                idx++;
              }
              if(card) card.innerHTML = html;
              try{
                const auto = localStorage.getItem('fac_auto_refresh') === '1';
                if(newFiles.length === 1){ showToast('Uploaded: ' + newFiles[0], 'success', 4200); }
                else if(newFiles.length > 1){ showToast('Uploaded ' + newFiles.length + ' files', 'success', 4200); }
                if(auto){ try{ const rd2 = getRootAndDest(); await load(rd2.root, rd2.dest); }catch(e){ showRefreshCard(); } }
                else { showRefreshCard(); }
              }catch(e){ showRefreshCard(); }
            }
          }
        }catch(e){}

      }catch(err){ alert('Upload failed: ' + err); }
    });
  }

    // cancel/abort upload button wiring
    try{
      const cancelBtn = document.getElementById('upload-cancel');
      if(cancelBtn){ cancelBtn.addEventListener('click', function(){ try{ if(currentUpload.xhr){ currentUpload.xhr.abort(); } const progressContainer = document.getElementById('upload-progress-container'); const progressBar = document.getElementById('upload-progress-bar'); const percentEl = document.getElementById('upload-percent'); const progressText = document.getElementById('upload-progress-text'); const speedEl = document.getElementById('upload-speed'); const timingEl = document.getElementById('upload-timing'); if(progressContainer){ progressContainer.classList.add('hidden'); } if(progressBar) progressBar.style.width = '0%'; if(percentEl) percentEl.textContent = '0%'; if(progressText) progressText.textContent = '0 B / 0 B'; if(speedEl) speedEl.textContent = '0 B/s'; if(timingEl) timingEl.innerHTML = 'Elapsed: 0s<br>Remaining: Calculating...'; }catch(e){} }); }
    }catch(e){}
  }catch(e){ /* ignore if upload area not present */ }

  // new folder
  document.getElementById('btn-new-folder').addEventListener('click', async ()=>{ const name = prompt('Folder name:'); if(!name) return; const dest = address.value && address.value.startsWith(rootSelect.value + '/') ? address.value.replace(rootSelect.value + '/', '') : ''; const r = await fetch('/api/fs/mkdir',{method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token': FAC_CSRF_TOKEN}, body:new URLSearchParams({root: rootSelect.value, path: dest, name, csrf_token: FAC_CSRF_TOKEN})}); const j = await r.json(); if(j.error) alert(j.error||j.message); else load(rootSelect.value, dest); });

  document.getElementById('btn-refresh').addEventListener('click', ()=> load(rootSelect.value, address.value.replace(rootSelect.value+'/', '')));
  document.getElementById('btn-up').addEventListener('click', ()=>{ const cur = address.value.replace(rootSelect.value+'/', ''); if(!cur) return; const parts = cur.split('/'); parts.pop(); load(rootSelect.value, parts.join('/')); });
  document.getElementById('btn-back').addEventListener('click', goBack);
  document.getElementById('btn-forward').addEventListener('click', goForward);
  document.getElementById('btn-zip').addEventListener('click', ()=>{ const root=rootSelect.value; const rel = address.value.replace(root + '/', ''); window.location='/download_folder_zip?browse_root='+encodeURIComponent(root)+'&browse_folder='+encodeURIComponent(rel); });

  // bulk delete
  bulkDeleteBtn.addEventListener('click', async ()=>{
    const sels = Array.from(list.querySelectorAll('.row-select')).filter(i=>i.checked);
    if(!sels.length) return alert('No items selected');
    if(!confirm('Delete '+sels.length+' items?')) return;
    // collect relative paths
    const base = address.value.replace(rootSelect.value+'/', '');
    const toDelete = sels.map(s=>{ const row = s.closest('.row'); const name = row.querySelector('.name').textContent; return base ? (base + '/' + name) : name; });
    const r = await fetch('/api/fs/bulk_delete', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': FAC_CSRF_TOKEN}, body: JSON.stringify({root: rootSelect.value, paths: toDelete, csrf_token: FAC_CSRF_TOKEN}) });
    const j = await r.json(); if(j.error) alert(j.error||j.message); else load(rootSelect.value, base);
  });

  // bulk status apply
  if(bulkStatusApply){
    bulkStatusApply.addEventListener('click', async ()=>{
      const sels = Array.from(list.querySelectorAll('.row-select')).filter(i=>i.checked);
      if(!sels.length) return alert('No items selected');
      const status = bulkStatusSelect ? bulkStatusSelect.value : null;
      if(!status) return alert('Select a status to apply');
      if(!confirm('Apply status "'+status+'" to '+sels.length+' items?')) return;
      const base = address.value.replace(rootSelect.value+'/', '');
      // collect ids from meta available on rendered rows (we store meta on row.dataset)
      const ids = sels.map(s=>{ const row = s.closest('.row'); try{ const m = JSON.parse(row.dataset.meta || 'null'); return m && m.id ? m.id : null;}catch(e){return null;} }).filter(x=>x);
      if(!ids.length) return alert('Selected items do not have associated DB ids');
      try{
        const payload = { file_ids: ids, status: status };
        const r = await fetch('/api/file_status_bulk', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': FAC_CSRF_TOKEN}, body: JSON.stringify(payload) });
        const j = await r.json(); if(j.error) return alert(j.error||j.message);
        // success: update badges for rows
        for(const s of sels){ const row = s.closest('.row'); try{ const m = JSON.parse(row.dataset.meta || 'null'); const nameEl = row.querySelector('.name'); const badge = nameEl && nameEl.querySelector('.status-badge'); if(badge) badge.textContent = status, badge.style.background = status === 'saved' ? '#1f8f4a' : (status === 'processing' ? '#f59e0b' : (status === 'waiting' ? '#3b82f6' : (status === 'paused' ? '#9ca3af' : '#6b7280'))); }catch(e){} }
        alert('Updated '+ (j.updated || ids.length) +' items');
      }catch(e){ alert('Bulk update failed: '+e.message); }
    });
  }

  selectAll.addEventListener('change', ()=>{ const checked = selectAll.checked; document.querySelectorAll('.row-select').forEach(r=>r.checked=checked); });

  // preview modal
  function showPreviewModal(data){ let modal = document.getElementById('preview-modal'); if(!modal){ modal = document.createElement('div'); modal.id='preview-modal'; modal.style.position='fixed'; modal.style.left='10%'; modal.style.top='10%'; modal.style.width='80%'; modal.style.height='80%'; modal.style.background='#0b1220'; modal.style.padding='12px'; modal.style.overflow='auto'; modal.style.zIndex=9999; modal.style.border='1px solid #333'; document.body.appendChild(modal); }
    modal.innerHTML = '';
    const h = document.createElement('div'); h.style.display='flex'; h.style.justifyContent='space-between'; const title = document.createElement('div'); title.textContent = data.name || 'Preview'; title.style.fontWeight='600'; h.appendChild(title); const close = document.createElement('button'); close.textContent='Close'; close.onclick = ()=> modal.remove(); h.appendChild(close); modal.appendChild(h);
    if(data.thumbnail){ const img = document.createElement('img'); img.src = data.thumbnail; img.style.maxWidth='240px'; img.style.float='right'; img.style.margin='6px'; modal.appendChild(img); }
    if(data.mime && data.mime.startsWith('text/')){ const pre = document.createElement('pre'); pre.style.whiteSpace='pre-wrap'; pre.textContent = data.preview || ''; modal.appendChild(pre); }
    else if(data.mime && data.mime.startsWith('image/')){ const full = document.createElement('img'); full.src = '/serve_fs_file?root='+encodeURIComponent(data.root)+'&path='+encodeURIComponent(data.path); full.style.maxWidth='100%'; modal.appendChild(full); }
    else { const pre = document.createElement('pre'); pre.style.whiteSpace='pre-wrap'; pre.textContent = data.preview || '[Binary preview not available]'; modal.appendChild(pre); }
  }

  // drag & drop support (uses XHR uploader to show progress)
  const container = document.getElementById('explorer-container');
  container.addEventListener('dragover', (e)=>{ e.preventDefault(); container.classList.add('dragover'); });
  container.addEventListener('dragleave', (e)=>{ container.classList.remove('dragover'); });
    container.addEventListener('drop', async (e)=>{
    e.preventDefault(); container.classList.remove('dragover');
    const files = e.dataTransfer.files; if(!files.length) return;
    // ensure CSRF token available
    await ensureCsrfToken();
    const progressContainer = document.getElementById('upload-progress-container');
    const progressBar = document.getElementById('upload-progress-bar');
    const progressText = document.getElementById('upload-progress-text');
    const percentEl = document.getElementById('upload-percent');
    const filenameEl = document.getElementById('upload-filename');
    const speedEl = document.getElementById('upload-speed');
    const timingEl = document.getElementById('upload-timing');

    if(progressContainer) progressContainer.classList.remove('hidden');

    for(const f of files){
      const rd = getRootAndDest();
      const dest = rd.dest;
      if(filenameEl) filenameEl.textContent = f.name;
      const start = Date.now(); let lastLoaded = 0;
      try{
        await uploadSingleFileXHR(f, rd.root, dest, (loaded, total)=>{
          try{
            const now = Date.now();
            const elapsed = Math.max(0.001, (now - start) / 1000);
            const uploaded = typeof loaded === 'number' ? loaded : 0;
            const tot = typeof total === 'number' ? total : (f.size || null);
            const pct = (tot ? Math.round((uploaded / tot) * 100) : 0);
            if(progressBar && typeof pct === 'number') progressBar.style.width = pct + '%';
            if(percentEl) percentEl.textContent = (tot ? pct + '%' : 'Uploading...');
            if(progressText) progressText.textContent = formatSize(uploaded) + (tot ? ' / ' + formatSize(tot) : '');
            const delta = uploaded - lastLoaded; lastLoaded = uploaded;
            const speed = Math.round(uploaded / elapsed);
            if(speedEl) speedEl.textContent = formatSize(speed) + '/s';
            if(timingEl){ const remaining = (tot && speed) ? Math.round((tot - uploaded) / speed) : null; timingEl.innerHTML = 'Elapsed: ' + Math.round(elapsed) + 's<br>Remaining: ' + (remaining === null ? 'Calculating...' : (remaining + 's')); }
          }catch(e){}
        });
      }catch(err){ try{ if(err && err.message) alert('Upload failed: ' + err.message); else if(err && err.error) alert('Upload failed: ' + (err.error || err.message)); else alert('Upload failed'); }catch(e){} break; }
    }

    if(progressContainer){ setTimeout(()=>{ try{ progressContainer.classList.add('hidden'); if(progressBar) progressBar.style.width = '0%'; if(percentEl) percentEl.textContent = '0%'; if(progressText) progressText.textContent = '0 B / 0 B'; if(speedEl) speedEl.textContent = '0 B/s'; if(timingEl) timingEl.innerHTML = 'Elapsed: 0s<br>Remaining: Calculating...'; }catch(e){} }, 800); }
    load(rootSelect.value, address.value.replace(rootSelect.value+'/', ''));
  });

  // initial behavior if query provided
  try{ const urlParams = new URLSearchParams(location.search); const br = urlParams.get('browse_root'); const bf = urlParams.get('browse_folder'); if(br){ rootSelect.value = br; load(br, bf||''); } }catch(e){}

  // load favorites on startup
  loadFavorites();

  // Create Image modal and handler
  document.getElementById('btn-create-image').addEventListener('click', ()=>{
    showCreateImageModal();
  });

  function showCreateImageModal(){
    let modal = document.getElementById('create-image-modal');
    if(modal) modal.remove();
    modal = document.createElement('div'); modal.id='create-image-modal'; modal.style.position='fixed'; modal.style.left='20%'; modal.style.top='15%'; modal.style.width='60%'; modal.style.background='#071018'; modal.style.padding='12px'; modal.style.zIndex=10000; modal.style.border='1px solid #333'; modal.style.boxShadow='0 4px 16px rgba(0,0,0,0.6)';
    const title = document.createElement('div'); title.textContent='Create Image'; title.style.fontWeight='700'; title.style.marginBottom='8px'; modal.appendChild(title);
    const form = document.createElement('div'); form.style.display='grid'; form.style.gridTemplateColumns='1fr 1fr'; form.style.gap='8px';

  // Source type selector
  const stLabel = document.createElement('label'); stLabel.textContent='Source type:'; const stSelect = document.createElement('select'); stSelect.id='ci_source_type'; stSelect.style.width='100%'; [['file','File'],['folder','Folder'],['cloud','Cloud URL'],['device','Device']].forEach(it=>{ const o=document.createElement('option'); o.value=it[0]; o.text=it[1]; stSelect.appendChild(o); }); form.appendChild(stLabel); form.appendChild(stSelect);

  // Source root (select)
  const srcRootLabel = document.createElement('label'); srcRootLabel.textContent='Source root:'; const srcRoot = document.createElement('select'); srcRoot.style.width='100%'; srcRoot.id='ci_src_root';
  Array.from(document.getElementById('root-select').options).forEach(opt=>{ const o = document.createElement('option'); o.value = opt.value; o.text = opt.text; srcRoot.appendChild(o); });
  form.appendChild(srcRootLabel); form.appendChild(srcRoot);

  // Source path / URL / device path
  const srcPathLabel = document.createElement('label'); srcPathLabel.textContent='Source path (relative) or URL/device path:'; const srcPath = document.createElement('input'); srcPath.type='text'; srcPath.id='ci_src_path'; srcPath.style.width='100%'; srcPath.placeholder='e.g. Session_20251014_151026 or https://... or \\\\.\\PhysicalDrive1'; form.appendChild(srcPathLabel); form.appendChild(srcPath);
    // Confirmation controls for device imaging (hidden unless device selected)
    const confirmContainer = document.createElement('div'); confirmContainer.style.gridColumn = '1 / span 2'; confirmContainer.style.display='none';
    const confirmChk = document.createElement('input'); confirmChk.type='checkbox'; confirmChk.id='ci_device_confirm_box';
    const confirmChkLabel = document.createElement('label'); confirmChkLabel.appendChild(confirmChk); confirmChkLabel.appendChild(document.createTextNode(' I understand this will image the selected physical device and may be destructive.'));
    const confirmText = document.createElement('input'); confirmText.type='text'; confirmText.id='ci_device_confirm_text'; confirmText.placeholder='Type the exact device path to confirm'; confirmText.style.width='100%'; confirmText.style.marginTop='6px';
    confirmContainer.appendChild(confirmChkLabel); confirmContainer.appendChild(confirmText); form.appendChild(confirmContainer);

    // Image format
    const fmtLabel = document.createElement('label'); fmtLabel.textContent='Image format/extension:'; const fmt = document.createElement('input'); fmt.type='text'; fmt.id='ci_fmt'; fmt.value='.dd'; fmt.style.width='100%'; form.appendChild(fmtLabel); form.appendChild(fmt);

    // Destination
    const destLabel = document.createElement('label'); destLabel.textContent='Destination:'; const dest = document.createElement('select'); dest.id='ci_dest'; dest.style.width='100%'; const opt1 = document.createElement('option'); opt1.value='download'; opt1.text='Provide download link'; const opt2 = document.createElement('option'); opt2.value='session'; opt2.text='Store in session folder only'; dest.appendChild(opt1); dest.appendChild(opt2); form.appendChild(destLabel); form.appendChild(dest);

  // EWF metadata fields
  const caseLabel = document.createElement('label'); caseLabel.textContent='Case number:'; const caseInput = document.createElement('input'); caseInput.type='text'; caseInput.id='ci_case'; caseInput.style.width='100%'; form.appendChild(caseLabel); form.appendChild(caseInput);
  const examinerLabel = document.createElement('label'); examinerLabel.textContent='Examiner:'; const examinerInput = document.createElement('input'); examinerInput.type='text'; examinerInput.id='ci_examiner'; examinerInput.style.width='100%'; form.appendChild(examinerLabel); form.appendChild(examinerInput);
  const notesLabel = document.createElement('label'); notesLabel.textContent='Notes:'; const notesInput = document.createElement('textarea'); notesInput.id='ci_notes'; notesInput.style.width='100%'; notesInput.style.height='60px'; form.appendChild(notesLabel); form.appendChild(notesInput);
  const compressLabel = document.createElement('label'); const compressInput = document.createElement('input'); compressInput.type='checkbox'; compressInput.id='ci_compress'; compressLabel.appendChild(compressInput); compressLabel.appendChild(document.createTextNode(' Enable EWF compression (when using .e01)')); form.appendChild(compressLabel);

    modal.appendChild(form);
  const ctrl = document.createElement('div'); ctrl.style.marginTop='10px'; ctrl.style.display='flex'; ctrl.style.gap='8px'; ctrl.style.alignItems='center';
  const submit = document.createElement('button'); submit.textContent='Create'; submit.className='btn-primary'; const cancel = document.createElement('button'); cancel.textContent='Cancel'; cancel.className='btn-secondary';
  const disabledMsg = document.createElement('div'); disabledMsg.id = 'ci_disabled_msg'; disabledMsg.style.color='salmon'; disabledMsg.style.fontSize='13px'; disabledMsg.style.marginLeft='8px'; disabledMsg.style.display='none';
  ctrl.appendChild(submit); ctrl.appendChild(cancel); ctrl.appendChild(disabledMsg); modal.appendChild(ctrl);

    const status = document.createElement('div'); status.id='ci_status'; status.style.marginTop='8px'; modal.appendChild(status);

    cancel.addEventListener('click', ()=> modal.remove());
    // enable/disable EWF options based on format and availability
    function updateEwfOptions(){
      const chosen = document.getElementById('ci_fmt').value || '';
      const isE01 = chosen.trim().toLowerCase() === '.e01';
      const compressEl = document.getElementById('ci_compress');
      const compressLabel = compressEl ? compressEl.parentElement : null;
      const noteId = 'ci_ewf_note';
      let note = document.getElementById(noteId);
      if(isE01 && !FAC_PYEWF_AVAILABLE){
        if(note) note.textContent = 'pyewf not installed; .e01 creation unavailable, fallback to zip image.';
        else { note = document.createElement('div'); note.id = noteId; note.style.color='salmon'; note.style.fontSize='12px'; note.textContent = 'pyewf not installed; .e01 creation unavailable, fallback to zip image.'; modal.appendChild(note); }
        if(compressLabel) compressLabel.style.opacity = '0.5';
        if(compressEl) compressEl.disabled = true;
      } else {
        if(note) note.remove();
        if(compressLabel) compressLabel.style.opacity = '1';
        if(compressEl) compressEl.disabled = false;
      }
    }

    document.getElementById('ci_fmt').addEventListener('input', updateEwfOptions);
    updateEwfOptions();

    submit.addEventListener('click', async ()=>{
      status.textContent = 'Scheduling image creation...';
      try{
        const formData = new FormData();
        formData.append('source_root', document.getElementById('ci_src_root').value);
        formData.append('source_path', document.getElementById('ci_src_path').value || '');
        formData.append('image_format', document.getElementById('ci_fmt').value || '.dd');
        formData.append('destination', document.getElementById('ci_dest').value || 'download');
  formData.append('csrf_token', FAC_CSRF_TOKEN);
  formData.append('case_number', document.getElementById('ci_case').value || '');
  formData.append('examiner', document.getElementById('ci_examiner').value || '');
  formData.append('notes', document.getElementById('ci_notes').value || '');
  formData.append('compress', document.getElementById('ci_compress').checked ? '1' : '');
        const r = await fetch('/api/create_image', { method: 'POST', body: formData, headers: {'X-CSRF-Token': FAC_CSRF_TOKEN} });
        const j = await r.json();
        if(j.error){ status.textContent = 'Error: ' + (j.message || j.error); return; }
        const jobId = j.job_id;
        status.textContent = 'Job queued: ' + jobId + '. Waiting for progress...';

        // poll status
        const poll = async ()=>{
          try{
            const resp = await fetch('/api/image_status/'+encodeURIComponent(jobId));
            if(resp.status === 404){ status.textContent = 'Job not found'; return; }
            const s = await resp.json();
            if(s.error){ status.textContent = 'Status error: ' + (s.error || 'unknown'); return; }
            status.innerHTML = '';
            const p = document.createElement('div'); p.textContent = 'Status: ' + (s.status || 'unknown') + ' — ' + (s.progress || 0) + '%'; status.appendChild(p);
            if(s.md5 || s.sha1){ const h = document.createElement('div'); h.style.marginTop='6px'; h.innerHTML = '<b>MD5:</b> '+(s.md5||'') + '<br/><b>SHA1:</b> '+(s.sha1||''); status.appendChild(h); }
            if(s.status === 'finished'){
              if(s.download_url){ const a = document.createElement('a'); a.href = s.download_url; a.target='_blank'; a.textContent = 'Download created image: ' + (s.filename||'image'); a.style.display='block'; a.style.marginTop='8px'; status.appendChild(a); }
              return; // done
            }
            if(s.status === 'error'){
              const e = document.createElement('div'); e.style.color='salmon'; e.textContent = 'Error: ' + (s.error || 'unknown'); status.appendChild(e); return;
            }
            // continue polling
            setTimeout(poll, 1500);
          }catch(err){ status.textContent = 'Polling failed: ' + err; }
        };
        setTimeout(poll, 800);

      }catch(err){ status.textContent = 'Request failed: ' + err; }
    });

    document.body.appendChild(modal);
    // helper: fetch devices and populate select (lazily creates select)
    async function fetchDevices(){
      try{
        let deviceSelect = document.getElementById('ci_device_select');
        let deviceLabel = null;
        if(!deviceSelect){
          deviceLabel = document.createElement('label'); deviceLabel.textContent = 'Device (select):'; deviceLabel.style.display='none';
          deviceSelect = document.createElement('select'); deviceSelect.id='ci_device_select'; deviceSelect.style.width='100%'; deviceSelect.style.display='none';
          form.insertBefore(deviceLabel, fmtLabel);
          form.insertBefore(deviceSelect, fmtLabel);
        } else {
          deviceLabel = deviceSelect.previousSibling && deviceSelect.previousSibling.tagName === 'LABEL' ? deviceSelect.previousSibling : null;
        }
        const r = await fetch('/api/devices');
        const j = await r.json();
        deviceSelect.innerHTML = '';
        if(j && Array.isArray(j.devices)){
          j.devices.forEach(d=>{
            const o = document.createElement('option'); o.value = d.path || d.id; o.text = (d.path || d.id) + (d.size_bytes ? ' (' + (d.size_bytes/ (1024*1024*1024)).toFixed(2) + ' GB)' : ''); deviceSelect.appendChild(o);
          });
        }
      }catch(e){ /* ignore */ }
    }

    stSelect.addEventListener('change', function(){
      const v = this.value;
      const deviceSelect = document.getElementById('ci_device_select');
      const deviceLabel = deviceSelect ? (deviceSelect.previousSibling || null) : null;
      if(v === 'device'){
        if(deviceLabel) deviceLabel.style.display='block';
        if(deviceSelect) deviceSelect.style.display='block';
        confirmContainer.style.display='block';
        srcPath.placeholder = 'Or override device path here';
        fetchDevices();
        submit.disabled = true;
      } else {
        if(deviceLabel) deviceLabel.style.display='none';
        if(deviceSelect) deviceSelect.style.display='none';
        confirmContainer.style.display='none';
        srcPath.placeholder = 'e.g. Session_20251014_151026 or https://...';
        submit.disabled = false;
      }
    });

    function validateDeviceConfirmation(){
      try{
        const chk = document.getElementById('ci_device_confirm_box');
        const txt = document.getElementById('ci_device_confirm_text');
        const sel = document.getElementById('ci_device_select');
        const msg = document.getElementById('ci_disabled_msg');
        if(!chk || !txt || !sel){ if(msg) msg.style.display='none'; return; }
        const selVal = (sel.value || '').trim();
        const txtVal = (txt.value || '').trim();
        if(!chk.checked){ submit.disabled = true; if(msg){ msg.textContent = 'Please check the confirmation box to enable imaging of a physical device.'; msg.style.display='block'; } return; }
        if(txtVal !== selVal){ submit.disabled = true; if(msg){ msg.textContent = 'Type the exact device path shown in the dropdown to confirm (case-sensitive).'; msg.style.display='block'; } return; }
        submit.disabled = false; if(msg) msg.style.display='none';
      }catch(e){}
    }
    document.addEventListener('change', function(e){ if(e.target && (e.target.id === 'ci_device_select' || e.target.id === 'ci_device_confirm_box')) validateDeviceConfirmation(); });
    document.addEventListener('input', function(e){ if(e.target && e.target.id === 'ci_device_confirm_text') validateDeviceConfirmation(); });
  }
})();
