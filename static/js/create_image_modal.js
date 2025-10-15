// Lightweight Create Image modal for pages that don't load the full explorer UI
document.addEventListener('DOMContentLoaded', function(){
  const btn = document.getElementById('btn-create-image');
  if(!btn) return;

  // helper to get CSRF and pyewf flag from root dataset
  function getConfig(){
    const fac = document.getElementById('fac-explorer');
    let token = null; let pyewf = false;
    try{ if(fac && fac.dataset){ token = fac.dataset.csrf ? JSON.parse(fac.dataset.csrf) : null; pyewf = fac.dataset.pyewfAvailable ? JSON.parse(fac.dataset.pyewfAvailable) : false; } }catch(e){}
    if(!token && typeof FAC_CSRF_TOKEN !== 'undefined') token = FAC_CSRF_TOKEN;
    return { csrf: token, pyewf: !!pyewf };
  }

  btn.addEventListener('click', showCreateImageModal);

  function showCreateImageModal(){
    // remove existing
    const existing = document.getElementById('create-image-modal'); if(existing) existing.remove();
    const modal = document.createElement('div'); modal.id = 'create-image-modal'; modal.style.position='fixed'; modal.style.left='20%'; modal.style.top='15%'; modal.style.width='60%'; modal.style.background='#071018'; modal.style.padding='12px'; modal.style.zIndex=10000; modal.style.border='1px solid #333'; modal.style.boxShadow='0 4px 16px rgba(0,0,0,0.6)';

    const title = document.createElement('div'); title.textContent='Create Image'; title.style.fontWeight='700'; title.style.marginBottom='8px'; modal.appendChild(title);
    const form = document.createElement('div'); form.style.display='grid'; form.style.gridTemplateColumns='1fr 1fr'; form.style.gap='8px';

  // Source type selector (file/folder/cloud/device)
  const stLabel = document.createElement('label'); stLabel.textContent = 'Source type:';
  const stSelect = document.createElement('select'); stSelect.id = 'ci_source_type'; stSelect.style.width = '100%';
  [['file','File'],['folder','Folder'],['cloud','Cloud URL'],['device','Device']].forEach(it=>{ const o = document.createElement('option'); o.value=it[0]; o.text=it[1]; stSelect.appendChild(o); });
  form.appendChild(stLabel); form.appendChild(stSelect);

  // Device selector (populated when device chosen)
  const deviceLabel = document.createElement('label'); deviceLabel.textContent = 'Device (select):'; deviceLabel.style.display='none';
  const deviceSelect = document.createElement('select'); deviceSelect.id='ci_device_select'; deviceSelect.style.width='100%'; deviceSelect.style.display='none';
  form.appendChild(deviceLabel); form.appendChild(deviceSelect);

  // Source root (used for file/folder)
  const srcRootLabel = document.createElement('label'); srcRootLabel.textContent='Source root:';
  const srcRoot = document.createElement('select'); srcRoot.style.width='100%'; srcRoot.id='ci_src_root';
  ['Session Files','Upload Files','Decrypted Files','Encrypted Files'].forEach(v=>{ const o = document.createElement('option'); o.value=v; o.text=v; srcRoot.appendChild(o); });
  form.appendChild(srcRootLabel); form.appendChild(srcRoot);

  // Source path (relative) for file/folder OR URL/device path for other types
  const srcPathLabel = document.createElement('label'); srcPathLabel.textContent='Source path (relative) or URL/device path:';
  const srcPath = document.createElement('input'); srcPath.type='text'; srcPath.id='ci_src_path'; srcPath.style.width='100%'; srcPath.placeholder='e.g. Session_20251014_151026 or https://... or \\\\.\\\\PhysicalDrive1'; form.appendChild(srcPathLabel); form.appendChild(srcPath);

  // Confirmation controls for device imaging (hidden unless device selected)
  const confirmContainer = document.createElement('div'); confirmContainer.style.gridColumn = '1 / span 2'; confirmContainer.style.display='none';
  const confirmChk = document.createElement('input'); confirmChk.type='checkbox'; confirmChk.id='ci_device_confirm_box';
  const confirmChkLabel = document.createElement('label'); confirmChkLabel.appendChild(confirmChk); confirmChkLabel.appendChild(document.createTextNode(' I understand this will image the selected physical device and may be destructive.'));
  const confirmText = document.createElement('input'); confirmText.type='text'; confirmText.id='ci_device_confirm_text'; confirmText.placeholder='Type the exact device path to confirm'; confirmText.style.width='100%'; confirmText.style.marginTop='6px';
  confirmContainer.appendChild(confirmChkLabel); confirmContainer.appendChild(confirmText); form.appendChild(confirmContainer);

    // Format
    const fmtLabel = document.createElement('label'); fmtLabel.textContent='Image format/extension:'; const fmt = document.createElement('input'); fmt.type='text'; fmt.id='ci_fmt'; fmt.value='.dd'; fmt.style.width='100%'; form.appendChild(fmtLabel); form.appendChild(fmt);

    // Destination
    const destLabel = document.createElement('label'); destLabel.textContent='Destination:'; const dest = document.createElement('select'); dest.id='ci_dest'; dest.style.width='100%'; const opt1 = document.createElement('option'); opt1.value='download'; opt1.text='Provide download link'; const opt2 = document.createElement('option'); opt2.value='session'; opt2.text='Store in session folder only'; dest.appendChild(opt1); dest.appendChild(opt2); form.appendChild(destLabel); form.appendChild(dest);

    // EWF metadata
    const caseLabel = document.createElement('label'); caseLabel.textContent='Case number:'; const caseInput = document.createElement('input'); caseInput.type='text'; caseInput.id='ci_case'; caseInput.style.width='100%'; form.appendChild(caseLabel); form.appendChild(caseInput);
    const examinerLabel = document.createElement('label'); examinerLabel.textContent='Examiner:'; const examinerInput = document.createElement('input'); examinerInput.type='text'; examinerInput.id='ci_examiner'; examinerInput.style.width='100%'; form.appendChild(examinerLabel); form.appendChild(examinerInput);
    const notesLabel = document.createElement('label'); notesLabel.textContent='Notes:'; const notesInput = document.createElement('textarea'); notesInput.id='ci_notes'; notesInput.style.width='100%'; notesInput.style.height='60px'; form.appendChild(notesLabel); form.appendChild(notesInput);
    const compressLabel = document.createElement('label'); const compressInput = document.createElement('input'); compressInput.type='checkbox'; compressInput.id='ci_compress'; compressLabel.appendChild(compressInput); compressLabel.appendChild(document.createTextNode(' Enable EWF compression (when using .e01)')); form.appendChild(compressLabel);

    modal.appendChild(form);
  const ctrl = document.createElement('div'); ctrl.style.marginTop='10px'; ctrl.style.display='flex'; ctrl.style.gap='8px'; ctrl.style.alignItems='center';
  const submit = document.createElement('button'); submit.textContent='Create'; submit.className='btn-primary'; const cancel = document.createElement('button'); cancel.textContent='Cancel'; cancel.className='btn-secondary';
  // disabled reason message
  const disabledMsg = document.createElement('div'); disabledMsg.id = 'ci_disabled_msg'; disabledMsg.style.color = 'salmon'; disabledMsg.style.fontSize='13px'; disabledMsg.style.marginLeft='8px'; disabledMsg.style.display='none';
  ctrl.appendChild(submit); ctrl.appendChild(cancel); ctrl.appendChild(disabledMsg); modal.appendChild(ctrl);

    const status = document.createElement('div'); status.id='ci_status'; status.style.marginTop='8px'; modal.appendChild(status);

    cancel.addEventListener('click', ()=> modal.remove());

    submit.addEventListener('click', async ()=>{
      status.textContent = 'Scheduling image creation...';
      const cfg = getConfig();
      try{
        const fd = new FormData();
        fd.append('source_type', document.getElementById('ci_source_type').value || 'file');
        fd.append('source_root', document.getElementById('ci_src_root').value);
        fd.append('source_path', document.getElementById('ci_src_path').value || '');
        fd.append('image_format', document.getElementById('ci_fmt').value || '.dd');
        fd.append('destination', document.getElementById('ci_dest').value || 'download');
        fd.append('csrf_token', cfg.csrf || '');
        fd.append('case_number', document.getElementById('ci_case').value || '');
        fd.append('examiner', document.getElementById('ci_examiner').value || '');
        fd.append('notes', document.getElementById('ci_notes').value || '');
        fd.append('compress', document.getElementById('ci_compress').checked ? '1' : '');
        const r = await fetch('/api/create_image', { method: 'POST', body: fd, headers: cfg.csrf ? {'X-CSRF-Token': cfg.csrf} : {} });
        const j = await r.json();
        if(j.error){ status.textContent = 'Error: ' + (j.message || j.error); return; }
        const jobId = j.job_id;
        status.textContent = 'Job queued: ' + jobId + '. Waiting for progress...';
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
            setTimeout(poll, 1500);
          }catch(err){ status.textContent = 'Polling failed: ' + err; }
        };
        setTimeout(poll, 800);

      }catch(err){ status.textContent = 'Request failed: ' + err; }
    });

    document.body.appendChild(modal);
    // helper: fetch devices and populate select (creates select if not present)
    async function fetchDevices(){
      try{
        // lazily create device select if not present
        let deviceSelect = document.getElementById('ci_device_select');
        let deviceLabel = null;
        if(!deviceSelect){
          deviceLabel = document.createElement('label'); deviceLabel.textContent = 'Device (select):'; deviceLabel.style.display='none';
          deviceSelect = document.createElement('select'); deviceSelect.id='ci_device_select'; deviceSelect.style.width='100%'; deviceSelect.style.display='none';
          // insert before the format label (approx)
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

    // adjust UI when source type changes
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
        submit.disabled = true; // require explicit confirm
      } else {
        if(deviceLabel) deviceLabel.style.display='none';
        if(deviceSelect) deviceSelect.style.display='none';
        confirmContainer.style.display='none';
        srcPath.placeholder = 'e.g. Session_20251014_151026 or https://...';
        submit.disabled = false;
      }
    });

    // enable submit only when confirmation matches selected device and set message
    function validateDeviceConfirmation(){
      try{
        const chk = document.getElementById('ci_device_confirm_box');
        const txt = document.getElementById('ci_device_confirm_text');
        const sel = document.getElementById('ci_device_select');
        const msg = document.getElementById('ci_disabled_msg');
        if(!chk || !txt || !sel){ if(msg) msg.style.display='none'; return; }
        const selVal = (sel.value || '').trim();
        const txtVal = (txt.value || '').trim();
        if(!chk.checked){
          submit.disabled = true; if(msg){ msg.textContent = 'Please check the confirmation box to enable imaging of a physical device.'; msg.style.display='block'; }
          return;
        }
        if(txtVal !== selVal){
          submit.disabled = true; if(msg){ msg.textContent = 'Type the exact device path shown in the dropdown to confirm (case-sensitive).'; msg.style.display='block'; }
          return;
        }
        // all good
        submit.disabled = false; if(msg) msg.style.display='none';
      }catch(e){}
    }
    // wire events if elements exist
    document.addEventListener('change', function(e){ if(e.target && (e.target.id === 'ci_device_select' || e.target.id === 'ci_device_confirm_box')) validateDeviceConfirmation(); });
    document.addEventListener('input', function(e){ if(e.target && e.target.id === 'ci_device_confirm_text') validateDeviceConfirmation(); });
  }
});
