/* CryptVault frontend — vanilla JS, no build step. */
(function () {
    'use strict';

    var root = document.getElementById('cryptvault');
    if (!root) return;

    var volumes = JSON.parse(root.dataset.volumes || '[]');
    var preselect = parseInt(root.dataset.preselect || '0', 10);
    var requestToken = root.dataset.requesttoken || (window.oc_requesttoken || '');

    var token = null;       // unlock token, kept in memory only
    var stateless = false;  // true when server has no APCu (password per request)
    var curFileId = 0;
    var curPim = 0;
    var curPath = '/';
    var curPassword = null; // only used in stateless mode, memory only

    function $(id) { return document.getElementById(id); }

    function toast(msg, isErr) {
        var t = $('cv-toast');
        t.textContent = msg;
        t.classList.toggle('err', !!isErr);
        t.classList.remove('hidden');
        setTimeout(function () { t.classList.add('hidden'); }, 4000);
    }

    function api(path, opts) {
        opts = opts || {};
        var headers = { 'requesttoken': requestToken };
        // Stateless mode: password travels in a header, never in the URL
        // (URLs end up in server access logs).
        if (stateless && curPassword !== null) {
            headers['X-CryptVault-Password'] = curPassword;
        }
        var body = opts.body;
        if (opts.json) {
            // form-encoded: universally parsed by Nextcloud's getParam()
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
            body = new URLSearchParams(opts.json).toString();
        }
        var url = OC.generateUrl('/apps/cryptvault' + path);
        return fetch(url, {
            method: opts.method || 'GET',
            headers: headers,
            body: body,
            credentials: 'same-origin'
        }).then(function (resp) {
            if (resp.status === 401) {
                // session expired or token dead -> back to unlock screen
                showUnlock('Session expired, please unlock again.');
                throw new Error('unauthorized');
            }
            var ct = resp.headers.get('Content-Type') || '';
            if (ct.indexOf('application/json') !== -1) {
                return resp.json().then(function (data) {
                    if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
                    return data;
                });
            }
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            return resp;
        });
    }

    function authParams(extra) {
        extra = extra || {};
        if (token) extra.token = token;
        else if (stateless && curPassword !== null) {
            // password goes in the X-CryptVault-Password header (see api());
            // only fileId/pim travel as params here.
            extra.fileId = curFileId;
            extra.pim = curPim;
        }
        return extra;
    }

    // ---------- unlock screen ----------

    function fillVolumeSelect() {
        var sel = $('cv-volume-select');
        sel.innerHTML = '';
        if (!volumes.length) {
            var o = document.createElement('option');
            o.value = '';
            o.textContent = 'No .hc files found in your files';
            sel.appendChild(o);
            return;
        }
        volumes.forEach(function (v) {
            var o = document.createElement('option');
            o.value = v.id;
            o.textContent = v.name + ' (' + fmtSize(v.size) + ')';
            if (v.id === preselect) o.selected = true;
            sel.appendChild(o);
        });
    }

    function showUnlock(msg) {
        token = null; curPassword = null;
        $('cv-unlock').classList.remove('hidden');
        $('cv-browser').classList.add('hidden');
        $('cv-btn-lock').classList.add('hidden');
        if (msg) $('cv-unlock-status').textContent = msg;
    }

    function doUnlock() {
        var fileId = parseInt($('cv-volume-select').value, 10);
        var pw = $('cv-password').value;
        var pim = parseInt($('cv-pim').value || '0', 10);
        if (!fileId || !pw) { toast('Pick a volume and enter its password', true); return; }
        $('cv-unlock-status').textContent = 'Deriving keys… (a few seconds)';
        $('cv-btn-unlock').disabled = true;
        api('/api/unlock', {
            method: 'POST',
            json: { fileId: fileId, password: pw, pim: pim }
        }).then(function (data) {
            token = data.token || null;
            stateless = !!data.stateless;
            if (stateless) curPassword = pw; // memory only, never persisted
            curFileId = fileId;
            curPim = pim;
            // wipe the password field right away
            $('cv-password').value = '';
            pw = null;
            $('cv-unlock').classList.add('hidden');
            $('cv-browser').classList.remove('hidden');
            $('cv-btn-lock').classList.remove('hidden');
            curPath = '/';
            renderMeta(data);
            loadDir('/');
        }).catch(function (e) {
            if (e.message !== 'unauthorized') {
                $('cv-unlock-status').textContent = 'Failed: ' + e.message;
            }
        }).finally(function () {
            $('cv-btn-unlock').disabled = false;
        });
    }

    // ---------- browser ----------

    function fmtSize(n) {
        if (n === 0) return '0 B';
        var u = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
        return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
    }

    function fmtDate(ts) {
        return new Date(ts * 1000).toLocaleString();
    }

    function renderMeta(data) {
        var el = $('cv-meta');
        var parts = [];
        if (data.fileName) parts.push('<strong>' + esc(data.fileName) + '</strong>');
        if (data.fsLabel) parts.push(esc(data.fsLabel));
        if (data.free >= 0) parts.push(fmtSize(data.free) + ' free');
        else if (data.size) parts.push(fmtSize(data.size) + ' volume');
        el.innerHTML = parts.join(' · ');
    }

    function esc(s) {
        return String(s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function loadDir(path) {
        curPath = path;
        renderBreadcrumb();
        var q = authParams({ path: path });
        var url = '/api/list?' + new URLSearchParams(q).toString();
        // GET with password in query for stateless mode — acceptable over HTTPS;
        // prefer token mode whenever APCu is available.
        api(url).then(function (data) {
            renderEntries(data.entries || []);
        }).catch(function (e) {
            if (e.message !== 'unauthorized') toast('List failed: ' + e.message, true);
        });
    }

    function renderBreadcrumb() {
        var bc = $('cv-breadcrumb');
        bc.innerHTML = '';
        var parts = curPath.split('/').filter(Boolean);
        var mk = function (label, p) {
            var a = document.createElement('a');
            a.href = '#';
            a.textContent = label;
            a.onclick = function (ev) { ev.preventDefault(); loadDir(p); };
            return a;
        };
        bc.appendChild(mk(' / ', '/'));
        var acc = '';
        parts.forEach(function (part) {
            acc += '/' + part;
            var s = document.createElement('span');
            s.textContent = ' › ';
            bc.appendChild(s);
            (function (p) { bc.appendChild(mk(part, p)); })(acc);
        });
    }

    function renderEntries(entries) {
        var tb = $('cv-tbody');
        tb.innerHTML = '';
        $('cv-empty').classList.toggle('hidden', entries.length > 0);
        entries.forEach(function (e) {
            var tr = document.createElement('tr');
            var tdN = document.createElement('td');
            if (e.type === 'dir') {
                var a = document.createElement('a');
                a.href = '#';
                a.textContent = '📁 ' + e.name;
                a.onclick = function (ev) { ev.preventDefault(); loadDir(joinPath(curPath, e.name)); };
                tdN.appendChild(a);
            } else {
                tdN.textContent = '📄 ' + e.name;
            }
            var tdS = document.createElement('td');
            tdS.textContent = e.type === 'dir' ? '—' : fmtSize(e.size);
            var tdM = document.createElement('td');
            tdM.textContent = e.mtime ? fmtDate(e.mtime) : '—';
            var tdA = document.createElement('td');
            tdA.className = 'cv-row-actions';
            if (e.type === 'file') {
                var dl = document.createElement('button');
                dl.textContent = 'Download';
                dl.onclick = function () { doDownload(e.name); };
                tdA.appendChild(dl);
            }
            var del = document.createElement('button');
            del.textContent = 'Delete';
            del.className = 'error';
            del.onclick = function () { doDelete(e.name, e.type); };
            tdA.appendChild(del);
            tr.appendChild(tdN); tr.appendChild(tdS); tr.appendChild(tdM); tr.appendChild(tdA);
            tb.appendChild(tr);
        });
    }

    function joinPath(base, name) {
        return (base === '/' ? '' : base) + '/' + name;
    }

    function doDownload(name) {
        var q = authParams({ path: joinPath(curPath, name) });
        var url = OC.generateUrl('/apps/cryptvault/api/download') + '?' + new URLSearchParams(q).toString();
        if (token || !stateless) {
            // token mode: direct link streams to disk
            var a = document.createElement('a');
            a.href = url;
            a.download = name;
            document.body.appendChild(a);
            a.click();
            a.remove();
        } else {
            // stateless: fetch with password header, then save the blob
            var headers = { 'requesttoken': requestToken, 'X-CryptVault-Password': curPassword };
            fetch(url, { headers: headers, credentials: 'same-origin' })
                .then(function (resp) {
                    if (!resp.ok) throw new Error('HTTP ' + resp.status);
                    return resp.blob();
                })
                .then(function (blob) {
                    var a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = name;
                    document.body.appendChild(a);
                    a.click();
                    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
                })
                .catch(function (e) { toast('Download failed: ' + e.message, true); });
        }
    }

    function doDelete(name, type) {
        if (!confirm('Delete "' + name + '"' + (type === 'dir' ? ' and its contents' : '') + '?')) return;
        api('/api/delete', { method: 'POST', json: authParams({ path: joinPath(curPath, name) }) })
            .then(function () { toast('Deleted'); loadDir(curPath); })
            .catch(function (e) { if (e.message !== 'unauthorized') toast('Delete failed: ' + e.message, true); });
    }

    function doMkdir() {
        modal('New folder', '<label>Name <input id="cv-m-name" placeholder="folder name"></label>', function () {
            var name = $('cv-m-name').value.trim();
            if (!name) return false;
            api('/api/mkdir', { method: 'POST', json: authParams({ path: joinPath(curPath, name) }) })
                .then(function () { toast('Folder created'); loadDir(curPath); })
                .catch(function (e) { if (e.message !== 'unauthorized') toast('Failed: ' + e.message, true); });
            return true;
        });
        setTimeout(function () { $('cv-m-name').focus(); }, 50);
    }

    function doUpload(files) {
        if (!files.length) return;
        var i = 0;
        var next = function () {
            if (i >= files.length) { loadDir(curPath); return; }
            var f = files[i++];
            toast('Uploading ' + f.name + ' (' + (i) + '/' + files.length + ')…');
            var fd = new FormData();
            fd.append('file', f, f.name);
            var q = authParams({ path: joinPath(curPath, f.name) });
            var url = OC.generateUrl('/apps/cryptvault/api/upload') + '?' + new URLSearchParams(q).toString();
            fetch(url, { method: 'POST', headers: { 'requesttoken': requestToken }, body: fd, credentials: 'same-origin' })
                .then(function (resp) {
                    if (resp.status === 401) { showUnlock('Session expired.'); throw new Error('unauthorized'); }
                    return resp.json().then(function (data) {
                        if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
                    });
                })
                .then(next)
                .catch(function (e) {
                    if (e.message !== 'unauthorized') toast('Upload failed: ' + e.message, true);
                });
        };
        next();
    }

    // ---------- modal ----------

    var modalOk = null;
    function modal(title, bodyHtml, onOk) {
        $('cv-modal-title').textContent = title;
        $('cv-modal-body').innerHTML = bodyHtml;
        $('cv-modal').classList.remove('hidden');
        modalOk = onOk;
    }
    function closeModal() {
        $('cv-modal').classList.add('hidden');
        modalOk = null;
    }

    // ---------- create volume ----------

    function doCreate() {
        modal('New encrypted volume',
            '<label>File name <input id="cv-m-cname" value="vault.hc"></label>' +
            '<label>Size (MiB, 35–2048) <input id="cv-m-csize" type="number" value="100" min="35" max="2048"></label>' +
            '<label>Password <input id="cv-m-cpw" type="password" autocomplete="new-password"></label>' +
            '<label>Repeat password <input id="cv-m-cpw2" type="password" autocomplete="new-password"></label>' +
            '<p class="cv-hint small">Creates a VeraCrypt-compatible AES-256 volume (FAT32) in your files.</p>',
            function () {
                var name = $('cv-m-cname').value.trim();
                var size = parseInt($('cv-m-csize').value, 10);
                var pw = $('cv-m-cpw').value, pw2 = $('cv-m-cpw2').value;
                if (!name) { toast('Enter a file name', true); return false; }
                if (pw !== pw2) { toast('Passwords do not match', true); return false; }
                if (pw.length < 8) { toast('Password must be at least 8 characters', true); return false; }
                toast('Creating volume… (this takes a while for large sizes)');
                api('/api/create-volume', { method: 'POST', json: { name: name, sizeMb: size, password: pw } })
                    .then(function (data) {
                        pw = null;
                        toast('Volume created: ' + data.name);
                        volumes.push({ id: data.fileId, name: data.name, size: size * 1048576, mtime: Date.now() / 1000 });
                        fillVolumeSelect();
                        $('cv-volume-select').value = data.fileId;
                    })
                    .catch(function (e) { if (e.message !== 'unauthorized') toast('Create failed: ' + e.message, true); });
                return true;
            });
    }

    function doChangePassword() {
        modal('Change volume password',
            '<label>New password <input id="cv-m-npw" type="password" autocomplete="new-password"></label>' +
            '<label>Repeat <input id="cv-m-npw2" type="password" autocomplete="new-password"></label>' +
            '<p class="cv-hint small">Only the header is re-encrypted — fast, data untouched. You will need to unlock again.</p>',
            function () {
                var pw = $('cv-m-npw').value, pw2 = $('cv-m-npw2').value;
                if (pw !== pw2) { toast('Passwords do not match', true); return false; }
                if (pw.length < 8) { toast('Password must be at least 8 characters', true); return false; }
                api('/api/change-password', { method: 'POST', json: authParams({ newPassword: pw }) })
                    .then(function () {
                        pw = null;
                        toast('Password changed — please unlock again');
                        showUnlock();
                    })
                    .catch(function (e) { if (e.message !== 'unauthorized') toast('Failed: ' + e.message, true); });
                return true;
            });
    }

    function doHeaderBackup() {
        var q = authParams({});
        var url = OC.generateUrl('/apps/cryptvault/api/header-backup') + '?' + new URLSearchParams(q).toString();
        var save = function (href) {
            var a = document.createElement('a');
            a.href = href;
            a.download = 'volume-header-backup.bin';
            document.body.appendChild(a);
            a.click();
            a.remove();
        };
        if (token || !stateless) {
            save(url);
        } else {
            var headers = { 'requesttoken': requestToken, 'X-CryptVault-Password': curPassword };
            fetch(url, { headers: headers, credentials: 'same-origin' })
                .then(function (resp) {
                    if (!resp.ok) throw new Error('HTTP ' + resp.status);
                    return resp.blob();
                })
                .then(function (blob) {
                    var href = URL.createObjectURL(blob);
                    save(href);
                    setTimeout(function () { URL.revokeObjectURL(href); }, 1000);
                })
                .catch(function (e) { toast('Backup failed: ' + e.message, true); });
            return;
        }
        toast('Header backup downloading — store it somewhere safe');
    }

    function doLock() {
        if (token) {
            api('/api/lock', { method: 'POST', json: { token: token } }).catch(function () {});
        }
        showUnlock('Locked.');
    }

    // ---------- wire up ----------

    $('cv-btn-unlock').onclick = doUnlock;
    $('cv-password').addEventListener('keydown', function (e) {
        if (e.key === 'Enter') doUnlock();
    });
    $('cv-btn-lock').onclick = doLock;
    $('cv-btn-create').onclick = doCreate;
    $('cv-btn-mkdir').onclick = doMkdir;
    $('cv-btn-chpw').onclick = doChangePassword;
    $('cv-btn-hdr').onclick = doHeaderBackup;
    $('cv-btn-upload').onclick = function () { $('cv-file-input').click(); };
    $('cv-file-input').addEventListener('change', function (e) {
        doUpload(e.target.files);
        e.target.value = '';
    });
    $('cv-modal-ok').onclick = function () { if (modalOk) { if (modalOk() !== false) closeModal(); } };
    $('cv-modal-cancel').onclick = closeModal;

    // wipe secrets if the page is being unloaded
    window.addEventListener('pagehide', function () {
        token = null; curPassword = null;
    });

    fillVolumeSelect();
    if (preselect) {
        for (var i = 0; i < volumes.length; i++) {
            if (volumes[i].id === preselect) { $('cv-volume-select').value = preselect; break; }
        }
    }
})();
