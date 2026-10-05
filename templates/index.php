<?php
/** @var array $_ */
script('cryptvault', 'cryptvault');
style('cryptvault', 'style');
?>
<div id="cryptvault" class="cryptvault"
     data-volumes='<?php p(json_encode($_['volumes'])); ?>'
     data-preselect="<?php p($_['preselect']); ?>"
     data-requesttoken="<?php p($_['requesttoken']); ?>">
    <div class="cv-header">
        <h2>CryptVault</h2>
        <div class="cv-actions">
            <button id="cv-btn-create" class="primary">New volume</button>
            <button id="cv-btn-lock" class="hidden">Lock</button>
        </div>
    </div>

    <div id="cv-unlock" class="cv-panel">
        <h3>Open a volume</h3>
        <p class="cv-hint">Pick one of your <code>.hc</code> volume files, enter its password.</p>
        <label>Volume file
            <select id="cv-volume-select"></select>
        </label>
        <label>Password
            <input id="cv-password" type="password" autocomplete="off" placeholder="Volume password">
        </label>
        <label class="cv-row">PIM (optional)
            <input id="cv-pim" type="number" min="0" value="0" title="Leave at 0 unless the volume was created with a custom PIM">
        </label>
        <div class="cv-row">
            <button id="cv-btn-unlock" class="primary">Unlock</button>
            <span id="cv-unlock-status" class="cv-status"></span>
        </div>
        <p class="cv-hint small">Your password is sent over HTTPS and never stored. Unlocking takes a few seconds (key derivation).</p>
    </div>

    <div id="cv-browser" class="cv-panel hidden">
        <div class="cv-browser-bar">
            <div id="cv-breadcrumb" class="cv-breadcrumb"></div>
            <div class="cv-browser-actions">
                <button id="cv-btn-upload">Upload</button>
                <button id="cv-btn-mkdir">New folder</button>
                <button id="cv-btn-chpw">Change password</button>
                <button id="cv-btn-hdr">Header backup</button>
            </div>
        </div>
        <div id="cv-meta" class="cv-meta"></div>
        <input id="cv-file-input" type="file" class="hidden" multiple>
        <table class="cv-table">
            <thead><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr></thead>
            <tbody id="cv-tbody"></tbody>
        </table>
        <div id="cv-empty" class="cv-empty hidden">This folder is empty.</div>
    </div>

    <div id="cv-modal" class="cv-modal hidden">
        <div class="cv-modal-box">
            <h3 id="cv-modal-title"></h3>
            <div id="cv-modal-body"></div>
            <div class="cv-row">
                <button id="cv-modal-ok" class="primary">OK</button>
                <button id="cv-modal-cancel">Cancel</button>
            </div>
        </div>
    </div>
    <div id="cv-toast" class="cv-toast hidden"></div>
</div>
