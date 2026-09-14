/* =========================================================================
   Protected posts — client-side AES-256-GCM decryption.
   The plaintext is never shipped: the post body only holds ciphertext, which
   is decrypted in the browser once the correct password is entered.
   Payload comes from tools/encrypt-post.rb as a <div class="post-lock">.
   ========================================================================= */
(function () {
  'use strict';

  var lock = document.querySelector('.post-lock');
  if (!lock || !window.crypto || !window.crypto.subtle) return;

  var iterations = parseInt(lock.getAttribute('data-iter'), 10) || 200000;
  var saltB64 = lock.getAttribute('data-salt');
  var ivB64 = lock.getAttribute('data-iv');
  var cipherB64 = lock.getAttribute('data-cipher');

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---- build the lock UI ----
  lock.innerHTML =
    '<div class="pl-card">' +
    '  <div class="pl-icon" aria-hidden="true"></div>' +
    '  <h2 class="pl-title">Protected post</h2>' +
    '  <p class="pl-desc">This content is encrypted. Enter the password to read it.</p>' +
    '  <form class="pl-form" autocomplete="off">' +
    '    <input class="pl-input" type="password" placeholder="Password" aria-label="Password" autocomplete="off" spellcheck="false">' +
    '    <button class="pl-btn" type="submit">Unlock</button>' +
    '  </form>' +
    '  <p class="pl-error" hidden>Wrong password — try again.</p>' +
    '</div>';

  var form = lock.querySelector('.pl-form');
  var input = lock.querySelector('.pl-input');
  var btn = lock.querySelector('.pl-btn');
  var error = lock.querySelector('.pl-error');

  function decrypt(password) {
    var enc = new TextEncoder();
    var salt = b64ToBytes(saltB64);
    var iv = b64ToBytes(ivB64);
    var payload = b64ToBytes(cipherB64);

    return crypto.subtle
      .importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey'])
      .then(function (baseKey) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
          baseKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['decrypt']
        );
      })
      .then(function (key) {
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, payload);
      })
      .then(function (buf) {
        return new TextDecoder().decode(buf);
      });
  }

  function reveal(html) {
    var content = lock.closest('.content') || lock.parentElement;
    // replace the whole content with the decrypted HTML
    content.innerHTML = html;
    content.classList.add('unlocked');
    // re-init lightbox for any images that were decrypted
    if (window.GLightbox) {
      try { window.GLightbox({ selector: '.content .popup, .content .img-link' }); } catch (e) {}
    }
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var pw = input.value;
    if (!pw) return;
    error.hidden = true;
    btn.disabled = true;
    btn.textContent = 'Unlocking…';
    decrypt(pw)
      .then(function (html) { reveal(html); })
      .catch(function () {
        btn.disabled = false;
        btn.textContent = 'Unlock';
        error.hidden = false;
        input.value = '';
        input.focus();
        lock.querySelector('.pl-card').classList.remove('shake');
        // reflow to restart the shake animation
        void lock.offsetWidth;
        lock.querySelector('.pl-card').classList.add('shake');
      });
  });
})();
