// MyPrep Username Progress Persistence
// Drop this file into your project and load it before your main JS.
//
// Usage:
// 1. Give every progress checkbox a unique id.
// 2. Add <script src="progress.js"></script> before your main JS.
// 3. Call MyPrepProgress.init() after the dashboard is loaded.
// 4. Call MyPrepProgress.loadUser(username) when the username is entered.
//
// This version uses browser localStorage. Progress survives closing/reopening
// the site on the same browser/device. It is not a cross-device database.

(() => {
  const PREFIX = "myPrepProgress:";

  function cleanUsername(username) {
    return String(username || "").trim();
  }

  function key(username) {
    return PREFIX + cleanUsername(username).toLowerCase();
  }

  function read(username) {
    try {
      return JSON.parse(localStorage.getItem(key(username)) || "{}");
    } catch {
      return {};
    }
  }

  function write(username, progress) {
    localStorage.setItem(key(username), JSON.stringify(progress));
  }

  function getCheckboxes(root = document) {
    return [...root.querySelectorAll('input[type="checkbox"][id]')];
  }

  function saveUser(username) {
    username = cleanUsername(username);
    if (!username) return;

    const progress = {};
    getCheckboxes().forEach(cb => {
      progress[cb.id] = cb.checked;
    });

    write(username, progress);
    sessionStorage.setItem("myPrepCurrentUsername", username);
  }

  function loadUser(username) {
    username = cleanUsername(username);
    if (!username) return false;

    const progress = read(username);

    getCheckboxes().forEach(cb => {
      if (Object.prototype.hasOwnProperty.call(progress, cb.id)) {
        cb.checked = Boolean(progress[cb.id]);
      }
    });

    sessionStorage.setItem("myPrepCurrentUsername", username);
    return true;
  }

  function currentUser() {
    return sessionStorage.getItem("myPrepCurrentUsername") || "";
  }

  function logout() {
    sessionStorage.removeItem("myPrepCurrentUsername");
  }

  function init() {
    document.addEventListener("change", event => {
      const cb = event.target;
      if (!(cb instanceof HTMLInputElement) || cb.type !== "checkbox" || !cb.id) return;

      const username = currentUser();
      if (username) saveUser(username);
    });
  }

  window.MyPrepProgress = {
    init,
    loadUser,
    saveUser,
    currentUser,
    logout
  };
})();
