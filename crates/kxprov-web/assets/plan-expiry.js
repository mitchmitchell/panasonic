(function () {
  function formatRemaining(ms) {
    if (ms <= 0) {
      return "expired";
    }
    var totalSec = Math.floor(ms / 1000);
    var min = Math.floor(totalSec / 60);
    var sec = totalSec % 60;
    if (min > 0) {
      return min + " min " + sec + " sec left";
    }
    return sec + " sec left";
  }

  function tick(el) {
    var expiresMs = Number(el.getAttribute("data-expires-ms"));
    if (!Number.isFinite(expiresMs)) {
      return;
    }
    var remaining = expiresMs - Date.now();
    el.textContent = formatRemaining(remaining);
  }

  document.querySelectorAll(".plan-expiry-countdown").forEach(function (el) {
    tick(el);
    setInterval(function () {
      tick(el);
    }, 1000);
  });
})();
