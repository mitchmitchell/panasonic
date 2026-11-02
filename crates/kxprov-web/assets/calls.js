(function () {
  var marker = document.getElementById("live-tail");
  if (!marker || !window.EventSource) {
    return;
  }
  var since = marker.getAttribute("data-since-id");
  var newest = since ? Number(since) : 0;
  var source = new EventSource(
    since ? "/calls/stream?since_id=" + encodeURIComponent(since) : "/calls/stream"
  );
  var fmt = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Chicago",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false, timeZoneName: "short"
  });
  function cell(row, text) {
    var td = document.createElement("td");
    td.textContent = text == null ? "" : String(text);
    row.appendChild(td);
  }
  source.addEventListener("call", function (e) {
    var body = document.querySelector("table.calls tbody");
    if (!body) {
      source.close();
      window.location.reload();
      return;
    }
    var c = JSON.parse(e.data);
    if (c.id <= newest) {
      return;
    }
    newest = c.id;
    var row = document.createElement("tr");
    cell(row, fmt.format(new Date(c.rx_ts_utc)).replace(",", ""));
    cell(row, c.ext);
    cell(row, c.co);
    cell(row, c.direction === "outgoing" ? "Outgoing" : "Incoming");
    cell(row, c.number);
    cell(row, c.cid_text);
    cell(row, c.ring_s);
    cell(row, c.duration_s);
    body.insertBefore(row, body.firstChild);
  });
  source.addEventListener("lagged", function () {
    source.close();
    window.location.reload();
  });
})();
