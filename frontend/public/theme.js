/* Set the colour theme before the first paint, so a dark-mode user never sees a white flash.
   A separate file because the Content-Security-Policy allows no inline script. */
(function () {
  var saved = null;
  try {
    saved = localStorage.getItem("kasauti-theme");
  } catch (e) {}
  var dark =
    saved === "dark" || (saved !== "light" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
})();
