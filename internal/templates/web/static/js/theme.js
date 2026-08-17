(function () {
  "use strict";

  document.querySelectorAll("[data-dialog-target]").forEach(function (button) {
    button.addEventListener("click", function () {
      var dialog = document.getElementById(button.dataset.dialogTarget);
      if (dialog && typeof dialog.showModal === "function") dialog.showModal();
    });
  });

  document.querySelectorAll("[data-dialog-close]").forEach(function (button) {
    button.addEventListener("click", function () {
      var dialog = button.closest("dialog");
      if (dialog) dialog.close();
    });
  });

  document.querySelectorAll("dialog.evidence-dialog").forEach(function (dialog) {
    dialog.addEventListener("click", function (event) {
      if (event.target === dialog) dialog.close();
    });
  });

  document.querySelectorAll("[data-custom-range-target]").forEach(function (select) {
    var target = document.getElementById(select.dataset.customRangeTarget);
    if (!target) return;
    var update = function () { target.hidden = select.value !== "custom"; };
    select.addEventListener("change", update);
    update();
  });

  var pad = function (value) { return String(value).padStart(2, "0"); };
  var toLocalDateTime = function (date) {
    return date.getFullYear() + "-" + pad(date.getMonth() + 1) + "-" + pad(date.getDate()) +
      "T" + pad(date.getHours()) + ":" + pad(date.getMinutes());
  };
  var todayStart = new Date();
  var todayEnd = new Date();
  todayStart.setHours(0, 0, 0, 0);
  todayEnd.setHours(23, 59, 0, 0);

  document.querySelectorAll("[data-day-start]").forEach(function (input) {
    if (!input.value) input.value = toLocalDateTime(todayStart);
  });

  document.querySelectorAll("[data-day-end]").forEach(function (input) {
    if (!input.value) input.value = toLocalDateTime(todayEnd);
  });
}());

