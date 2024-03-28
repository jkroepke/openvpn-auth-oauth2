(async () => {
  const response = await fetch(`../assets/i18n/${navigator.language.split('-')[0]}.json`);
  if (!response.ok) return

  const json = await response.json();

  document.querySelectorAll("[data-i18n]").forEach(el => {
    if (el.innerText in json) {
      el.innerText = json[el.innerText];
    }
  });
})();
