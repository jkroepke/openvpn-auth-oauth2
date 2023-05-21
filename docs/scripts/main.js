(function () {
    const code = location.search.match(/code=([A-Z0-9]+)/)
    if (code != null) {
        document.getElementById('code').innerText = code[1]
    }

    document.getElementById('copy').onclick = () => navigator.clipboard.writeText(document.getElementById("code").innerText)
})();

