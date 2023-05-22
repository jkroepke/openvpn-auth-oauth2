(function () {
    const url = location.search.match(/url=([^&]+)/)
    if (url != null) {
        document.getElementById('url').innerText = document.getElementById('url').href = url[1]
    }
    const code = location.search.match(/code=([A-Z0-9]+)/)
    if (code != null) {
        document.getElementById('code').innerText = code[1]
    }

    document.getElementById('copy').onclick = () => navigator.clipboard.writeText(document.getElementById("code").innerText)
})();

