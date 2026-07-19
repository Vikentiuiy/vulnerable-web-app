// Browser-side sinks for the lab. Served to the client, so everything here is
// attacker-visible and executes in the victim's browser.

// VULN:VULN-27:CWE-798:pattern hard-coded API key / secret shipped to the browser
var API_KEY = "sk_live_9f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d";
var INTERNAL_ENDPOINT = "http://10.0.0.5:9000/internal";

(function () {
    var params = new URLSearchParams(location.search);

    // Greet using the URL fragment (e.g. #name=Alice) or the `q` query param.
    var raw = decodeURIComponent(location.hash.slice(1));
    var name = raw.replace(/^name=/, "") || (params.get("q") || "guest");
    // VULN:VULN-26:CWE-79:taint DOM-based XSS — untrusted input written via innerHTML
    document.getElementById("greeting").innerHTML = "Hello, " + name + "!";

    // VULN:VULN-28:CWE-95:taint dynamic evaluation of a URL-controlled value
    if (params.has("calc")) {
        document.getElementById("output").innerHTML = "Result: " + eval(params.get("calc"));
    }
})();
