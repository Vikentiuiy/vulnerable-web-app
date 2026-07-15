// Client-side dashboard logic for the vulnerable lab.

// VULN:VULN-27:CWE-798 hard-coded API key / secret shipped to the browser
var API_KEY = "sk_live_9f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d";
var INTERNAL_ENDPOINT = "http://10.0.0.5:9000/internal";

(function () {
    // Read the URL fragment (e.g. #name=Alice) and greet the user.
    var raw = decodeURIComponent(location.hash.slice(1));
    var name = raw.replace(/^name=/, "") || "guest";

    // VULN:VULN-26:CWE-79 DOM-based XSS — untrusted fragment written via innerHTML
    document.getElementById("greeting").innerHTML = "Hello, " + name + "!";

    // Also reflects the `q` query parameter into the DOM without sanitisation.
    var params = new URLSearchParams(location.search);
    if (params.has("q")) {
        // VULN:VULN-26:CWE-79 DOM XSS — query param concatenated into innerHTML
        document.getElementById("output").innerHTML = "You searched: " + params.get("q");
    }

    // VULN:VULN-28:CWE-95 dynamic code evaluation of a URL-controlled value
    if (params.has("calc")) {
        document.getElementById("output").innerHTML += "<br>Result: " + eval(params.get("calc"));
    }
})();
