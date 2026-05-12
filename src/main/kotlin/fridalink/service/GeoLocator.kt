package fridalink.service

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import fridalink.model.GeoResult
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Resolves hostnames / IPs to geolocation data.
 *
 * Provider chain (tried in order):
 *   1. ip-api.com  — free, no key, 45 req/min (batch counts as 1)
 *   2. ipwho.is    — free, no key, no published rate limit (fallback)
 *
 * DNS pre-resolution is OPTIONAL.  When the local machine cannot resolve a
 * hostname (VPN split-DNS, firewall, NDR blocking) the hostname is passed
 * directly to ip-api.com which resolves it server-side.  Only confirmed
 * private/RFC-1918 addresses are short-circuited to a LOCAL result.
 */
class GeoLocator {

    private val cache    = ConcurrentHashMap<String, GeoResult>()
    private val executor = Executors.newCachedThreadPool()
    private val mapper   = jacksonObjectMapper()

    // Fields requested from ip-api.com (single + batch).
    // "as" = AS number + org name.  "query" = IP actually resolved by ip-api.
    private val IP_API_FIELDS =
        "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,reverse,proxy,hosting,timezone,query"

    private val PRIVATE_RANGES = listOf(
        Regex("""^10\."""),
        Regex("""^192\.168\."""),
        Regex("""^172\.(1[6-9]|2\d|3[01])\."""),
        Regex("""^127\."""),
        Regex("""^169\.254\."""),
        Regex("""^::1$"""),
        Regex("""^fc|^fd"""),
    )

    // ----------------------------------------------------------------
    // Threat domain classification
    // ----------------------------------------------------------------

    val THREAT_DOMAINS: Map<String, String> = mapOf(
        // Ad networks & trackers
        "doubleclick.net"              to "Ad Tracker",
        "googleadservices.com"         to "Ad Tracker",
        "googlesyndication.com"        to "Ad Tracker",
        "admob.com"                    to "Ad Network",
        "adcolony.com"                 to "Ad Network",
        "applovin.com"                 to "Ad Network",
        "mopub.com"                    to "Ad Network",
        "unity3d.com"                  to "Unity Ads",
        "unityads.unity3d.com"         to "Unity Ads",
        "ironsrc.com"                  to "Ad Network (ironSource)",
        // Social / tracking
        "facebook.net"                 to "Facebook Tracker",
        "graph.facebook.com"           to "Facebook API",
        "connect.facebook.net"         to "Facebook SDK",
        // Analytics
        "amplitude.com"                to "Analytics (Amplitude)",
        "mixpanel.com"                 to "Analytics (Mixpanel)",
        "mparticle.com"                to "Analytics (mParticle)",
        "segment.io"                   to "Analytics (Segment)",
        "segment.com"                  to "Analytics (Segment)",
        "fullstory.com"                to "Analytics (FullStory)",
        "hotjar.com"                   to "Analytics (Hotjar)",
        "heap.io"                      to "Analytics (Heap)",
        // Attribution
        "appsflyer.com"                to "Attribution (AppsFlyer)",
        "adjust.com"                   to "Attribution (Adjust)",
        "branch.io"                    to "Attribution (Branch)",
        "kochava.com"                  to "Attribution (Kochava)",
        "singular.net"                 to "Attribution (Singular)",
        // Crash/performance
        "bugsnag.com"                  to "Crash Analytics",
        "sentry.io"                    to "Crash Analytics (Sentry)",
        "crashlytics.com"              to "Crash Analytics (Crashlytics)",
        "raygun.io"                    to "Crash Analytics",
        // Push / engagement
        "onesignal.com"                to "Push / Engagement",
        "clevertap.com"                to "Marketing Analytics",
        "intercom.io"                  to "CRM / Analytics",
        "braze.com"                    to "CRM (Braze)",
        // Chinese data entities — high risk for non-CN apps
        "bytedance.com"                to "Data Broker (CN — ByteDance)",
        "toutiao.com"                  to "Data Broker (CN — Toutiao)",
        "musical.ly"                   to "Data Broker (CN — ByteDance)",
        "tiktokv.com"                  to "Data Broker (CN — TikTok)",
        "snssdk.com"                   to "Data Broker (CN — ByteDance)",
        "tencent.com"                  to "Data Broker (CN — Tencent)",
        "qq.com"                       to "Data Broker (CN — Tencent)",
        "alibaba.com"                  to "Data Broker (CN — Alibaba)",
        "aliyun.com"                   to "Data Broker (CN — Alibaba)",
        "alicdn.com"                   to "Data Broker (CN — Alibaba)",
        // Suspicious hosting / tunnels
        "pastebin.com"                 to "Potential C2 (Pastebin)",
        "ngrok.io"                     to "Tunnel (Ngrok — suspicious in production)",
        "ngrok.app"                    to "Tunnel (Ngrok)",
    )

    private val SUSPICIOUS_TLDS = setOf(
        ".ru", ".cn", ".tk", ".xyz", ".top", ".club", ".pw", ".icu", ".gq", ".ml", ".cf"
    )

    fun classifyDomain(host: String): String {
        if (host.isBlank()) return ""
        val lower = host.lowercase().trimEnd('.')
        for ((suffix, label) in THREAT_DOMAINS) {
            if (lower == suffix || lower.endsWith(".$suffix")) return label
        }
        for (tld in SUSPICIOUS_TLDS) {
            if (lower.endsWith(tld)) return "Suspicious TLD ($tld)"
        }
        return ""
    }

    // ----------------------------------------------------------------
    // Public API
    // ----------------------------------------------------------------

    fun isPrivateIp(ip: String): Boolean = PRIVATE_RANGES.any { it.containsMatchIn(ip) }

    fun lookupAsync(hostOrIp: String, callback: (GeoResult) -> Unit) {
        if (hostOrIp.isBlank()) return
        cache[hostOrIp]?.let { callback(it); return }

        if (isPrivateIp(hostOrIp)) {
            val r = localResult(hostOrIp, hostOrIp)
            cache[hostOrIp] = r; callback(r); return
        }

        executor.submit {
            val resolvedIp = tryResolveLocally(hostOrIp)
            val result = when {
                // Local resolution succeeded and it's private — short circuit
                resolvedIp != null && isPrivateIp(resolvedIp) ->
                    localResult(resolvedIp, hostOrIp)
                // Either local resolution gave us an IP, or it failed — pass whatever we have
                // to ip-api.com (it can resolve hostnames server-side)
                else -> {
                    val queryTarget = resolvedIp ?: hostOrIp
                    fetchWithFallback(queryTarget).copy(host = hostOrIp, threatLabel = classifyDomain(hostOrIp))
                }
            }
            cache[hostOrIp] = result
            callback(result)
        }
    }

    /**
     * Batch-resolve up to 100 hosts per ip-api.com request.
     * When local DNS fails for a host, the hostname itself is passed to ip-api.com
     * so it can resolve server-side — critical for VPN/split-DNS environments.
     */
    fun lookupBatch(hosts: Collection<String>, callback: (String, GeoResult) -> Unit) {
        val distinct = hosts.distinct().filter { it.isNotBlank() }
        if (distinct.isEmpty()) return

        // Attempt local DNS resolution for all hosts (in-thread — fast for cached entries)
        val hostToLocalIp: Map<String, String?> = distinct.associateWith { tryResolveLocally(it) }

        val toFetch = mutableListOf<Pair<String, String>>() // (originalHost, queryTarget)

        for (host in distinct) {
            val cached = cache[host]
            if (cached != null) {
                callback(host, cached); continue
            }
            val localIp = hostToLocalIp[host]
            when {
                // Confirmed private IP — no external lookup
                (localIp != null && isPrivateIp(localIp)) || isPrivateIp(host) -> {
                    val r = localResult(localIp ?: host, host)
                    cache[host] = r; callback(host, r)
                }
                // Local resolution succeeded — use resolved IP for geo
                localIp != null -> toFetch.add(host to localIp)
                // Local DNS failed — pass hostname directly; ip-api.com will resolve
                else -> toFetch.add(host to host)
            }
        }

        if (toFetch.isEmpty()) return

        executor.submit {
            toFetch.chunked(100).forEach { chunk ->
                try {
                    fetchGeoBatch(chunk, callback)
                } catch (_: Exception) {
                    // Batch failed — fall back to individual lookups
                    chunk.forEach { (host, queryTarget) ->
                        val r = try {
                            fetchWithFallback(queryTarget).copy(host = host, threatLabel = classifyDomain(host))
                        } catch (_: Exception) {
                            failResult(queryTarget, "all providers failed").copy(host = host)
                        }
                        cache[host] = r; callback(host, r)
                    }
                }
            }
        }
    }

    fun getCached(hostOrIp: String): GeoResult? = cache[hostOrIp]
    fun allResults(): Map<String, GeoResult> = cache.toMap()

    // ----------------------------------------------------------------
    // Internal: DNS resolution
    // ----------------------------------------------------------------

    /** Returns null if the local machine cannot resolve the host — does NOT throw. */
    private fun tryResolveLocally(hostOrIp: String): String? {
        if (hostOrIp.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) return hostOrIp
        return try {
            InetAddress.getByName(hostOrIp).hostAddress
        } catch (_: UnknownHostException) { null }
          catch (_: Exception) { null }
    }

    // ----------------------------------------------------------------
    // Internal: ip-api.com (primary) + ipwho.is (fallback)
    // ----------------------------------------------------------------

    /** Try ip-api.com first; fall back to ipwho.is on rate-limit or error. */
    private fun fetchWithFallback(queryTarget: String): GeoResult =
        try { fetchIpApi(queryTarget) }
        catch (_: RateLimitException) { fetchIpWhoIs(queryTarget) }
        catch (_: Exception) {
            try { fetchIpWhoIs(queryTarget) }
            catch (e2: Exception) { failResult(queryTarget, e2.message ?: "all providers failed") }
        }

    /** ip-api.com single-host lookup — handles both raw IPs and hostnames. */
    private fun fetchIpApi(queryTarget: String): GeoResult {
        val conn = URL("http://ip-api.com/json/$queryTarget?fields=$IP_API_FIELDS")
            .openConnection() as HttpURLConnection
        conn.connectTimeout = 7000
        conn.readTimeout    = 7000
        conn.requestMethod  = "GET"
        conn.setRequestProperty("User-Agent", "FridaLink-Pentest/1.0")

        val code = conn.responseCode
        if (code == 429) throw RateLimitException("ip-api.com rate limited")
        if (code != 200) throw RuntimeException("ip-api.com HTTP $code")

        val json = conn.inputStream.bufferedReader().readText()
        @Suppress("UNCHECKED_CAST")
        val m = mapper.readValue(json, Map::class.java) as Map<String, Any?>
        if (m["status"] != "success") throw RuntimeException("ip-api.com: ${m["message"]}")

        return geoResultFromIpApi(m, queryTarget)
    }

    /** ip-api.com batch endpoint — up to 100 hosts per request. */
    private fun fetchGeoBatch(
        hostQueryPairs: List<Pair<String, String>>,
        callback: (String, GeoResult) -> Unit,
    ) {
        val queries = hostQueryPairs.map { it.second }
        val bodyJson = mapper.writeValueAsString(queries.map { mapOf("query" to it) })

        val conn = URL("http://ip-api.com/batch?fields=$IP_API_FIELDS")
            .openConnection() as HttpURLConnection
        conn.connectTimeout = 10000
        conn.readTimeout    = 10000
        conn.requestMethod  = "POST"
        conn.doOutput       = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("User-Agent", "FridaLink-Pentest/1.0")
        conn.outputStream.use { it.write(bodyJson.toByteArray()) }

        val httpCode = conn.responseCode
        if (httpCode == 429) throw RateLimitException("ip-api.com batch rate limited")
        if (httpCode != 200) throw RuntimeException("ip-api.com batch HTTP $httpCode")

        val responseText = conn.inputStream.bufferedReader().readText()
        @Suppress("UNCHECKED_CAST")
        val list = mapper.readValue(responseText, List::class.java) as List<Map<String, Any?>>

        list.forEachIndexed { i, m ->
            val (host, _) = hostQueryPairs[i]
            val result = if (m["status"] == "success") {
                geoResultFromIpApi(m, host).copy(host = host, threatLabel = classifyDomain(host))
            } else {
                // ip-api returned fail for this entry — try fallback individually
                try {
                    fetchIpWhoIs(queries[i]).copy(host = host, threatLabel = classifyDomain(host))
                } catch (_: Exception) {
                    failResult(queries[i], m["message"]?.toString() ?: "failed").copy(
                        host = host, threatLabel = classifyDomain(host))
                }
            }
            cache[host] = result
            callback(host, result)
        }
    }

    /**
     * ipwho.is fallback — no key required, no published rate limit.
     * Accepts both IPs and hostnames (it resolves hostnames internally).
     */
    private fun fetchIpWhoIs(queryTarget: String): GeoResult {
        val conn = URL("https://ipwho.is/$queryTarget")
            .openConnection() as HttpURLConnection
        conn.connectTimeout = 7000
        conn.readTimeout    = 7000
        conn.requestMethod  = "GET"
        conn.setRequestProperty("User-Agent", "FridaLink-Pentest/1.0")
        conn.setRequestProperty("Accept", "application/json")

        val code = conn.responseCode
        if (code != 200) throw RuntimeException("ipwho.is HTTP $code")

        val json = conn.inputStream.bufferedReader().readText()
        @Suppress("UNCHECKED_CAST")
        val m = mapper.readValue(json, Map::class.java) as Map<String, Any?>
        if (m["success"] as? Boolean != true) throw RuntimeException("ipwho.is: ${m["message"]}")

        @Suppress("UNCHECKED_CAST")
        val conn2 = m["connection"] as? Map<String, Any?> ?: emptyMap()
        @Suppress("UNCHECKED_CAST")
        val tz    = m["timezone"] as? Map<String, Any?> ?: emptyMap()

        val resolvedIp  = m["ip"]?.toString() ?: queryTarget
        val cc          = (m["country_code"]?.toString() ?: "").uppercase()
        val asnRaw      = conn2["asn"]?.toString() ?: ""
        val asnStr      = if (asnRaw.isNotBlank()) "AS$asnRaw" else ""
        val orgStr      = conn2["org"]?.toString() ?: ""
        val ispStr      = conn2["isp"]?.toString() ?: ""
        val domainStr   = conn2["domain"]?.toString() ?: ""

        return GeoResult(
            ip          = resolvedIp,
            host        = queryTarget,
            country     = m["country"]?.toString() ?: "",
            countryCode = cc,
            city        = m["city"]?.toString() ?: "",
            regionName  = m["region"]?.toString() ?: "",
            lat         = (m["latitude"] as? Number)?.toDouble() ?: 0.0,
            lon         = (m["longitude"] as? Number)?.toDouble() ?: 0.0,
            org         = orgStr,
            isp         = ispStr,
            asn         = asnStr,
            reverse     = domainStr,
            isProxy     = false,
            isHosting   = false,
            timezone    = tz["id"]?.toString() ?: "",
            isUS        = cc == "US",
            status      = "success",
            threatLabel = classifyDomain(queryTarget),
        )
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private fun geoResultFromIpApi(m: Map<String, Any?>, originalQuery: String): GeoResult {
        val resolvedIp = m["query"]?.toString() ?: originalQuery
        val cc         = m["countryCode"]?.toString() ?: ""
        return GeoResult(
            ip          = resolvedIp,
            host        = originalQuery,
            country     = m["country"]?.toString() ?: "",
            countryCode = cc,
            city        = m["city"]?.toString() ?: "",
            regionName  = m["regionName"]?.toString() ?: "",
            lat         = (m["lat"] as? Number)?.toDouble() ?: 0.0,
            lon         = (m["lon"] as? Number)?.toDouble() ?: 0.0,
            org         = m["org"]?.toString() ?: "",
            isp         = m["isp"]?.toString() ?: "",
            asn         = m["as"]?.toString() ?: "",
            reverse     = m["reverse"]?.toString() ?: "",
            isProxy     = m["proxy"] as? Boolean ?: false,
            isHosting   = m["hosting"] as? Boolean ?: false,
            timezone    = m["timezone"]?.toString() ?: "",
            isUS        = cc == "US",
            status      = "success",
            threatLabel = classifyDomain(originalQuery),
        )
    }

    private fun localResult(ip: String, host: String) = GeoResult(
        ip = ip, host = host,
        country = "Local/Private", countryCode = "LO",
        city = "LAN", regionName = "", lat = 0.0, lon = 0.0,
        org = "Private Network", isp = "Private Network",
        asn = "", reverse = "", isProxy = false, isHosting = false, timezone = "",
        isUS = false, status = "local", threatLabel = "",
    )

    private fun failResult(ip: String, msg: String) = GeoResult(
        ip = ip, host = ip,
        country = "Unknown", countryCode = "??",
        city = "", regionName = "", lat = 0.0, lon = 0.0,
        org = "", isp = "",
        asn = "", reverse = "", isProxy = false, isHosting = false, timezone = "",
        isUS = false, status = "fail:$msg",
        threatLabel = classifyDomain(ip),
    )

    private class RateLimitException(msg: String) : RuntimeException(msg)
}
