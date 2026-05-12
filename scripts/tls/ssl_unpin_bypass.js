// @name     SSL Pinning Bypass (Universal)
// @category tls
// @description Disables certificate pinning across OkHttp3, TrustManager,
//              HostnameVerifier, WebViewClient, HttpsURLConnection, and the
//              native SSL_CTX layer. Covers the vast majority of Android apps.
// @version  1.0

// =============================================================================
// FRIDALINK SYNTAX REQUIREMENT
// =============================================================================
// Scripts loaded through FridaLink MUST emit events using this exact send()
// shape so the sidecar can parse and display them in the Live Feed tab:
//
//   send({
//       type:          'fridalink_event',   // <-- REQUIRED
//       timestamp:     new Date().toISOString(),
//       thread_id:     String(Process.getCurrentThreadId()),
//       script_source: TAG,
//       severity:      'info' | 'warn' | 'error',
//       category:      'tls' | 'java' | 'native' | 'http' | 'script' | ...,
//       module:        'ClassName' | 'library.so',
//       target:        'methodName' | 'url' | 'symbol',
//       summary:       'Human readable one-liner shown in the Live Feed table',
//   });
//
// Plain send() calls that omit type:'fridalink_event' are still forwarded to
// Burp but appear as raw unstructured messages and cannot be filtered by
// category, module, or severity in the Live Feed.
// =============================================================================

'use strict';

const TAG = 'ssl_unpin_bypass';

function emit(fields) {
    send(Object.assign({
        type:          'fridalink_event',
        timestamp:     new Date().toISOString(),
        thread_id:     String(Process.getCurrentThreadId()),
        script_source: TAG,
        severity:      'info',
    }, fields));
}

// =============================================================================
// JAVA-LAYER BYPASSES
// Poll until the Android Runtime (ART) is ready before calling Java.*.
// Using setImmediate() instead of this polling pattern will crash on spawn.
// =============================================================================
(function waitForJava() {
    if (typeof Java === 'undefined' || !Java.available) {
        setTimeout(waitForJava, 50);
        return;
    }

    Java.perform(function () {

        // -- 1. Generic X509TrustManager --------------------------------------
        // Installs a trust-all TrustManager as the system default SSLContext.
        // Covers HttpsURLConnection, Retrofit (default), Volley, and any lib
        // that delegates to the system SSL context.
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext       = Java.use('javax.net.ssl.SSLContext');

            var TrustAll = Java.registerClass({
                name: 'com.fridalink.bypass.TrustAll',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; },
                },
            });

            var ctx = SSLContext.getInstance('TLS');
            ctx.init(null, [TrustAll.$new()], null);
            SSLContext.setDefault(ctx);

            emit({ category: 'tls', module: 'SSLContext', target: 'TrustAll',
                   summary: 'Generic X509TrustManager replaced with trust-all' });
        } catch(e) {
            emit({ category: 'tls', module: 'SSLContext', target: 'TrustAll',
                   summary: 'TrustAll install failed: ' + e, severity: 'warn' });
        }

        // -- 2. HostnameVerifier -----------------------------------------------
        try {
            var HostnameVerifier   = Java.use('javax.net.ssl.HostnameVerifier');
            var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');

            var AllowAll = Java.registerClass({
                name: 'com.fridalink.bypass.AllowAllHostnames',
                implements: [HostnameVerifier],
                methods: {
                    verify: function(hostname, session) { return true; },
                },
            });

            HttpsURLConnection.setDefaultHostnameVerifier(AllowAll.$new());
            emit({ category: 'tls', module: 'HttpsURLConnection',
                   target: 'HostnameVerifier', summary: 'HostnameVerifier set to allow-all' });
        } catch(e) {
            emit({ category: 'tls', module: 'HttpsURLConnection', target: 'HostnameVerifier',
                   summary: 'HostnameVerifier bypass failed: ' + e, severity: 'warn' });
        }

        // -- 3. OkHttp3 CertificatePinner -------------------------------------
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');

            CertificatePinner.check.overload('java.lang.String', 'java.util.List')
                .implementation = function(hostname) {
                    emit({ category: 'tls', module: 'CertificatePinner', target: hostname,
                           summary: 'OkHttp3 pin check bypassed for ' + hostname });
                };

            try {
                CertificatePinner.check.overload('java.lang.String', 'java.security.cert.Certificate')
                    .implementation = function(hostname) {
                        emit({ category: 'tls', module: 'CertificatePinner', target: hostname,
                               summary: 'OkHttp3 pin check (cert) bypassed for ' + hostname });
                    };
            } catch(_) {}

            emit({ category: 'tls', module: 'OkHttp3', target: 'CertificatePinner',
                   summary: 'OkHttp3 CertificatePinner hooked' });
        } catch(e) {
            emit({ category: 'tls', module: 'OkHttp3', target: 'CertificatePinner',
                   summary: 'OkHttp3 not present or hook failed: ' + e, severity: 'warn' });
        }

        // -- 4. OkHttp3 builder-level SSLSocketFactory override ---------------
        // Covers apps that supply their own TrustManager to OkHttpClient.Builder.
        try {
            var Builder       = Java.use('okhttp3.OkHttpClient$Builder');
            var X509TM2       = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext2   = Java.use('javax.net.ssl.SSLContext');

            var TrustAll2 = Java.registerClass({
                name: 'com.fridalink.bypass.TrustAll2',
                implements: [X509TM2],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; },
                },
            });

            Builder.sslSocketFactory.overload(
                'javax.net.ssl.SSLSocketFactory', 'javax.net.ssl.X509TrustManager'
            ).implementation = function() {
                var c2  = SSLContext2.getInstance('TLS');
                var tm2 = TrustAll2.$new();
                c2.init(null, [tm2], null);
                return this.sslSocketFactory(c2.getSocketFactory(), tm2);
            };

            emit({ category: 'tls', module: 'OkHttpClient.Builder',
                   target: 'sslSocketFactory', summary: 'OkHttp builder SSLSocketFactory hooked' });
        } catch(_) {}

        // -- 5. WebViewClient SSL error handler --------------------------------
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation =
                function(webView, handler, error) {
                    handler.proceed();
                    emit({ category: 'tls', module: 'WebViewClient',
                           target: 'onReceivedSslError',
                           summary: 'WebView SSL error suppressed: ' + error.toString(),
                           severity: 'warn' });
                };
            emit({ category: 'tls', module: 'WebViewClient',
                   target: 'onReceivedSslError', summary: 'WebViewClient SSL error hook active' });
        } catch(e) {
            emit({ category: 'tls', module: 'WebViewClient', target: 'onReceivedSslError',
                   summary: 'WebViewClient hook failed: ' + e, severity: 'warn' });
        }

        // -- 6. Android Network Security Config (Conscrypt TrustManagerImpl) --
        // Bypasses the platform-enforced network_security_config.xml pinning.
        try {
            var TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TMImpl.checkTrustedRecursive.implementation =
                function(certs, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                    emit({ category: 'tls', module: 'TrustManagerImpl', target: host,
                           summary: 'TrustManagerImpl check bypassed for ' + host });
                    return Java.use('java.util.ArrayList').$new();
                };
            emit({ category: 'tls', module: 'TrustManagerImpl',
                   target: 'checkTrustedRecursive',
                   summary: 'Network security config trust check bypassed' });
        } catch(_) {}

        emit({ category: 'script', module: TAG, target: 'load',
               summary: 'ssl_unpin_bypass: all Java-layer hooks active' });
    });
})();

// =============================================================================
// NATIVE-LAYER BYPASS
// Hooks SSL_CTX_set_verify in OpenSSL / BoringSSL to force SSL_VERIFY_NONE.
// Required for: Unity games, Flutter, Cronet, React Native custom builds,
// and any app that links TLS natively without going through the Java layer.
// =============================================================================
(function hookNativeSsl() {
    var LIBS = ['libssl.so', 'libboringssl.so', 'libflutter.so', 'libcronet.so'];
    var hooked = false;
    var zeroPtr = NULL;

    // Try well-known library names first
    for (var i = 0; i < LIBS.length; i++) {
        var ptr = null;
        try { ptr = Module.findExportByName(LIBS[i], 'SSL_CTX_set_verify'); } catch(_) {}
        if (ptr) {
            (function(p, libName) {
                Interceptor.attach(p, {
                    onEnter: function(args) {
                        args[1] = ptr.and(0);  // mode = SSL_VERIFY_NONE
                        args[2] = ptr.and(0);  // callback = NULL
                    },
                });
            })(ptr, LIBS[i]);
            emit({ category: 'tls', module: LIBS[i], target: 'SSL_CTX_set_verify',
                   summary: 'Native SSL_CTX_set_verify hooked in ' + LIBS[i] });
            hooked = true;
            break;
        }
    }

    // Fallback: scan all loaded modules
    if (!hooked) {
        var mods = Process.enumerateModules();
        for (var j = 0; j < mods.length; j++) {
            var ptr2 = null;
            try { ptr2 = mods[j].findExportByName('SSL_CTX_set_verify'); } catch(_) {}
            if (ptr2) {
                (function(p, modName) {
                    Interceptor.attach(p, {
                        onEnter: function(args) { args[1] = p.and(0); args[2] = p.and(0); },
                    });
                })(ptr2, mods[j].name);
                emit({ category: 'tls', module: mods[j].name, target: 'SSL_CTX_set_verify',
                       summary: 'Native SSL_CTX_set_verify hooked in ' + mods[j].name });
                hooked = true;
                break;
            }
        }
    }

    if (!hooked) {
        emit({ category: 'tls', module: 'native', target: 'SSL_CTX_set_verify',
               summary: 'SSL_CTX_set_verify not found — native bypass skipped',
               severity: 'warn' });
    }
})();
