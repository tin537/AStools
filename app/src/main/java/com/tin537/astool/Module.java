package com.tin537.astool;

import static java.lang.reflect.Array.newInstance;

import static de.robv.android.xposed.XposedHelpers.callMethod;
import static de.robv.android.xposed.XposedHelpers.callStaticMethod;
import static de.robv.android.xposed.XposedHelpers.findAndHookConstructor;
import static de.robv.android.xposed.XposedHelpers.findClass;
import static de.robv.android.xposed.XposedHelpers.getObjectField;
import static de.robv.android.xposed.XposedHelpers.setObjectField;

import android.os.Build;
import android.util.Base64;
import android.util.Log;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.apache.http.conn.scheme.HostNameResolver;

import java.net.Socket;
import java.net.URI;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

class EmptyTrustManager implements X509TrustManager {

    private static TrustManager[] emptyTM = null;

    public static TrustManager[] getInstance(){
        if (emptyTM == null) {
            emptyTM = new TrustManager[1];
            emptyTM[0] = new EmptyTrustManager();
        }
        return emptyTM;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

public class Module implements IXposedHookLoadPackage {
    private static final String TAG = "ASTools";
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private ThreadLocal<String> lastKey = new ThreadLocal<>();
    private ThreadLocal<String> lastIv = new ThreadLocal<>();
    private ThreadLocal<Integer> lastMode = new ThreadLocal<>();
    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {


        try {
            XposedHelpers.findAndHookMethod(WebView.class, "loadUrl", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String url = (String) param.args[0];
                    URI uri = new URI(url);
                    String host = uri.getHost();
                    if ("about:blank".equals(url)) {
                        WebView webView = (WebView) param.thisObject;
                        webView.loadData("ok", "text/html", "UTF-8");
                        param.setResult(null);  // Stop further execution of the original method
                    }
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Error hooking onReceivedError");
        }
        try {
            // Hook Cipher.init to capture the secret key, IV in Base64, and mode
            XposedHelpers.findAndHookMethod(
                    Cipher.class,
                    "init",
                    int.class, Key.class, AlgorithmParameterSpec.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            int mode = (int) param.args[0];
                            lastMode.set(mode);

                            if (param.args[1] instanceof SecretKeySpec) {
                                byte[] keyBytes = ((SecretKeySpec) param.args[1]).getEncoded();
                                lastKey.set(Base64.encodeToString(keyBytes, Base64.DEFAULT));
                            }

                            if (param.args[2] instanceof IvParameterSpec) {
                                byte[] ivBytes = ((IvParameterSpec) param.args[2]).getIV();
                                lastIv.set(Base64.encodeToString(ivBytes, Base64.DEFAULT));
                            }
                        }
                    }
            );
        } catch (Error e) {
            Log.e(TAG, "Error hooking onReceivedError");
        }
        try {
            XposedBridge.hookAllMethods(MessageDigest.class, "update", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.thisObject instanceof MessageDigest && "SHA-256".equals(((MessageDigest) param.thisObject).getAlgorithm())) {
                        byte[] input = (byte[]) param.args[0];
                        XposedBridge.log("SHA-256 update input by " + lpparam.packageName + ": " + new String(input));
                    }
                }
            });

            XposedBridge.hookAllMethods(MessageDigest.class, "digest", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.thisObject instanceof MessageDigest && "SHA-256".equals(((MessageDigest) param.thisObject).getAlgorithm())) {
                        XposedBridge.log("SHA-256 digest called by " + lpparam.packageName);
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.thisObject instanceof MessageDigest && "SHA-256".equals(((MessageDigest) param.thisObject).getAlgorithm())) {
                        byte[] hash = (byte[]) param.getResult();
                        String hexHash = bytesToHex(hash);
                        XposedBridge.log("SHA-256 hash output by " + lpparam.packageName + ": " + hexHash);
                    }
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Error hooking into SHA256()");
        }
        try {
            XposedHelpers.findAndHookMethod(
                    Cipher.class,
                    "doFinal",
                    byte[].class,
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            if (lastMode.get() == Cipher.ENCRYPT_MODE) {
                                byte[] plaintext = (byte[]) param.args[0];
                                System.out.println("e2e: Plaintext (Before Encryption): " + new String(plaintext));
                                System.out.println("e2e: Using Key (Base64): " + lastKey.get());
                                System.out.println("e2e: Using IV (Base64): " + lastIv.get());
                            }
                        }
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            XposedHelpers.findAndHookMethod(
                                    Cipher.class,
                                    "doFinal",
                                    byte[].class,
                                    new XC_MethodHook() {
                                        @Override
                                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                            if (lastMode.get() == Cipher.DECRYPT_MODE) {
                                                byte[] result = (byte[]) param.getResult(); // Get the result of the doFinal method.
                                                if (result != null) {
                                                    String decryptedText = new String(result);
                                                    System.out.println("e2e: Plaintext (After Decryption): " + decryptedText);
                                                }
                                            }
                                        }
                                    }
                            );}
                    }
            );
        } catch (Error e) {
            Log.e(TAG, "Error hooking onReceivedError");
        }
        // bypass SSL
        final X509TrustManager[] x509TrustManagerArr = {new X509TrustManager() { // from class: io.github.tehcneko.sslunpinning.SSLUnpinning.1
            @Override // javax.net.ssl.X509TrustManager
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override // javax.net.ssl.X509TrustManager
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override // javax.net.ssl.X509TrustManager
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};
        try {
            XposedHelpers.findAndHookMethod("javax.net.ssl.TrustManagerFactory", lpparam.classLoader, "getTrustManagers", new Object[]{XC_MethodReplacement.returnConstant(x509TrustManagerArr)});
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            XposedHelpers.findAndHookMethod("javax.net.ssl.SSLContext", lpparam.classLoader, "init", new Object[]{KeyManager[].class, TrustManager[].class, SecureRandom.class, new XC_MethodHook() { // from class: io.github.tehcneko.sslunpinning.SSLUnpinning.2
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.args[0] = null;
                    param.args[1] = x509TrustManagerArr;
                    param.args[2] = null;
                }
            }});
        } catch (Error e2) {
            Log.e(TAG, "Unpinning error", e2);
        }
        try {
            XposedHelpers.findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setSSLSocketFactory", new Object[]{org.apache.http.conn.ssl.SSLSocketFactory.class, new XC_MethodHook() { // from class: io.github.tehcneko.sslunpinning.SSLUnpinning.3
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.args[0] = XposedHelpers.newInstance(org.apache.http.conn.ssl.SSLSocketFactory.class, new Object[0]);
                }
            }});
        } catch (Error e3) {
            Log.e(TAG, "Unpinning error", e3);
        }
        XposedHelpers.findAndHookMethod("org.apache.http.conn.scheme.SchemeRegistry", lpparam.classLoader, "register", new Object[]{"org.apache.http.conn.scheme.Scheme", new XC_MethodHook() { // from class: io.github.tehcneko.sslunpinning.SSLUnpinning.4
            protected void beforeHookedMethod(MethodHookParam param) {
                Object obj = param.args[0];
                if (callMethod(obj, "getName", new Object[0]) == "https") {
                    param.args[0] = XposedHelpers.newInstance(obj.getClass(), new Object[]{"https", org.apache.http.conn.ssl.SSLSocketFactory.getSocketFactory(), 443});
                }
            }
        }});
        try {
            XposedHelpers.findAndHookMethod("org.apache.http.conn.ssl.HttpsURLConnection", lpparam.classLoader, "setDefaultHostnameVerifier", new Object[]{HostnameVerifier.class, new XC_MethodHook() { // from class: io.github.tehcneko.sslunpinning.SSLUnpinning.5
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.args[0] = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                }
            }});
        } catch (Error e4) {
            Log.e(TAG, "Unpinning error", e4);
        }
        try {
            XposedHelpers.findAndHookMethod("org.apache.http.conn.ssl.HttpsURLConnection", lpparam.classLoader, "setHostnameVerifier", new Object[]{HostnameVerifier.class, new XC_MethodHook() { // from class: io.github.tehcneko.sslunpinning.SSLUnpinning.6
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.args[0] = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                }
            }});
        } catch (Error e5) {
            Log.e(TAG, "Unpinning error", e5);
        }
        try {
            XposedHelpers.findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "getSocketFactory", new Object[]{new XC_MethodHook() { // from class: io.github.tehcneko.sslunpinning.SSLUnpinning.7
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(XposedHelpers.newInstance(org.apache.http.conn.ssl.SSLSocketFactory.class, new Object[0]));
                }
            }});
        } catch (Error e6) {
            Log.e(TAG, "Unpinning error", e6);
        }
        try {
            findAndHookConstructor(findClass("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader), new Object[]{String.class, KeyStore.class, String.class, KeyStore.class, SecureRandom.class, HostNameResolver.class, new XC_MethodHook() { // from class: io.github.tehcneko.sslunpinning.SSLUnpinning.8
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    String str = (String) param.args[0];
                    KeyStore keyStore = (KeyStore) param.args[1];
                    String str2 = (String) param.args[2];
                    SecureRandom secureRandom = (SecureRandom) param.args[4];
                    KeyManager[] keyManagerArr = keyStore != null ? (KeyManager[]) callStaticMethod(org.apache.http.conn.ssl.SSLSocketFactory.class, "createKeyManagers", new Object[]{keyStore, str2}) : null;
                    setObjectField(param.thisObject, "sslcontext", SSLContext.getInstance(str));
                    callMethod(getObjectField(param.thisObject, "sslcontext"), "init", new Object[]{keyManagerArr, x509TrustManagerArr, secureRandom});
                    setObjectField(param.thisObject, "socketfactory", callMethod(getObjectField(param.thisObject, "sslcontext"), "getSocketFactory", new Object[0]));
                }
            }});
        } catch (Error e7) {
            Log.e(TAG, "Unpinning error", e7);
        }
        try {
            XposedHelpers.findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "isSecure", new Object[]{Socket.class, XC_MethodReplacement.returnConstant(true)});
        } catch (Error e8) {
            Log.e(TAG, "Unpinning error", e8);
        }
        try {
            XposedHelpers.findAndHookMethod("okhttp3.CertificatePinner", lpparam.classLoader, "findMatchingPins", new Object[]{String.class, new XC_MethodHook() { // from class: io.github.tehcneko.sslunpinning.SSLUnpinning.9
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.args[0] = "";
                }
            }});
        } catch (Error e9) {
            Log.e(TAG, "Unpinning error", e9);
        }

        try {
            // --- Java Secure Socket Extension (JSSE) ---

            //TrustManagerFactory.getTrustManagers >> EmptyTrustManager
            XposedHelpers.findAndHookMethod("javax.net.ssl.TrustManagerFactory", lpparam.classLoader, "getTrustManagers", new XC_MethodHook() {

                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                    TrustManager[] tms = EmptyTrustManager.getInstance();
                    param.setResult(tms);
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            //SSLContext.init >> (null,EmptyTrustManager,null)
            XposedHelpers.findAndHookMethod("javax.net.ssl.SSLContext", lpparam.classLoader, "init", KeyManager[].class, TrustManager[].class, SecureRandom.class, new XC_MethodHook() {

                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.args[0] = null;
                    param.args[1] = EmptyTrustManager.getInstance();
                    param.args[2] = null;
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            //HttpsURLConnection.setSSLSocketFactory >> new SSLSocketFactory
            XposedHelpers.findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setSSLSocketFactory", javax.net.ssl.SSLSocketFactory.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.args[0] = XposedHelpers.newInstance(javax.net.ssl.SSLSocketFactory.class);
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        // --- APACHE ---
        try {
            //HttpsURLConnection.setDefaultHostnameVerifier >> SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER
            XposedHelpers.findAndHookMethod("org.apache.http.conn.ssl.HttpsURLConnection", lpparam.classLoader, "setDefaultHostnameVerifier",
                    HostnameVerifier.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            param.args[0] = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                        }
                    });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            //HttpsURLConnection.setHostnameVerifier >> SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER
            XposedHelpers.findAndHookMethod("org.apache.http.conn.ssl.HttpsURLConnection", lpparam.classLoader, "setHostnameVerifier", HostnameVerifier.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            param.args[0] = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                        }
                    });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            //SSLSocketFactory.getSocketFactory >> new SSLSocketFactory
            XposedHelpers.findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "getSocketFactory", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult((org.apache.http.conn.ssl.SSLSocketFactory) XposedHelpers.newInstance(org.apache.http.conn.ssl.SSLSocketFactory.class));
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            //SSLSocketFactory(...) >> SSLSocketFactory(...){ new EmptyTrustManager()}
            Class<?> sslSocketFactory = findClass("org.apache.http.conn.ssl.SSLSocketFactory",lpparam.classLoader);
            findAndHookConstructor(sslSocketFactory, String.class, KeyStore.class, String.class, KeyStore.class,
                    SecureRandom.class, HostNameResolver.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                            String algorithm = (String) param.args[0];
                            KeyStore keystore = (KeyStore) param.args[1];
                            String keystorePassword = (String) param.args[2];
                            SecureRandom random = (SecureRandom) param.args[4];

                            KeyManager[] keymanagers = null;
                            TrustManager[] trustmanagers;

                            if (keystore != null) {
                                keymanagers = (KeyManager[]) callStaticMethod(org.apache.http.conn.ssl.SSLSocketFactory.class, "createKeyManagers", keystore, keystorePassword);
                            }

                            trustmanagers = new TrustManager[]{new EmptyTrustManager()};

                            setObjectField(param.thisObject, "sslcontext", SSLContext.getInstance(algorithm));
                            callMethod(getObjectField(param.thisObject, "sslcontext"), "init", keymanagers, trustmanagers, random);
                            setObjectField(param.thisObject, "socketfactory", callMethod(getObjectField(param.thisObject, "sslcontext"), "getSocketFactory"));
                        }

                    });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }

        try {
            //SSLSocketFactory.isSecure >> true
            XposedHelpers.findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "isSecure", Socket.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(true);
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        // --- OKHTTP ---
        try {
            // Hook the method that sets the SSLSocketFactory on the OkHttpClient.Builder class
            XposedHelpers.findAndHookMethod("okhttp3.OkHttpClient$Builder", lpparam.classLoader, "sslSocketFactory", javax.net.ssl.SSLSocketFactory.class, X509TrustManager.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    TrustManager[] trustManagers = EmptyTrustManager.getInstance();
                    sslContext.init(null, trustManagers, new SecureRandom());
                    javax.net.ssl.SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                    param.args[0] = sslSocketFactory;
                    param.args[1] = (X509TrustManager) trustManagers[0];
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            // Hook the method that sets the hostname verifier to allow all hosts
            XposedHelpers.findAndHookMethod("okhttp3.OkHttpClient$Builder", lpparam.classLoader, "hostnameVerifier", HostnameVerifier.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    HostnameVerifier allowAllHostnameVerifier = (hostname, session) -> true;
                    param.args[0] = allowAllHostnameVerifier;
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            // Hook the CertificatePinner class to bypass certificate pinning
            XposedHelpers.findAndHookMethod("okhttp3.CertificatePinner", lpparam.classLoader, "check", String.class, List.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(null);
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            XposedHelpers.findAndHookMethod("okhttp3.CertificatePinner", lpparam.classLoader, "findMatchingPins", String.class, List.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(null);
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            XposedHelpers.findAndHookMethod(
                    "okhttp3.internal.tls.OkHostnameVerifier",
                    lpparam.classLoader,
                    "verify",
                    String.class,
                    SSLSession.class,
                    new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                            return true; // Always trust the hostname
                        }
                    }
            );
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            XposedHelpers.findAndHookMethod(
                    "okhttp3.mockwebserver.MockWebServer$Companion$UNTRUSTED_TRUST_MANAGER$1",
                    lpparam.classLoader,
                    "getAcceptedIssuers",
                    new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                            return new X509Certificate[0]; // empty list of accepted issuers
                        }
                    }
            );
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {

            // Bypass OkHttpClient's setCertificatePinner method
            XposedHelpers.findAndHookMethod("com.squareup.okhttp.OkHttpClient", lpparam.classLoader, "setCertificatePinner", "com.squareup.okhttp.CertificatePinner", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("OkHttpClient.setCertificatePinner Called!");
                    param.setResult(null);
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            // Invalidate the CertificatePinner checks
            XposedHelpers.findAndHookMethod("com.squareup.okhttp.CertificatePinner", lpparam.classLoader, "check", String.class, Certificate[].class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("okhttp Called! [Certificate]");
                    param.setResult(null);
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            XposedHelpers.findAndHookMethod("com.squareup.okhttp.CertificatePinner", lpparam.classLoader, "check", String.class, List.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("okhttp Called! [List]");
                    param.setResult(null);
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Unpinning error", e);
        }
        try {
            XposedHelpers.findAndHookMethod(WebViewClient.class, "onReceivedSslError",
                    "android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            XposedBridge.log("WebViewClient onReceivedSslError invoked");
                            Object sslErrorHandler = param.args[1];
                            callMethod(sslErrorHandler, "proceed");
                            param.setResult(null);
                        }
                    });
        } catch (Error e) {
            Log.e(TAG, "Error hooking onReceivedSslError", e);
        }

        // Hook the onReceivedError methods of WebViewClient (Overload 1)
        try {
            XposedHelpers.findAndHookMethod(WebViewClient.class, "onReceivedError",
                    WebView.class, int.class, String.class, String.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            int errorCode = (int) param.args[1];
                            String description = (String) param.args[2];

                            if (description.contains("net::ERR_FAILED")) {
                                WebView webView = (WebView) param.args[0];
                                webView.loadData("ok", "text/html", "UTF-8");
                                param.setResult(null);
                            }
                        }
                    });
        } catch (Error e) {
            Log.e(TAG, "Error hooking onReceivedError (Overload 1)", e);
        }

        // Hook the onReceivedError methods of WebViewClient (Overload 2)
        try {
            XposedHelpers.findAndHookMethod(WebViewClient.class, "onReceivedError",
                    "android.webkit.WebView", "android.webkit.WebResourceRequest", "android.webkit.WebResourceError", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            XposedBridge.log("WebViewClient onReceivedError invoked");
                            param.setResult(null);
                        }
                    });
        } catch (Error e) {
            Log.e(TAG, "Error hooking onReceivedError (Overload 2)", e);
        }
        try {
            XposedHelpers.findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl", lpparam.classLoader, "checkTrustedRecursive",
                    // Assuming it has 6 parameters of type Object as your JavaScript code does not specify their types.
                    Object.class, Object.class, Object.class, Object.class, Object.class, Object.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            XposedBridge.log("Bypassing SSL Pinning");
                            // Return an empty array instead of a list
                            param.setResult(new Object[0]);
                        }
                    });
        } catch (Error e) {
            Log.e(TAG, "Error hooking onReceivedError (Overload 2)", e);
        }
        try {
            XposedBridge.hookAllMethods(WebView.class, "loadUrl", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    WebView webView = (WebView) param.thisObject;
                    String url = (String) param.args[0];

                    XposedBridge.log("Enable webview debug for URL: " + url);

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                        WebView.setWebContentsDebuggingEnabled(true);
                    }
                }
            });
        } catch (Error e) {
            Log.e(TAG, "Error hooking onReceivedError (Overload 2)", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }
}