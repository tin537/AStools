# General ProGuard rules for an Android application
-keepattributes *Annotation*, Signature
-dontwarn okio.**
-dontwarn javax.annotation.**

# Keep application classes that extend Android components
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider
-keep public class * extends android.app.backup.BackupAgentHelper
-keep public class * extends android.preference.Preference

# Keep classes that use JNI
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep custom views and their setters
-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet);
}
-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet, int);
}
-keepclassmembers class * extends android.view.View {
    void set*(***);
    *** get*();
}

# Keep methods in Activity that could be used in the XML
-keepclassmembers class * extends android.app.Activity {
   public void *(android.view.View);
}

# Keep enums
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Preserve all native method names and the names of their classes
-keepclasseswithmembernames class * {
    native <methods>;
}

# Prevent obfuscating Serializable classes and methods
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# Keep Xposed and related classes
-keep class de.robv.android.xposed.** { *; }
-keep class * implements de.robv.android.xposed.IXposedHookLoadPackage { *; }

# Keep classes and methods that are used by reflection
-keepclassmembers class yyyyy.xxxx.zzzzzz.Module {
    private void sendToTestDotCom2(java.lang.String);
    private java.lang.String bytesToHex(byte[]);
    public void handleLoadPackage(de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam);
}

# Keep OkHttpClient and related classes
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# Keep classes for JSON processing
-keep class org.json.** { *; }

# Keep WebView methods
-keepclassmembers class android.webkit.WebView {
    public void loadUrl(java.lang.String);
    public void loadData(java.lang.String, java.lang.String, java.lang.String);
}

# Keep encryption classes
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }
-keep class javax.crypto.spec.** { *; }

# Keep logging
-keep class android.util.Log { *; }

# Keep Base64
-keep class android.util.Base64 { *; }
