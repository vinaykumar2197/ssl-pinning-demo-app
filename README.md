# Hi, I'm Vinay! 👋

# ssl-pinning-demo-app

A tiny demo app using SSL pinning to block HTTPS MitM interception.

Pressing each button will send an HTTP request with the corresponding configuration. The buttons are purple initially or while a request is in flight, and then turn green or red (with corresponding icons, and an error message popped up for failures) when the request succeeds/fails.

On a normal unintercepted device, every button should always immediately go green. On a device whose HTTPS is being intercepted (e.g. by [HTTP Toolkit](https://httptoolkit.tech/android)) all except the first button will go red, unless you've used Frida or similar to disable certificate pinning.

<img src="https://raw.githubusercontent.com/vinaykumar2197/ssl-pinning-demo-app/master/screenshot.png" width="600" height="400">

Let's talk about ssl pinning in android.

SSL ( Secure Sockets Layer )

### Benefits of SSL implementation in Android:
If ssl is implemented on app level. API request's can't be intercepted by tools such as http canary, charles, fiddler etc.

If http canary is enabled, and trying to access application ( which has ssl already implemented), you will get ssl error.
API request's won't be logged on these tools.

By implementing ssl pinning, api's can be secured and MITM ( man in the middle) attacks can be avoided.

### This connection ensures that all data passed between the server and app remain private and integral.


## Steps

```

Add networkSecurityConfig in AndroidManifest.xml like below: 

      <application
        android:networkSecurityConfig="@xml/network_security_config"
        />

```

### Make xml folder in res directory.

```
 res -> xml -> network_security_config.xml 


 <?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="false">untrusted-root.badssl.com</domain>
        <pin-set>
            <pin digest="SHA-256">sr2tjak7H6QRi8o0fyIXGWdPiU32rDsczcIEAqA+s4g=</pin>
        </pin-set>
        <trust-anchors>
            <certificates src="@raw/badssl_untrusted_root" />
        </trust-anchors>
    </domain-config>
</network-security-config>

```


### Make raw folder in res directory.

```
 res -> raw -> badssl_untrusted_root.pem  ( required if okhttp is used while pinning )
 res -> raw -> example_com_digicert_ca.pem  ( required if volley is used)

```


### There are 5 buttons in MainActivity.kt.

```
  Button 1 - > normal api request without ssl pinning. This request can be seen on tools like charles, fiddler, burp suite or http canary. 
  Since it's unpinned request. It includes url which is not their in network config as well.

      fun sendUnpinned(view: View) {
        GlobalScope.launch(Dispatchers.IO) {
            onStart(R.id.unpinned)
            try {
                val mURL = URL("https://badssl.com")
                with(mURL.openConnection() as HttpsURLConnection) {
                    println("URL: ${this.url}")
                    println("Response Code: ${this.responseCode}")
                }

                onSuccess(R.id.unpinned)
            } catch (e: Throwable) {
                println(e)
                onError(R.id.unpinned, e.toString())
            }
        }
    }
```

  ```
  Button 2 - > // Untrusted in system store, trusted & pinned in network config:
  It is using url which has been defined in network config.
   fun sendConfigPinned(view: View) {
        GlobalScope.launch(Dispatchers.IO) {
            onStart(R.id.config_pinned)
            try {
                // Untrusted in system store, trusted & pinned in network config:
                val mURL = URL("https://untrusted-root.badssl.com")
                with(mURL.openConnection() as HttpsURLConnection) {
                    println("URL: ${this.url}")
                    println("Response Code: ${this.responseCode}")
                }

                onSuccess(R.id.config_pinned)
            } catch (e: Throwable) {
                println(e)
                onError(R.id.config_pinned, e.toString())
            }
        }
    }


  ```


```
  Button 3 - > OkHttp Certicate Pinning 

  implementation 'com.squareup.okhttp3:okhttp:4.5.0'

      fun sendOkHttpPinned(view: View) {
        GlobalScope.launch(Dispatchers.IO) {
            onStart(R.id.okhttp_pinned)

            try {
                val hostname = "badssl.com"
                val certificatePinner = CertificatePinner.Builder()
                    // DigiCert SHA2 Secure Server CA (valid until March 2023)
                    .add(hostname, "sha256/aw2f0c8chnyyhYvpY+iyMuAJ5ufPfM26h+wh9C3zS1k=")
                    .build()

                val client = OkHttpClient.Builder()
                    .certificatePinner(certificatePinner)
                    .build()
                val request = Request.Builder()
                    .url("https://badssl.com")
                    .build();

                client.newCall(request).execute().use { response ->
                    println("URL: ${request.url}")
                    println("Response Code: ${response.code}")
                }

                onSuccess(R.id.okhttp_pinned)
            } catch (e: Throwable) {
                println(e)
                onError(R.id.okhttp_pinned, e.toString())
            }
        }
    }

  ```

  ```
  Button 4 - > implementation of ssl pinning using volley
  
  implementation 'com.android.volley:volley:1.2.0'

      fun sendVolleyPinned(view: View) {
        onStart(R.id.volley_pinned)

        try {
            // Create an HTTP client that only trusts our specific certificate:
            val cf = CertificateFactory.getInstance("X.509")
            val caStream = BufferedInputStream(resources.openRawResource(R.raw.example_com_digicert_ca))
            val ca = cf.generateCertificate(caStream)
            caStream.close()

            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(null, null)
            keyStore.setCertificateEntry("ca", ca)

            val trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm()
            val trustManagerFactory = TrustManagerFactory.getInstance(trustManagerAlgorithm)
            trustManagerFactory.init(keyStore)

            val context = SSLContext.getInstance("TLS")
            context.init(null, trustManagerFactory.trustManagers, null)

            val requestQueue = RequestQueue(
                NoCache(),
                BasicNetwork(HurlStack(null, context.socketFactory))
            )
            requestQueue.start()

            // Make a request using that client:
            val stringRequest = StringRequest(
                com.android.volley.Request.Method.GET,
                "https://example.com",
                { _ ->
                    println("Volley success")
                    this@MainActivity.onSuccess(R.id.volley_pinned)
                },
                {
                    println(it.toString())
                    this@MainActivity.onError(R.id.volley_pinned, it.toString())
                }
            )

            requestQueue.add(stringRequest)
        } catch (e: Throwable) {
            println(e)
            onError(R.id.volley_pinned, e.toString())
        }
    }


  ```

  ```
  Button 5 - > Using trustkit

  implementation 'com.datatheorem.android.trustkit:trustkit:1.1.3'


      fun sendTrustKitPinned(view: View) {
        GlobalScope.launch(Dispatchers.IO) {
            onStart(R.id.trustkit_pinned)
            try {
                val mURL = URL("https://untrusted-root.badssl.com")
                with(mURL.openConnection() as HttpsURLConnection) {
                    this.sslSocketFactory = TrustKit.getInstance().getSSLSocketFactory(
                            "untrusted-root.badssl.com"
                    )
                    println("URL: ${this.url}")
                    println("Response Code: ${this.responseCode}")
                }

                onSuccess(R.id.trustkit_pinned)
            } catch (e: Throwable) {
                println(e)
                onError(R.id.trustkit_pinned, e.toString())
            }
        }
    }



  ```

## Acknowledgements

- [Really thankful to httptoolkit for guidance ](https://github.com/httptoolkit)

## Authors

- [@Vinaykumar](https://www.github.com/vinaykumar2197)


## License
Copyright 2021 Vinaykumar Mishra

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
