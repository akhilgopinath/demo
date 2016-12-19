
C!
W!
# Backends

backend F_AWS_Wordpress_Origin_Server {
    .first_byte_timeout = 600s;
    .connect_timeout = 600s;
    .max_connections = 800;
    .between_bytes_timeout = 600s;
    .share_key = "b9ji8kyU2F4O2KnrxTTdV";
    .port = "443";
    .host = "52.200.65.253";
  
    .ssl = true;
    .min_tls_version = "1.2";
    .ssl_ciphers = "ECDHE-RSA-AES128-GCM-SHA256:!RC4";
    .ssl_cert_hostname = "*.intellectseec.cloud";
    .ssl_check_cert = always;
    .ssl_client_key = {"-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDF6rcVeAXuyzre
b8OZfgYiwDCN5EnFG2fWYYJrs8B7cunhvd8EG9fU8f6a3DgtC4bguh0S5DR8vqg3
yamki0D3/pLZdJR819tJ2/PyjQn2G8CwqNj6DVqstkQ9tNCWkusSle8d58/uFS9m
XRsbmrn0ENCaGvrAdhBKM0p0KrfzSWTJQ976d0Qz1FQMcDnrRLIW1Od29HAnGgHZ
cie75dR2yUALhGMQlvXBTWTLKlWeZGjkJ8RG9xf9KGYqKeRSBMH5Q0B3uutd4xFf
l8AmRzin7+o1rUF0X+70dRXKfvWZ0W5cpUi6pCjBAiTU6CovJx8kk9YgkyjNybsa
v8ZilacLAgMBAAECggEBAI60HGqYbf6t/rZf87L60UXBOcE1d5NtnUNQb49kvkbE
pqqkEueNg+QA0MmsO70O8KOczlXOwaGofvYqq+z+k0u8/PlaO66AnZb1x0F+PE59
2EQImtpBQr4BddbgRv4q1OBDx3PSr3RFRjYSr/cJa0b10NMs3NxkxH4b2XVFT/lU
D4PC1SMi72+Pom8kzSr5wIIzxN3uLn1ktt9yNBk3LCuxWiTTdHKG2b6AG6AQlHmv
6hl/mq5fxzqZNmSCoCnETdtRS4N+xzp+p0ptu2wnf54zz8RYYVHXmebzcLEZN3Av
5xIw3Jzzl2ahbXQNAWt8GVqfZ4dq7c88uHFBogwzh3ECgYEA4StoFVSWLugSU1so
40roEJuj57Js+ex+pABI0bT5chfblixOXa2xj7P4IlFedNvGq5a3573LfQ8VkCrU
CCZgVDTI6ZnNfFiSD9t48j2pweYAz+Qd5wFeSgQCgdxdQjbtXvnuUeOAAiq0G/AZ
uOhHRyQqZv5+LASfJi/GQhkDdocCgYEA4QQNjyDCX58r0WSrB7R9B8k+5QoKjY8i
sfA2cCdNb+5+2rGY+0nDNmnw7SNMipkuR8RU6egKJg+bD044TyZoDAmLkAR/q6sl
zsUHE4vUWD9lcYo8xTHv1/rwgT9lJWVi8VQhjiGhk1OcS8KACDId9OUSJWKfvA5m
RhfJv6zdqF0CgYEAxPOeuumd47GCNf8KqKUgj0ZT+5oJ0CGYNAM7rpJJjg5oN9bR
RQdkxHl6lSnvIPALupK+kallkCHdjpinlelbYMw64HlzT0x5lf02sUxWbA+uriiu
Lxz3SG5xcv05ZW19+xFJ7766fSq1F6rQFPi3P/bWT/hSjFYOjuxC0hXm/YkCgYEA
lpi10nMkZAcNtojfhrqfa5SfCX+c7H09xUV1yb4kL6O5Nvjh4FzP0B07aBrV4XT/
6nxWMG5iTHLpXmcFfMPBozzIMU0xfV2AYlCvmb9eEOntJP5WCcyQL0b9rCMXuN2Q
SN/7zTpo/0dYNcQpGFMihYLCkE7fhWdFv+ev2R8DAukCgYEAs7tv98emACkjDHuo
piCEog26no6XsvwKTlBfO650W0lRaRLcdIi3JHdGP/Q306yaaSuP063mRU81Hls0
N52Vw2Jn0uyQDqDLHsrn4fpH+5OM5f/Z8c/a0RX/T9WLemlkdJky8jFBYj4f2j0v
RO5+2qmRSOeHWYUwAkLH80CChqA=
-----END PRIVATE KEY-----"};
    .ssl_client_cert = {"-----BEGIN CERTIFICATE-----
MIIFZjCCBE6gAwIBAgIQHvtj/M1oyFo/+QTfk/74FDANBgkqhkiG9w0BAQsFADCB
kDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxNjA0BgNV
BAMTLUNPTU9ETyBSU0EgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBD
QTAeFw0xNjA2MDcwMDAwMDBaFw0xNzA2MDcyMzU5NTlaMGIxITAfBgNVBAsTGERv
bWFpbiBDb250cm9sIFZhbGlkYXRlZDEdMBsGA1UECxMUUG9zaXRpdmVTU0wgV2ls
ZGNhcmQxHjAcBgNVBAMMFSouaW50ZWxsZWN0c2VlYy5jbG91ZDCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMXqtxV4Be7LOt5vw5l+BiLAMI3kScUbZ9Zh
gmuzwHty6eG93wQb19Tx/prcOC0LhuC6HRLkNHy+qDfJqaSLQPf+ktl0lHzX20nb
8/KNCfYbwLCo2PoNWqy2RD200JaS6xKV7x3nz+4VL2ZdGxuaufQQ0Joa+sB2EEoz
SnQqt/NJZMlD3vp3RDPUVAxwOetEshbU53b0cCcaAdlyJ7vl1HbJQAuEYxCW9cFN
ZMsqVZ5kaOQnxEb3F/0oZiop5FIEwflDQHe6613jEV+XwCZHOKfv6jWtQXRf7vR1
Fcp+9ZnRblylSLqkKMECJNToKi8nHyST1iCTKM3Juxq/xmKVpwsCAwEAAaOCAecw
ggHjMB8GA1UdIwQYMBaAFJCvajqUWgvYkOoSVnPfQ7Q6KNrnMB0GA1UdDgQWBBSb
SqQQ3dnL3uBWx/LdMSJF8ppZOjAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIw
ADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwTwYDVR0gBEgwRjA6Bgsr
BgEEAbIxAQICBzArMCkGCCsGAQUFBwIBFh1odHRwczovL3NlY3VyZS5jb21vZG8u
Y29tL0NQUzAIBgZngQwBAgEwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2NybC5j
b21vZG9jYS5jb20vQ09NT0RPUlNBRG9tYWluVmFsaWRhdGlvblNlY3VyZVNlcnZl
ckNBLmNybDCBhQYIKwYBBQUHAQEEeTB3ME8GCCsGAQUFBzAChkNodHRwOi8vY3J0
LmNvbW9kb2NhLmNvbS9DT01PRE9SU0FEb21haW5WYWxpZGF0aW9uU2VjdXJlU2Vy
dmVyQ0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20w
NQYDVR0RBC4wLIIVKi5pbnRlbGxlY3RzZWVjLmNsb3VkghNpbnRlbGxlY3RzZWVj
LmNsb3VkMA0GCSqGSIb3DQEBCwUAA4IBAQBBo60X9VtCkHlrnMl4OFsV7kkRo5qy
xl5wnA7j4VtdUEo9LesdLd79k3UDnRt+bf31Tp4sRNYVwcSyvKvBSj9ZI2q+7gXg
n8cGXzOEl22dY6b6gRotUWL6fmK5c6HBQoydOe+/c6E30xdGk9vGpyHRiYoAHPaw
HnPMSQqVuaGuQEDtM387xWUc8okL6wQnP6cO6GbinI7XXd2NzNqniF9xsbU2qEHM
CDkdnoWrI8lmAGDV7z/X2phYKzmaFZvV+K1HVIz/IvvJ9AnAjzOnWO6bOp2nLXAP
FaI1bKwCAGnG0oKe51tl9O1Hmv60drejZKqOx0PYNhJOQuxntgVJWvOt
-----END CERTIFICATE-----"};
        
  
}











sub vcl_recv {
#--FASTLY RECV BEGIN
  if (req.restarts == 0) {
    if (!req.http.X-Timer) {
      set req.http.X-Timer = "S" time.start.sec "." time.start.usec_frac;
    }
    set req.http.X-Timer = req.http.X-Timer ",VS0";
  }

    
    set req.http.Fastly-Orig-Host = req.http.host;
    set req.http.host = "www.intellectseec.cloud";
            

    
  # default conditions
  set req.backend = F_AWS_Wordpress_Origin_Server;
  
# --- Wordpress specific configuration

        # Did not cache the admin and login pages
        if (req.url ~ "wp-(login|admin)" || req.url ~ "preview=true" || req.url ~ "phpmyadmin") {
        return (pass);
        }


        # Remove the "has_js" cookie
        set req.http.Cookie = regsuball(req.http.Cookie, "has_js=[^;]+(; )?", "");
        # Remove any Google Analytics based cookies
        set req.http.Cookie = regsuball(req.http.Cookie, "__utm.=[^;]+(; )?", "");
        # Remove the Quant Capital cookies (added by some plugin, all __qca)
        set req.http.Cookie = regsuball(req.http.Cookie, "__qc.=[^;]+(; )?", "");
        # Remove the wp-settings-1 cookie
        set req.http.Cookie = regsuball(req.http.Cookie, "wp-settings-1=[^;]+(; )?", "");
        # Remove the wp-settings-time-1 cookie
        set req.http.Cookie = regsuball(req.http.Cookie, "wp-settings-time-1=[^;]+(; )?", "");
        # Remove the wp test cookie
        set req.http.Cookie = regsuball(req.http.Cookie, "wordpress_test_cookie=[^;]+(; )?", "");
        # Are there cookies left with only spaces or that are empty?
        if (req.http.cookie ~ "^ *$") {
                    unset req.http.cookie;
        }
        # Cache the following files extensions
        if (req.url ~ "\.(css|js|png|gif|jp(e)?g|swf|ico)") {
                unset req.http.cookie;
        }
        # Normalize Accept-Encoding header and compression https://www.varnish-cache.org/docs/3.0/tutorial/vary.html
        if (req.http.Accept-Encoding) {
                # Do no compress compressed files...
                if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") {
                                unset req.http.Accept-Encoding;
                } elsif (req.http.Accept-Encoding ~ "gzip") {
                        set req.http.Accept-Encoding = "gzip";
                } elsif (req.http.Accept-Encoding ~ "deflate") {
                        set req.http.Accept-Encoding = "deflate";
                } else {
                        unset req.http.Accept-Encoding;
                }
        }
        # Check the cookies for wordpress-specific items
        if (req.http.Cookie ~ "wordpress_" || req.http.Cookie ~ "comment_") {
                return (pass);
        }
        if (!req.http.cookie) {
                unset req.http.cookie;
        }

        # --- End of Wordpress specific configuration Did not cache HTTP authentication and HTTP Cookie
        if (req.http.Authorization || req.http.Cookie) {
                # Not cacheable by default
                return (pass);
        }
  
  # end default conditions

  
      
  
  
#--FASTLY RECV END



    if (req.request != "HEAD" && req.request != "GET" && req.request != "FASTLYPURGE") {
      return(pass);
    }


    return(lookup);
}


sub vcl_fetch {



#--FASTLY FETCH BEGIN


# record which cache ran vcl_fetch for this object and when
  set beresp.http.Fastly-Debug-Path = "(F " server.identity " " now.sec ") " if(beresp.http.Fastly-Debug-Path, beresp.http.Fastly-Debug-Path, "");

# generic mechanism to vary on something
  if (req.http.Fastly-Vary-String) {
    if (beresp.http.Vary) {
      set beresp.http.Vary = "Fastly-Vary-String, "  beresp.http.Vary;
    } else {
      set beresp.http.Vary = "Fastly-Vary-String, ";
    }
  }
  
    
  
 # priority: 0

      
    # seec cache
    set beresp.ttl = 600s;
    set beresp.grace = 300s;
    return(pass);
  
 
 
      
  # Gzip gzip rule
  if ((beresp.status == 200 || beresp.status == 404) && (beresp.http.content-type ~ "^(text\/html|application\/x\-javascript|text\/css|application\/javascript|text\/javascript|application\/json|application\/vnd\.ms\-fontobject|application\/x\-font\-opentype|application\/x\-font\-truetype|application\/x\-font\-ttf|application\/xml|font\/eot|font\/opentype|font\/otf|image\/svg\+xml|image\/vnd\.microsoft\.icon|text\/plain|text\/xml)\s*($|;)" || req.url ~ "\.(css|js|html|eot|ico|otf|ttf|json)($|\?)" ) ) {
  
    # always set vary to make sure uncompressed versions dont always win
    if (!beresp.http.Vary ~ "Accept-Encoding") {
      if (beresp.http.Vary) {
        set beresp.http.Vary = beresp.http.Vary ", Accept-Encoding";
      } else {
         set beresp.http.Vary = "Accept-Encoding";
      }
    }
    if (req.http.Accept-Encoding == "gzip") {
      set beresp.gzip = true;
    }
  }
 
      
#--FASTLY FETCH END



  if ((beresp.status == 500 || beresp.status == 503) && req.restarts < 1 && (req.request == "GET" || req.request == "HEAD")) {
    restart;
  }
  

  # Did not cache the admin and login pages
  if (req.url ~ "wp-(login|admin)" || req.url ~ "preview=true") {
  return (pass);
  }

  if(req.restarts > 0 ) {
    set beresp.http.Fastly-Restarts = req.restarts;
  }

  if (beresp.http.Set-Cookie) {
    set req.http.Fastly-Cachetype = "SETCOOKIE";
    return (pass);
  }

  if (beresp.http.Cache-Control ~ "private") {
    set req.http.Fastly-Cachetype = "PRIVATE";
    return (pass);
  }

  if (beresp.status == 500 || beresp.status == 503) {
    set req.http.Fastly-Cachetype = "ERROR";
    set beresp.ttl = 1s;
    set beresp.grace = 5s;
    return (deliver);
  }  
  

  if (beresp.http.Expires || beresp.http.Surrogate-Control ~ "max-age" || beresp.http.Cache-Control ~"(s-maxage|max-age)") {
    # keep the ttl here
  } else {
        # apply the default ttl
    set beresp.ttl = 4600s;
    
  }

  return(deliver);
}

sub vcl_hit {
#--FASTLY HIT BEGIN

# we cannot reach obj.ttl and obj.grace in deliver, save them when we can in vcl_hit
  set req.http.Fastly-Tmp-Obj-TTL = obj.ttl;
  set req.http.Fastly-Tmp-Obj-Grace = obj.grace;

  {
    set req.http.Fastly-Cachetype = "HIT";

    
  }
#--FASTLY HIT END
  if (!obj.cacheable) {
    return(pass);
  }
  return(deliver);
}

sub vcl_miss {
#--FASTLY MISS BEGIN
  

# this is not a hit after all, clean up these set in vcl_hit
  unset req.http.Fastly-Tmp-Obj-TTL;
  unset req.http.Fastly-Tmp-Obj-Grace;

  {
    if (req.http.Fastly-Check-SHA1) {
       error 550 "Doesnt exist";
    }
    
#--FASTLY BEREQ BEGIN
    {
      if (req.http.Fastly-Original-Cookie) {
        set bereq.http.Cookie = req.http.Fastly-Original-Cookie;
      }
      
      if (req.http.Fastly-Original-URL) {
        set bereq.url = req.http.Fastly-Original-URL;
      }
      {
        if (req.http.Fastly-FF) {
          set bereq.http.Fastly-Client = "1";
        }
      }
      {
        # do not send this to the backend
        unset bereq.http.Fastly-Original-Cookie;
        unset bereq.http.Fastly-Original-URL;
        unset bereq.http.Fastly-Vary-String;
        unset bereq.http.X-Varnish-Client;
      }
      if (req.http.Fastly-Temp-XFF) {
         if (req.http.Fastly-Temp-XFF == "") {
           unset bereq.http.X-Forwarded-For;
         } else {
           set bereq.http.X-Forwarded-For = req.http.Fastly-Temp-XFF;
         }
         # unset bereq.http.Fastly-Temp-XFF;
      }
    }
#--FASTLY BEREQ END


 #;

    set req.http.Fastly-Cachetype = "MISS";

    
  }
#--FASTLY MISS END
  return(fetch);
}

sub vcl_deliver {


#--FASTLY DELIVER BEGIN

# record the journey of the object, expose it only if req.http.Fastly-Debug.
  if (req.http.Fastly-Debug || req.http.Fastly-FF) {
    set resp.http.Fastly-Debug-Path = "(D " server.identity " " now.sec ") "
       if(resp.http.Fastly-Debug-Path, resp.http.Fastly-Debug-Path, "");

    set resp.http.Fastly-Debug-TTL = if(obj.hits > 0, "(H ", "(M ")
       server.identity
       if(req.http.Fastly-Tmp-Obj-TTL && req.http.Fastly-Tmp-Obj-Grace, " " req.http.Fastly-Tmp-Obj-TTL " " req.http.Fastly-Tmp-Obj-Grace " ", " - - ")
       if(resp.http.Age, resp.http.Age, "-")
       ") "
       if(resp.http.Fastly-Debug-TTL, resp.http.Fastly-Debug-TTL, "");

    set resp.http.Fastly-Debug-Digest = digest.hash_sha256(req.digest);
  } else {
    unset resp.http.Fastly-Debug-Path;
    unset resp.http.Fastly-Debug-TTL;
  }

  # add or append X-Served-By/X-Cache(-Hits)
  {

    if(!resp.http.X-Served-By) {
      set resp.http.X-Served-By  = server.identity;
    } else {
      set resp.http.X-Served-By = resp.http.X-Served-By ", " server.identity;
    }

    set resp.http.X-Cache = if(resp.http.X-Cache, resp.http.X-Cache ", ","") if(fastly_info.state ~ "HIT($|-)", "HIT", "MISS");

    if(!resp.http.X-Cache-Hits) {
      set resp.http.X-Cache-Hits = obj.hits;
    } else {
      set resp.http.X-Cache-Hits = resp.http.X-Cache-Hits ", " obj.hits;
    }

  }

  if (req.http.X-Timer) {
    set resp.http.X-Timer = req.http.X-Timer ",VE" time.elapsed.msec;
  }

  # VARY FIXUP
  {
    # remove before sending to client
    set resp.http.Vary = regsub(resp.http.Vary, "Fastly-Vary-String, ", "");
    if (resp.http.Vary ~ "^\s*$") {
      unset resp.http.Vary;
    }
  }
  unset resp.http.X-Varnish;


  # Pop the surrogate headers into the request object so we can reference them later
  set req.http.Surrogate-Key = resp.http.Surrogate-Key;
  set req.http.Surrogate-Control = resp.http.Surrogate-Control;

  # If we are not forwarding or debugging unset the surrogate headers so they are not present in the response
  if (!req.http.Fastly-FF && !req.http.Fastly-Debug) {
    unset resp.http.Surrogate-Key;
    unset resp.http.Surrogate-Control;
  }

  if(resp.status == 550) {
    return(deliver);
  }
  

  #default response conditions
    
  # s3 intellectSeecS3
  log {"syslog b9ji8kyU2F4O2KnrxTTdV intellectSeecS3 :: "} req.http.Fastly-Client-IP {" "} {""-""} {" "} {""-""} {" "} now {" "} req.request {" "} req.url {" "} resp.status;
  
  
      

  
#--FASTLY DELIVER END
  return(deliver);
}

sub vcl_error {
#--FASTLY ERROR BEGIN

  if (obj.status == 801) {
     set obj.status = 301;
     set obj.response = "Moved Permanently";
     set obj.http.Location = "https://" req.http.host req.url;
     synthetic {""};
     return (deliver);
  }

  
      
  if (req.http.Fastly-Restart-On-Error) {
    if (obj.status == 503 && req.restarts == 0) {
      restart;
    }
  }

  {
    if (obj.status == 550) {
      return(deliver);
    }
  }
#--FASTLY ERROR END



}

sub vcl_pipe {
#--FASTLY PIPE BEGIN
  {
     
    
#--FASTLY BEREQ BEGIN
    {
      if (req.http.Fastly-Original-Cookie) {
        set bereq.http.Cookie = req.http.Fastly-Original-Cookie;
      }
      
      if (req.http.Fastly-Original-URL) {
        set bereq.url = req.http.Fastly-Original-URL;
      }
      {
        if (req.http.Fastly-FF) {
          set bereq.http.Fastly-Client = "1";
        }
      }
      {
        # do not send this to the backend
        unset bereq.http.Fastly-Original-Cookie;
        unset bereq.http.Fastly-Original-URL;
        unset bereq.http.Fastly-Vary-String;
        unset bereq.http.X-Varnish-Client;
      }
      if (req.http.Fastly-Temp-XFF) {
         if (req.http.Fastly-Temp-XFF == "") {
           unset bereq.http.X-Forwarded-For;
         } else {
           set bereq.http.X-Forwarded-For = req.http.Fastly-Temp-XFF;
         }
         # unset bereq.http.Fastly-Temp-XFF;
      }
    }
#--FASTLY BEREQ END


    #;
    set req.http.Fastly-Cachetype = "PIPE";
    set bereq.http.connection = "close";
  }
#--FASTLY PIPE END

}

sub vcl_pass {
#--FASTLY PASS BEGIN
  

  {
    
#--FASTLY BEREQ BEGIN
    {
      if (req.http.Fastly-Original-Cookie) {
        set bereq.http.Cookie = req.http.Fastly-Original-Cookie;
      }
      
      if (req.http.Fastly-Original-URL) {
        set bereq.url = req.http.Fastly-Original-URL;
      }
      {
        if (req.http.Fastly-FF) {
          set bereq.http.Fastly-Client = "1";
        }
      }
      {
        # do not send this to the backend
        unset bereq.http.Fastly-Original-Cookie;
        unset bereq.http.Fastly-Original-URL;
        unset bereq.http.Fastly-Vary-String;
        unset bereq.http.X-Varnish-Client;
      }
      if (req.http.Fastly-Temp-XFF) {
         if (req.http.Fastly-Temp-XFF == "") {
           unset bereq.http.X-Forwarded-For;
         } else {
           set bereq.http.X-Forwarded-For = req.http.Fastly-Temp-XFF;
         }
         # unset bereq.http.Fastly-Temp-XFF;
      }
    }
#--FASTLY BEREQ END


 #;
    set req.http.Fastly-Cachetype = "PASS";
  }

#--FASTLY PASS END

}

sub vcl_log {
#--FASTLY LOG START

  # default response conditions
  
  
#--FASTLY LOG END
}

sub vcl_hash {

  #--FASTLY HASH BEGIN

    
  
  #if unspecified fall back to normal
  {
    

    set req.hash += req.url;
    set req.hash += req.http.host;
    set req.hash += "#####GENERATION#####";
    return (hash);
  }
  #--FASTLY HASH END


}

