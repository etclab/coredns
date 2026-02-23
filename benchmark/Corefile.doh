# DoH Server (Plain DNS-over-HTTPS baseline)
# Standard RFC 8484 DoH — no oblivious encryption, no proxy
https://.:7443 {
    tls localhost.pem localhost-key.pem
    forward . 127.0.0.1:5353
}
