# gpsfluxlite

A lighter version of [`gpsinflux`](https://github.com/iotfablab/gpsinflux) without the usage of `influxdb-python`.

## Features

- Send data to InfluxDB on a hardware using UDP Socket directly
- Provide TLS settings for connecting to a Secure MQTT Broker
- Use a fixed length queue to store the incoming RMC Co-ordinates in Line Protocol Format and send them to `DEVICE_NAME/DEVICE_ID/gps` topic
  with `QoS=1`
- Hard-code the `GPMRC` Setting for GPS Module to only collect RMC co-ordinates when the satellite lock is minimum value of 3


### Secure MQTT Configuration

Followig sample configuration for using a Secure MQTT Broker with Certificates. Use `insecure: true` to not use certificates.

```json
"mqtt": {
      "broker": "secure_broker",
      "port": 8883,
      "username": null,
      "password": null,
      "TLS": {
          "enable": true,
          "insecure": false,
          "tls_version": "tlsv1.2",
          "certs": {
            "certdir": "/etc/ssl/certs/mqtt",
            "cafile": "ca.crt",
            "certfile": "mqtt-client.crt",
            "keyfile": "mqtt-client.key"
          }
      }
    }
```

### InfluxDB UDP Configuration

Sample configuration for `influxdb.conf`

```toml
[[udp]]
  enabled = true
  bind-address = ":8092"
  database = "IoTSink"
  precision = "n"
```