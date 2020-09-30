import argparse
import io
import json
import logging
import os
import socket
import ssl
import sys
import time
from queue import Queue

import serial
import pynmea2
import paho.mqtt.client as mqtt


# Logging Configuration
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)

handler = logging.FileHandler('/var/log/gpsfluxlite.log')
handler.setLevel(logging.ERROR)

formatter = logging.Formatter('%(asctime)s-%(name)s-%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


CONFIG = dict()
DEVICE_NAME = ''
DEVICE_ID = ''
INFLUX_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def on_connect(mqttc, obj, flags, rc):
    """MQTT Callback Function upon connecting to MQTT Broker"""
    if rc == 0:
        logger.debug("MQTT CONNECT rc: " + str(rc))
        logger.info("Succesfully Connected to MQTT Broker")


def on_publish(mqttc, obj, mid):
    """MQTT Callback Function upon publishing to MQTT Broker"""
    logger.debug("MQTT PUBLISH: mid: " + str(mid))


def on_disconnect(mqttc, obj, rc):
    if rc == 0:
        logger.debug("MQTT DISCONNECTED: rc: " + str(rc))
        logger.debug("Disconnected Successfully from MQTT Broker")


def setup_mqtt_client(mqtt_conf, mqtt_client):
    """Configure MQTT Client based on Configuration"""

    if mqtt_conf['TLS']['enable']:
        logger.info("TLS Setup for Broker")
        logger.info("checking TLS_Version")
        tls = mqtt_conf['TLS']['tls_version']
        if tls == 'tlsv1.2':
             tlsVersion = ssl.PROTOCOL_TLSv1_2
        elif tls == "tlsv1.1":
            tlsVersion = ssl.PROTOCOL_TLSv1_1
        elif tls == "tlsv1":
            tlsVersion = ssl.PROTOCOL_TLSv1
        else:
            logger.info("Unknown TLS version - ignoring")
            tlsVersion = None
        if not mqtt_conf['TLS']['insecure']:

            logger.info("Searching for Certificates in certdir")
            CERTS_DIR = mqtt_conf['TLS']['certs']['certdir']
            if os.path.isdir(CERTS_DIR):
                logger.info("certdir exists")
                CA_CERT_FILE = os.path.join(CERTS_DIR, mqtt_conf['TLS']['certs']['cafile'])
                CERT_FILE = os.path.join(CERTS_DIR, mqtt_conf['TLS']['certs']['certfile'])
                KEY_FILE = os.path.join(CERTS_DIR, mqtt_conf['TLS']['certs']['keyfile'])

                mqtt_client.tls_set(ca_certs=CA_CERT_FILE, certfile=CERT_FILE, keyfile=KEY_FILE, cert_reqs=ssl.CERT_REQUIRED, tls_version=tlsVersion)
            else:
                logger.error("certdir does not exist.. check path")
                sys.exit()
        else:
            mqtt_client.tls_set(ca_certs=None, certfile=None, keyfile=None, cert_reqs=ssl.CERT_NONE, tls_version=tlsVersion)
            mqtt_client.tls_insecure_set(True)
    
    if mqtt_conf['username'] and mqtt_conf['password']:
        logger.info("setting username and password for Broker")
        mqtt_client.username_pw_set(mqtt_conf['username'], mqtt_conf['password'])
    
    return mqtt_client



def send_data(payloads, mqtt_client):
    """Publish GPS RMC Co-ordinates to MQTT Broker + InfluxDB insert"""
    global CONFIG
    global DEVICE_ID, DEVICE_NAME
    global INFLUX_SOCKET
    while not payloads.empty():
        for topic in CONFIG['gps']['topics']:
            data =  ''.join(list(payloads.queue))
            payloads.queue.clear()
            topic_to_publish = DEVICE_NAME + '/' + DEVICE_ID + '/' + topic
            logger.debug(data)
            mqtt_client.publish(topic_to_publish, data, qos=1)
            INFLUX_SOCKET.sendto(data.encode('utf-8'), (CONFIG['influx']['host'], CONFIG['gps']['udp_port']))


def read_from_gps(sio, ser, payload_q, mqttc):
    """Read From GPS Device and push incoming RMC Co-ordinates to payload Queue"""
    mqttc.loop_start()
    while 1:
        try:
            line = sio.readline()
            reader = pynmea2.NMEAStreamReader(errors='ignore')
            for msg in reader.next(line):
                gps_data = pynmea2.parse(str(msg), check=True)
                
                if isinstance(gps_data, pynmea2.RMC):
                    if gps_data.latitude == 0.0 and gps_data.longitude == 0.0:
                        logger.info('No RMC Co-ordinates available. Waiting for Satellite Lock on Device')
                    else:
                        # Line Protocol Format: geolocation,src=gps lat=<latitude>,lon=<longitude> <ns_timestamp>
                        payload_q.put_nowait(f'geolocation,src=gps lat={gps_data.latitude:.6f},lon={gps_data.longitude:.6f} {time.time_ns()}\n')
                        # Line Protocol Format: geolocation,src=gps sog=<speed_over_ground>,cog=<course_over_ground> <ns_timestamp>
                        payload_q.put_nowait(f'groundvelocity,src=gps sog={gps_data.spd_over_grnd},cog={gps_data.true_course} {time.time_ns()}\n')

                    # If Queue is full i.e. latitude, longitude, speed over ground, course over ground
                    if payload_q.full():
                        send_data(payload_q, mqttc)
                        time.sleep(1.0)

        except serial.SerialException as e:
            logger.exception(f"Device error: {e}")
            break
        except pynmea2.ParseError as e:
            logger.exception(f"Parse error:{e}")
            continue
        except KeyboardInterrupt as e:
            logger.exception("CTRL+C pressed")
            break
    
    logger.info("Cleaning up queue, closing connections")
    if not payload_q.empty():
        payload_q.queue.clear()
    ser.close()
    mqttc.loop_stop()
    mqttc.disconnect()
    sys.exit()


def parse_arguments():
    """Arguments to run the script"""
    parser = argparse.ArgumentParser(description='CLI to obtain MTK3339 RMC GPS Co-ordinates and save them to InfluxDBv1.x and Publish them to MQTT')
    parser.add_argument('--config', '-c', required=True, help='JSON Configuration File for gpsfluxlite CLI')
    return parser.parse_args()


def main():
    """Initialization"""
    args = parse_arguments()
    if not os.path.isfile(args.config):
        logger.error("configuration file not readable. Check path to configuration file")
        sys.exit()
    payload_q = Queue(maxsize=2)
    global CONFIG
    with open(args.config, 'r') as config_file:
        CONFIG = json.load(config_file)
    # print(CONFIG)
    
    # MQTT Client Configuration
    global DEVICE_NAME, DEVICE_ID
    DEVICE_NAME = CONFIG['device']['name']
    DEVICE_ID = CONFIG['device']['ID']
    MQTT_CONF = CONFIG['mqtt']

    mqttc = mqtt.Client(client_id=f'{DEVICE_NAME}/{DEVICE_ID}-GPS')
    mqttc = setup_mqtt_client(MQTT_CONF, mqttc)

    mqttc.on_connect = on_connect
    mqttc.on_publish = on_publish
    mqttc.on_disconnect = on_disconnect

    mqttc.connect(CONFIG['mqtt']['broker'], CONFIG['mqtt']['port'])
    
    logger.info("Configuring GPS Module for RMC Co-ordinates")

    ser = serial.Serial(port=CONFIG['gps']['serialport'], baudrate=CONFIG['gps']['baudrate'], timeout=5.0)

    sio = io.TextIOWrapper(io.BufferedRWPair(ser, ser))
    if sio.writable():
        try:
            # NMEA Sentence to enable min. 3 satellites lock for RMC
            sio.write('$PMTK314,0,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0*15\r\n')
        except Exception as e:
            logger.exception('cannot set RMC command on device')
            logger.exception(f"Serial Write Exception: {e}")
    
    read_from_gps(sio, ser, payload_q, mqttc)

if __name__ == "__main__":
    main()
