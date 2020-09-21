from setuptools import setup


def readme():
    with open('README.md') as f:
        return f.read()


setup(name='gpsfluxlite',
    version='0.0.4',
    description='CLI to parse GPS RMC Co-ordinates and publish them via MQTT and store into InfluxDB',
    long_description=readme(),
    author='Shan Desai',
    author_email='des@biba.uni-bremen.de',
    license='MIT',
    packages=['gpsfluxlite'],
    scripts=['bin/gpsfluxlite'],
    install_requires=[
        'pynmea2',
        'pyserial',
        'paho-mqtt'
    ],
    include_data_package=True,
    zip_safe=False)
