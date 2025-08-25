#!/usr/bin/env python3
# flake8: noqa

'''
    NAME: lf_interop_ping_plotter.py

    PURPOSE: lf_interop_ping_plotter.py will let the user select real devices, virtual devices or both and then allows them to run
    ping plotter test for user given duration and packet interval on the given target IP or domain name and generates realtime ping status and line charts for every device.

    EXAMPLE-1:
    Command Line Interface to run ping plotter test with only virtual clients with eth1 as the default target
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.103 --virtual --num_sta 1 --radio 1.1.wiphy2 --ssid RDT_wpa2 --security wpa2
    --passwd OpenWifi --ping_interval 1 --ping_duration 1m --server_ip 192.168.1.61 --debug

    EXAMPLE-2:
    Command Line Interface to stop cleaning up stations after the test
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.103 --virtual --num_sta 1 --radio 1.1.wiphy2 --ssid RDT_wpa2 --security wpa2
    --passwd OpenWifi --ping_interval 1 --ping_duration 1m --server_ip 192.168.1.61 --debug --no_cleanup

    EXAMPLE-3:
    Command Line Interface to run ping plotter test with only real clients
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.103 --real --ping_interval 1 --ping_duration 1m --server_ip 192.168.1.61

    EXAMPLE-4:
    Command Line Interface to run ping plotter test with both real and virtual clients
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.103 --real --virtual --num_sta 1 --radio 1.1.wiphy2 --ssid RDT_wpa2 --security wpa2
    --passwd OpenWifi --ping_interval 1 --ping_duration 1m --server_ip 192.168.1.61

    EXAMPLE-5:
    Command Line Interface to run ping plotter test with a different target
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.63 --real --ping_interval 5 --ping_duration 1m --target 192.168.1.61

    EXAMPLE-6:
    Command Line Interface to run ping plotter test with a Multiple radios
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.145 --ping_interval 1 --target 8.8.8.8 --radios "radio==1.1.wiphy1 num_sta==3 ssid==SVB  passwd==Password@123 security==wpa2"
    --radios "radio==1.1.wiphy0 num_sta==1 ssid==SVB  passwd==Password@123 security==wpa2"  --debug --virtual

    --no_pre_cleanup
                    Disables generic endpoints cleanup before creation of new endpoints.

            example:
            python3 lf_interop_ping_plotter.py --mgr 192.168.200.145 --ping_interval 1 --target 8.8.8.8 --radios "radio==1.1.wiphy1 num_sta==3 ssid==SVB  passwd==Password@123 security==wpa2"
            --radios "radio==1.1.wiphy0 num_sta==1 ssid==SVB  passwd==Password@123 security==wpa2"  --debug --virtual --no_pre_cleanup

    --no_cleanup
                    Add this flag to stop cleaning generic endpoints after completion of the test.



    SCRIPT_CLASSIFICATION : Test

    SCRIPT_CATEGORIES: Performance, Functional, Report Generation

    NOTES:
    1.Use './lf_interop_ping.py --help' to see command line usage and options
    2.Use 's','m','h' as suffixes for ping_duration in seconds, minutes and hours respectively
    3.After passing the cli, if --real flag is selected, then a list of available real devices will be displayed on the terminal
    4.Enter the real device resource numbers seperated by commas (,)
    5.For --target, you can specify it as eth1, IP address or domain name (e.g., google.com)

    * For enterprise authentication with multiple radios, please use the following command line arguments:
            eap_method==<eap_method>
                    Add this argument to specify the EAP method

            example:
                    DEFAULT
                    EAP-MD5
                    MSCHAPV2
                    EAP-OTP
                    EAP-GTC
                    EAP-TLS
                    EAP-PEAP
                    EAP-TTLS
                    EAP-SIM
                    EAP-AKA
                    EAP-PSK
                    EAP-IKEV2
                    EAP-FAST
                    WFA-UNAUTH-TLS
                    TTLS PEAP TLS

            --pairwise==[BLANK]
                    Add this argument to specify the type of pairwise cipher

                DEFAULT
                CCMP
                TKIP
                NONE
                CCMP TKIP
                CCMP-256
                GCMP (wpa3)
                GCMP-256 (wpa3)
                CCMP/GCMP-256 (wpa3)

            --groupwise==[BLANK]
                    Add this argument to specify the type of groupwise cipher

                DEFAULT
                CCMP
                WEP104
                WEP40
                GTK_NOT_USED
                GCMP-256 (wpa3)
                CCMP-256 (wpa3)
                GCMP/CCMP-256 (wpa3)
                All

            --key_mgmt==<SAE>
                    Add this flag to give the key management value

                DEFAULT
                NONE
                WPA-PSK
                FT-PSK (11r)
                FT-EAP (11r)
                FT-SAE (11r)
                FT-SAE-EXT-KEY (11r)
                FT-EAP-SHA384 (11r)
                WPA-EAP
                OSEN
                IEEE8021X
                WPA-PSK-SHA256
                WPA-EAP-SHA256
                PSK & EAP 128
                PSK & EAP 256
                PSK & EAP 128/256
                SAE
                SAE-EXT-KEY
                WPA-EAP-SUITE-B
                WPA-EAP-SUITE-B-192
                FILS-SHA256
                FILS-SHA384
                OWE

    STATUS: BETA RELEASE

    VERIFIED_ON:
    Working date    - 06/12/2023
    Build version   - 5.4.7
    kernel version  - 6.2.16+

    License: Free to distribute and modify. LANforge systems must be licensed.
    Copyright 2023 Candela Technologies Inc.
'''

import argparse
import random
import time
import sys
import os
import pandas as pd
import importlib
import logging
import matplotlib.pyplot as plt
import csv
import asyncio
import json
import shutil
import requests
import plotly.graph_objs as go
from plotly.subplots import make_subplots
import webbrowser

if 'py-json' not in sys.path:
    sys.path.append(os.path.join(os.path.abspath('..'), 'py-json'))

if 'py-scripts' not in sys.path:
    # sys.path.append('/home/agent11/Desktop/lanforge-scripts/py-scripts')
    sys.path.append('/home/lanforge/lanforge-scripts/py-scripts')

from lf_base_interop_profile import RealDevice
from datetime import datetime, timedelta
from lf_graph import lf_bar_graph_horizontal
from lf_graph import lf_bar_graph
from lf_report import lf_report
from station_profile import StationProfile
import interop_connectivity
from LANforge import LFUtils

logger = logging.getLogger(__name__)
lf_logger_config = importlib.import_module("py-scripts.lf_logger_config")

if sys.version_info[0] != 3:
    print("This script requires Python 3")
    exit(1)

realm = importlib.import_module("py-json.realm")
Realm = realm.Realm


class Ping(Realm):
    EAP_METHOD_MAP = {
        "DEFAULT": "DEFAULT",
        "EAP-MD5": "MD5",
        "MSCHAPV2": "MSCHAPV2",
        "EAP-OTP": "OTP",
        "EAP-GTC": "GTC",
        "EAP-TLS": "TLS",
        "EAP-PEAP": "PEAP",
        "EAP-TTLS": "TTLS",
        "EAP-SIM": "SIM",
        "EAP-AKA": "AKA",
        "EAP-PSK": "PSK",
        "EAP-IKEV2": "IKEV2",
        "EAP-FAST": "FAST",
        "WFA-UNAUTH-TLS": "WFA-UNAUTH-TLS",
        "TTLS PEAP TLS": "TTLS PEAP TLS",
    }

    KEY_MGMT_MAP = {
        "DEFAULT": "DEFAULT",
        "NONE": "NONE",
        "WPA-PSK": "WPA-PSK",
        "FT-PSK (11r)": "FT-PSK",
        "FT-EAP (11r)": "FT-EAP",
        "FT-SAE (11r)": "FT-SAE",
        "FT-SAE-EXT-KEY (11r)": "FT-SAE-EXT-KEY",
        "FT-EAP-SHA384 (11r)": "FT-EAP-SHA-384",
        "WPA-EAP": "WPA-EAP",
        "OSEN": "OSEN",
        "IEEE8021X": "IEEE8021X",
        "WPA-PSK-SHA256": "WPA-PSK-SHA256",
        "WPA-EAP-SHA256": "WPA-EAP-SHA256",
        "PSK & EAP 128": "WPA-PSK WPA-EAP",
        "PSK & EAP 256": "WPA-PSK-256 WPA-EAP-256",
        "PSK & EAP 128/256": "WPA-PSK WPA-EAP WPA-PSK-256 WPA-EAP-256",
        "SAE": "SAE",
        "SAE-EXT-KEY": "SAE-EXT-KEY",
        "WPA-EAP-SUITE-B": "WPA-EAP-SUITE-B",
        "WPA-EAP-SUITE-B-192": "WPA-EAP-SUITE-B-192",
        "FILS-SHA256": "FILS-SHA256",
        "FILS-SHA384": "FILS-SHA384",
        "OWE": "OWE",
    }

    PAIRWISE_CIPHER_MAP = {
        "DEFAULT": "DEFAULT",
        "CCMP": "CCMP",
        "TKIP": "TKIP",
        "NONE": "NONE",
        "CCMP TKIP": "CCMP TKIP",
        "CCMP-256": "CCMP-256",
        "GCMP (wpa3)": "GCMP",
        "GCMP-256 (wpa3)": "GCMP-256",
        "CCMP/GCMP-256 (wpa3)": "GCMP-256 CCMP-256",
    }

    GROUPWISE_CIPHER_MAP = {
        "DEFAULT": "DEFAULT",
        "CCMP": "CCMP",
        "WEP104": "WEP104",
        "WEP40": "WEP40",
        "GTK_NOT_USED": "GTK_NOT_USED",
        "GCMP-256 (wpa3)": "GCMP-256",
        "CCMP-256 (wpa3)": "CCMP-256",
        "GCMP/CCMP-256 (wpa3)": "GCMP-256 CCMP-256",
        "All": "CCMP TKIP WEP104 WEP40 CCMP-256 GCMP-256",
    }

    def __init__(self,
                 host=None,
                 port=None,
                 ssid=None,
                 security=None,
                 password=None,
                 radio=None,
                 target=None,
                 interval=None,
                 lanforge_password='lanforge',
                 sta_list=None,
                 virtual=None,
                 existing_sta=None,
                 duration=1,
                 real=None,
                 do_webUI=False,
                 ui_report_dir=None,
                 debug=False):
        super().__init__(lfclient_host=host,
                         lfclient_port=port)
        self.host = host
        self.lanforge_password = lanforge_password
        self.port = port
        self.lfclient_host = host
        self.lfclient_port = port
        self.ssid = ssid
        self.security = security
        self.password = password
        self.radio = radio
        self.target = target
        self.interval = interval
        self.debug = debug
        self.sta_list = sta_list
        self.real_sta_list = []
        self.real_sta_data_dict = {}
        self.radio_sta_info = {}
        self.enable_virtual = virtual
        self.enable_real = real
        self.enable_existing_sta = existing_sta
        self.duration = duration
        self.android = 0
        self.virtual = 0
        self.linux = 0
        self.windows = 0
        self.mac = 0
        self.result_json = {}
        self.generic_endps_profile = self.new_generic_endp_profile()
        self.generic_endps_profile.type = 'lfping'
        self.generic_endps_profile.dest = self.change_target_to_ip()
        self.generic_endps_profile.interval = self.interval
        self.Devices = None
        self.start_time = ""
        self.stop_time = ""
        self.do_webUI = do_webUI
        self.ui_report_dir = ui_report_dir

    def change_target_to_ip(self):

        # checking if target is an IP or a port
        if (self.target.count('.') != 3 and self.target.split('.')[-2].isnumeric()):
            # checking if target is eth1 or 1.1.eth1
            target_port_list = self.name_to_eid(self.target)
            shelf, resource, port, _ = target_port_list
            try:
                target_port_ip = self.json_get('/port/{}/{}/{}?fields=ip'.format(shelf, resource, port))['interface'][
                    'ip']
                self.target = target_port_ip
            except:
                logging.warning(
                    'The target is not an ethernet port. Proceeding with the given target {}.'.format(self.target))
            logging.info(self.target)
        else:
            logging.info(self.target)
        return self.target

    def cleanup(self):
        if (self.enable_virtual or self.enable_existing_sta):
            # removing virtual stations if existing
            for station in self.sta_list:
                logging.info('Removing the station {} if exists'.format(station))
                self.generic_endps_profile.created_cx.append(
                    'CX_generic-{}'.format(station.split('.')[2]))
                self.generic_endps_profile.created_endp.append(
                    'generic-{}'.format(station.split('.')[2]))
                self.rm_port(station, check_exists=True)

            if (not LFUtils.wait_until_ports_disappear(base_url=self.host, port_list=self.sta_list, debug=self.debug)):
                logging.info('All stations are not removed or a timeout occured.')
                logging.error('Aborting the test.')
                exit(0)

        if (self.enable_real):
            # removing generic endpoints for real devices if existing
            for station in self.real_sta_list:
                self.generic_endps_profile.created_cx.append(
                    'CX_generic-{}'.format(station))
                self.generic_endps_profile.created_endp.append(
                    'generic-{}'.format(station))

        logging.info('Cleaning up generic endpoints if exists')
        self.generic_endps_profile.cleanup()
        self.generic_endps_profile.created_cx = []
        self.generic_endps_profile.created_endp = []
        logging.info('Cleanup Successful')

    # Args:
    #   devices: Connected RealDevice object which has already populated tracked real device
    #            resources through call to get_devices()
    def select_real_devices(self, real_devices, real_sta_list=None, base_interop_obj=None):
        if real_sta_list is None:
            self.real_sta_list, _, _ = real_devices.query_user()
        else:
            self.real_sta_list = real_sta_list
        if base_interop_obj is not None:
            self.Devices = base_interop_obj

        # Need real stations to run interop test
        if (len(self.real_sta_list) == 0):
            logger.error('There are no real devices in this testbed. Aborting test')
            exit(0)

        logging.info('{}'.format(*self.real_sta_list))

        for sta_name in self.real_sta_list:
            if sta_name not in real_devices.devices_data:
                logger.error('Real station not in devices data, ignoring it from testing')
                continue
                # raise ValueError('Real station not in devices data')

            self.real_sta_data_dict[sta_name] = real_devices.devices_data[sta_name]

        # Track number of selected devices
        self.android = self.Devices.android
        self.windows = self.Devices.windows
        self.mac = self.Devices.mac
        self.linux = self.Devices.linux

    def buildstation(self):
        logging.info('Creating Virtual Stations: {}'.format(self.sta_list))
        station_object = StationProfile(lfclient_url='http://{}:{}'.format(self.host, self.port), local_realm=self,
                                        ssid=self.ssid, ssid_pass=self.password, security=self.security,
                                        number_template_='00')
        station_object.use_security(self.security, self.ssid, self.password)
        station_object.set_command_flag("add_sta", "create_admin_down", 1)
        station_object.set_command_param("set_port", "report_timer", 1500)
        station_object.set_command_flag("set_port", "rpt_timer", 1)
        station_object.create(radio=self.radio, sta_names_=self.sta_list)
        station_object.admin_up()
        if Realm.wait_for_ip(self=self, station_list=self.sta_list, timeout_sec=-1):
            self._pass("All stations got IPs", print_=True)
        else:
            self._fail("Stations failed to get IPs", print_=True)
            logger.info("Please re-check the configuration applied")

    def build_stations(self,
                       radio,
                       station_list,
                       ssid,
                       password,
                       security,
                       pairwise_cipher='[BLANK]',
                       groupwise_cipher='[BLANK]',
                       eap_identity='[BLANK]',
                       eap_password='[BLANK]',
                       private_key='[BLANK]',
                       ca_cert='[BLANK]',
                       pk_passwd='[BLANK]',
                       eap_phase1='[BLANK]',
                       eap_phase2='[BLANK]',
                       eap_method=None,
                       key_mgmt=None,
                       eap_anonymous_identity='[BLANK]',
                       custom_wifi_cmd=None,
                       ):
        if eap_method in self.EAP_METHOD_MAP:
            eap_method = self.EAP_METHOD_MAP[eap_method]
        else:
            eap_method = eap_method

        if key_mgmt in self.KEY_MGMT_MAP:
            key_mgmt = self.KEY_MGMT_MAP[key_mgmt]
        else:
            key_mgmt = key_mgmt

        if pairwise_cipher in self.PAIRWISE_CIPHER_MAP:
            pairwise_cipher = self.PAIRWISE_CIPHER_MAP[pairwise_cipher]
        else:
            pairwise_cipher = pairwise_cipher

        if groupwise_cipher in self.GROUPWISE_CIPHER_MAP:
            groupwise_cipher = self.GROUPWISE_CIPHER_MAP[groupwise_cipher]
        else:
            groupwise_cipher = groupwise_cipher

        station_object = StationProfile(lfclient_url='http://{}:{}'.format(self.host, self.port), local_realm=self,
                                        ssid=ssid, ssid_pass=password, security=security,
                                        number_template_='00')
        station_object.use_security(security, ssid, passwd=password)
        station_object.set_command_flag("add_sta", "create_admin_down", 1)

        if not eap_method:
            if key_mgmt:
                if not password:
                    password = "[BLANK]"
                station_object.set_wifi_extra(key_mgmt=key_mgmt,
                                              psk=password)
                station_object.set_command_flag(command_name="add_sta", param_name="80211u_enable", value=0)
                station_object.set_command_flag(command_name="add_sta", param_name="8021x_radius",
                                                value=1)  # Enable Advanced/802.1X flag
        else:
            if eap_method == 'TLS':
                station_object.set_wifi_extra(key_mgmt=key_mgmt,
                                              pairwise=pairwise_cipher,
                                              group=groupwise_cipher,
                                              eap=eap_method,
                                              identity=eap_identity,
                                              passwd=eap_password,
                                              private_key=private_key,
                                              ca_cert=ca_cert,
                                              pk_password=pk_passwd,
                                              phase1=eap_phase1,
                                              phase2=eap_phase2)
            elif eap_method == 'TTLS' or eap_method == 'PEAP':
                station_object.set_wifi_extra(key_mgmt=key_mgmt,
                                              pairwise=pairwise_cipher,
                                              group=groupwise_cipher,
                                              eap=eap_method,
                                              identity=eap_identity,
                                              anonymous_identity=eap_anonymous_identity,
                                              passwd=eap_password,
                                              phase1=eap_phase1,
                                              phase2=eap_phase2)
            # Security type comes in one of following formats (possibly capitalized),
            # so need to check if substring:
            #   'type'
            #   '<type1|type2>'
            if 'wpa3' in self.security or 'WPA3' in self.security:
                station_object.set_command_param("add_sta", "ieee80211w", 2)

            station_object.set_command_flag(command_name="add_sta", param_name="8021x_radius",
                                            value=1)  # enable 802.1x flag

            # station_object.set_wifi_extra(key_mgmt="WPA-EAP",eap="TTLS",identity='testuser',passwd='testpasswd')
            # station_object.set_command_flag(command_name="add_sta", param_name="80211u_enable", value=0)  # disable 80211u flag
            # station_object.set_command_flag(command_name="add_sta", param_name="8021x_radius", value=1)  # enable 802.1x flag

        if station_object.create(radio=radio, sta_names_=station_list, debug=self.debug):
            self._pass("Stations created.")
        else:
            self._fail("Stations not properly created.")

        # Custom Wifi setting
        if custom_wifi_cmd:
            for sta in station_list:
                self.set_custom_wifi(resource=int(sta.split('.')[1]),
                                     station=str(sta.split('.')[2]),
                                     cmd=custom_wifi_cmd)

        station_object.admin_up()
        if not LFUtils.wait_until_ports_admin_up(base_url='http://{}:{}'.format(self.host, self.port),
                                                 port_list=station_list,
                                                 debug_=self.debug,
                                                 timeout=20):
            self._fail("Unable to bring all stations up")
            return
        if self.wait_for_ip(station_list=station_list, timeout_sec=-1, debug=self.debug):
            self._pass("All stations got IPs", print_=True)
        else:
            self._fail("Stations failed to get IPs", print_=True)
            logger.info("Please re-check the configuration applied")

    def check_tab_exists(self):
        response = self.json_get("generic")
        if response is None:
            return False
        else:
            return True

    def create_generic_endp(self):
        # Virtual stations are tracked in same list as real stations, so need to separate them
        # in order to create generic endpoints for just the virtual stations
        virtual_stations = list(set(self.sta_list).difference(set(self.real_sta_list)))

        if (self.enable_existing_sta):
            if (self.generic_endps_profile.create(ports=self.sta_list, sleep_time=.5)):
                logging.info('Virtual client generic endpoint creation completed.')
            else:
                logging.error('Virtual client generic endpoint creation failed.')
                exit(0)

        elif (self.enable_virtual):
            if (self.generic_endps_profile.create(ports=virtual_stations, sleep_time=.5)):
                logging.info('Virtual client generic endpoint creation completed.')
            else:
                logging.error('Virtual client generic endpoint creation failed.')
                exit(0)

        print(self.generic_endps_profile.created_endp, self.generic_endps_profile.created_cx)

        if (self.enable_real):
            real_sta_os_types = [self.real_sta_data_dict[real_sta_name]['ostype'] for real_sta_name in
                                 self.real_sta_data_dict]

            if (self.generic_endps_profile.create(ports=self.real_sta_list, sleep_time=.5,
                                                  real_client_os_types=real_sta_os_types)):
                logging.info('Real client generic endpoint creation completed.')
            else:
                logging.error('Real client generic endpoint creation failed.')
                exit(0)

        # setting endpoint report time to ping packet interval
        for endpoint in self.generic_endps_profile.created_endp:
            self.generic_endps_profile.set_report_timer(endp_name=endpoint, timer=250)

    def start_generic(self):
        self.generic_endps_profile.start_cx()
        self.start_time = datetime.now()

    def stop_generic(self):
        self.generic_endps_profile.stop_cx()
        self.stop_time = datetime.now()

    def clean_generic_cx(self):
        self.generic_endps_profile.cleanup()
        self.generic_endps_profile.created_cx = []
        self.generic_endps_profile.created_endp = []

    def get_results(self):
        # logging.info(self.generic_endps_profile.created_endp)
        results = self.json_get(
            "/generic/{}".format(','.join(self.generic_endps_profile.created_endp)))
        if (len(self.generic_endps_profile.created_endp) > 1 and 'endpoints' in results.keys()):
            results = results['endpoints']
        else:
            results = results['endpoint']
        return (results)

    def generate_remarks(self, station_ping_data):
        remarks = []

        # NOTE if there are any more ping failure cases that are missed, add them here.

        # checking if ping output is not empty
        if (station_ping_data['last_result'] == ""):
            remarks.append('No output for ping')

        # illegal division by zero error. Issue with arguments.
        if ('Illegal division by zero' in station_ping_data['last_result']):
            remarks.append('Illegal division by zero error. Please re-check the arguments passed.')

        # unknown host
        if ('Totals:  *** dropped: 0  received: 0  failed: 0  bytes: 0' in station_ping_data[
            'last_result'] or 'unknown host' in station_ping_data['last_result']):
            remarks.append('Unknown host. Please re-check the target')

        # checking if IP is existing in the ping command or not for Windows device
        if (station_ping_data['os'] == 'Windows'):
            if ('None' in station_ping_data['command'] or station_ping_data['command'].split('-n')[0].split('-S')[
                -1] == "  "):
                remarks.append('Station has no IP')

        # network buffer overflow
        if ('ping: sendmsg: No buffer space available' in station_ping_data['last_result']):
            remarks.append('Network buffer overlow')

        # checking for no ping states
        if (float(station_ping_data['min_rtt'].replace(',', '')) == 0 and float(
                station_ping_data['max_rtt'].replace(',', '')) == 0 and float(
            station_ping_data['avg_rtt'].replace(',', '')) == 0):

            # Destination Host Unreachable state
            if ('Destination Host Unreachable' in station_ping_data['last_result']):
                remarks.append('Destination Host Unrechable')

            # Name or service not known state
            if ('Name or service not known' in station_ping_data['last_result']):
                remarks.append('Name or service not known')

            # network buffer overflow
            if ('ping: sendmsg: No buffer space available' in station_ping_data['last_result']):
                remarks.append('Network buffer overlow')

        return (remarks)

    def generate_uptime_graph(self):
        json_data = {}
        for station in self.result_json:
            json_data[station] = {
                'rtts': {},
                'sent': "",
                'dropped': ""
            }
            # print('------------',json_data)
            # for seq in self.result_json[station]['rtts']:
            json_data[station]['rtts'] = self.result_json[station]['rtts']
            json_data[station]['sent'] = self.result_json[station]['sent']
            json_data[station]['dropped'] = self.result_json[station]['dropped']
        self.graph_values = json_data
        device_names = list(json_data.keys())
        sequence_numbers = list(set(seq for device_data in json_data.values() for seq in device_data.get("rtts", {})))
        # print(sequence_numbers)
        rtt_values = {}
        for seq in sequence_numbers:
            rtt_values[seq] = []
            for device_data in json_data.values():
                if ("rtts" in device_data.keys()):
                    if (seq in device_data['rtts'].keys()):
                        rtt_values[seq].append(device_data['rtts'][seq])
                    else:
                        if (device_data['sent'] == device_data['dropped']):
                            rtt_values[seq].append(0)
                        elif (len(device_data['rtts'].keys()) != 0):
                            rtt_values[seq].append(1)
                        else:
                            rtt_values[seq].append(0)
        # rtt_values = {seq: [device_data.get("rtts", {}).get(seq, 0) for device_data in json_data.values()] for seq in sequence_numbers}
        # print(rtt_values)
        # Set different colors based on RTT values
        colors = [['red' if rtt == 0 else 'green' for rtt in rtt_values[seq]] for seq in sequence_numbers]

        # Create a stacked horizontal bar graph
        bar_width = 1
        fig, ax = plt.subplots(figsize=(20, len(device_names) * .5 + 10))
        # y_positions = np.arange(len(device_names)) * (bar_width + 1)  # Adjust the 0.1 to control the gap
        for i, device_name in enumerate(self.report_names):
            # plt.barh(device_name, 1, color='white', height=0.5)
            for j, seq in enumerate(sequence_numbers):
                plt.barh(device_name, 1, left=int(seq) - 1, color=colors[j][i], height=0.3)

        # Customize the plot
        plt.xlabel('Time', fontweight='bold', fontsize=15)
        plt.ylabel('Client Status', fontweight='bold', fontsize=15)
        plt.title('Client Status vs Time')
        # plt.legend(sequence_numbers, title='Sequence Numbers', loc='upper right')

        # Remove y-axis labels
        # plt.yticks([])

        # building timestamps
        start_time = self.start_time
        interval = timedelta(seconds=int(self.interval))

        timestamps = []
        for seq_num in sequence_numbers:
            timestamp = ((int(seq_num) - 1) * interval + start_time).strftime("%d/%m/%Y %H:%M:%S")
            timestamps.append(timestamp)

        # settings labels for x-axis
        # print(list(map(int,sequence_numbers)))
        # print(list(map(int,sequence_numbers))[0::10])
        # print(timestamps)

        # ticks_sequence_numbers =  list(map(int,sequence_numbers))
        # ticks_sequence_numbers.sort()
        sequence_numbers.sort()
        timestamps.sort()
        # print('--------------')
        # print(ticks_sequence_numbers[0::10])
        # print(timestamps[0::10])
        # settings labels for x-axis
        if (len(sequence_numbers) > 30):
            temp_sequence_numbers = sequence_numbers[
                                    :len(sequence_numbers):max(round(len(timestamps) / 30), len(timestamps) // 30)]
            temp_timestamps = timestamps[:len(timestamps):max(round(len(timestamps) / 30), len(timestamps) // 30)]

            if (len(temp_sequence_numbers) != len(temp_timestamps)):
                temp_sequence_numbers.pop(0)
            # plt.xticks(temp_sequence_numbers, temp_timestamps, rotation=45)
            ax.set_xticks(temp_sequence_numbers)
            ax.set_xticklabels(temp_timestamps, rotation=45, ha='right')
        else:
            # plt.xticks(sequence_numbers, timestamps, rotation=45)
            ax.set_xticks(sequence_numbers)
            ax.set_xticklabels(timestamps, rotation=45, ha='right')
        # plt.xlim(0, max([max(rtt_values[seq]) for seq in sequence_numbers]))

        if (len(sequence_numbers) != 0):
            plt.xlim(0, max(sequence_numbers))

        # print('working xlim', max([max(rtt_values[seq]) for seq in sequence_numbers]))

        # fixing the number of ticks to 30 in x-axis
        # plt.locator_params(axis='x', nbins=30)

        # Show the plot
        # plt.show()
        plt.savefig("%s.png" % "uptime_graph", dpi=96)
        plt.close()

        logger.debug("{}.png".format("uptime_graph"))
        return ("%s.png" % "uptime_graph")

    def generate_random_colors(self, n):
        colors = []
        numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        alpha = ['A', 'B', 'C', 'D', 'E', 'F']
        while len(colors) < n:
            color = '#' + ''.join(random.choices(numbers + alpha, k=6))
            if color != '#FFFFFF' and color not in colors:
                colors.append(color)
        return colors

    def build_line_graphs(self, report_path_date_time, report_obj=None):
        json_data = self.graph_values
        device_names = list(json_data.keys())
        num_devices = len(device_names)

        # Generate random colors for each device
        colors = self.generate_random_colors(num_devices)

        # Create a Plotly figure with subplots
        fig = make_subplots(rows=2, cols=1, row_heights=[0.7, 0.3], vertical_spacing=0.2,
                            specs=[[{"type": "xy"}], [{"type": "table"}]])
        figs, ax = plt.subplots(figsize=(15, len(device_names) * .5 + 10))

        all_rtts = []

        # Prepare the radio and station information
        radio_station_info = []
        # num_sta_each_radio = len(self.sta_list) // len(self.radio)
        for radio_index in self.radio_sta_info:
            radio_info = f"{radio_index} :  {self.radio_sta_info[radio_index]}"
            radio_station_info.append(radio_info)

        # Add radio and station info to Plotly graph
        fig.add_annotation(
            text='<br><br><br><br>'.join(radio_station_info),
            showarrow=False,
            xref="paper",
            yref="paper",
            x=0.5,
            y=1.15,
            xanchor='center',
            yanchor='bottom',
            align='center',
        )

        ax.text(0.5, 1.1, '\n'.join(radio_station_info), transform=ax.transAxes, fontsize=12, ha='center')
        for idx, (device_name, device_data) in enumerate(json_data.items()):
            rtts = []
            sequence_numbers = []
            if 'rtts' in device_data.keys():
                for seq in sorted(list(device_data['rtts'].keys())):
                    if device_data['rtts'][seq] == 0.11:
                        continue
                    rtts.append(device_data['rtts'][seq])
                    sequence_numbers.append(seq)

            # Collect all RTTs for y-axis limit calculation
            all_rtts.extend(rtts)

            if sequence_numbers and rtts:
                # Plotting with Matplotlib
                ax.plot(sequence_numbers, rtts, label=device_name, color=colors[idx], alpha=0.6)
                # Plotting with Plotly
                fig.add_trace(go.Scatter(
                    x=sequence_numbers, y=rtts, mode='lines', name=device_name, line=dict(color=colors[idx])
                ), row=1, col=1)

            ax.set_xlabel('Time', fontweight='bold', fontsize=15)
            ax.set_ylabel('RTT (ms)', fontweight='bold', fontsize=16)

            # Customize the plot
            start_time = self.start_time
            interval = timedelta(seconds=int(self.interval))

            timestamps = []
            for seq_num in sequence_numbers:
                timestamp = ((int(seq_num) - 1) * interval + start_time).strftime("%H:%M:%S")
                timestamps.append(timestamp)

            # Generating CSV
            with open(f'{report_obj.path_date_time}/{device_name}.csv', 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Time', 'RTT (ms)'])
                for row in range(len(timestamps)):
                    writer.writerow([timestamps[row], rtts[row]])

        # Define options for the dropdown menu
        dropdown_buttons = [
                               {
                                   "label": "All",
                                   "method": "update",
                                   "args": [{"visible": [True] * num_devices}, {"showlegend": True}]
                               },
                               {
                                   "label": "None",
                                   "method": "update",
                                   "args": [{"visible": "legendonly"}, {"showlegend": True}]
                               }
                           ] + [
                               {
                                   "label": device_names[i],
                                   "method": "update",
                                   "args": [{"visible": [j == i for j in range(num_devices)]}, {"showlegend": True}]
                               } for i in range(num_devices)
                           ]

        # Update layout for the combined figure
        fig.update_layout(
            title="RTT Line Graphs",
            xaxis_title="Time",
            yaxis_title="RTT (ms)",
            xaxis=dict(
                tickmode='array',
                tickvals=sequence_numbers,
                ticktext=timestamps,
                tickangle=45,
            ),
            yaxis=dict(range=[0, max(all_rtts) + 10] if all_rtts else [0, 10]),  # Increase y-axis limit by 10 in Plotly
            showlegend=True,
            updatemenus=[
                {
                    "buttons": dropdown_buttons,
                    "direction": "down",
                    "showactive": True,
                    "x": 1.15,
                    "xanchor": "left",
                    "y": 1.15,
                    "yanchor": "top"
                }
            ]
        )

        # Customize Matplotlib figure
        if len(sequence_numbers) > 30:
            temp_sequence_numbers = sequence_numbers[
                                    :len(sequence_numbers):max(round(len(timestamps) / 30), len(timestamps) // 30)]
            temp_timestamps = timestamps[:len(timestamps):max(round(len(timestamps) / 30), len(timestamps) // 30)]

            if len(temp_sequence_numbers) != len(temp_timestamps):
                temp_sequence_numbers.pop(0)
            ax.set_xticks(temp_sequence_numbers)
            ax.set_xticklabels(temp_timestamps, rotation=45, ha='right')
        else:
            ax.set_xticks(sequence_numbers)
            ax.set_xticklabels(timestamps, rotation=45, ha='right')
        if sequence_numbers:
            plt.xlim(0, max(sequence_numbers))

        # Set y-axis limit for Matplotlib
        if all_rtts:
            plt.ylim(0, max(all_rtts) + 10)

        # Add legend
        ax.legend()

        # Save the Matplotlib figure as a PNG image
        png_path = f"combined_graph.png"
        plt.savefig(png_path, dpi=96)
        plt.close()
        logger.debug(png_path)

        # Create the dataframe
        dataframe2 = pd.DataFrame({
            'Wireless Client': self.device_names,
            'MAC': self.device_mac,
            'Channel': self.device_channels,
            'Mode': self.device_modes,
            'Min RTT (ms)': self.device_min,
            'Average RTT (ms)': self.device_avg,
            'Max RTT (ms)': self.device_max
        })

        # Add table to Plotly figure
        fig.add_trace(go.Table(
            header=dict(values=list(dataframe2.columns),
                        fill_color='paleturquoise',
                        align='left'),
            cells=dict(values=[dataframe2[col] for col in dataframe2.columns],
                       fill_color='lavender',
                       align='left')
        ), row=2, col=1)

        # Save the Plotly figure as an HTML file
        html_path = f"{report_path_date_time}/combined_graph.html"
        fig.write_html(html_path)
        logger.debug(html_path)

        # Set graph image in the report object
        report_obj.set_graph_image(png_path)
        report_obj.move_graph_image()
        report_obj.build_graph()

    def store_csv(self, data=None):
        if (data is None):
            data = self.result_json

        if ('status' in data.keys() and data['status'] == 'Aborted'):
            return False
        else:
            data['status'] = 'Running'
            interval = timedelta(seconds=int(self.interval))
            for device, device_data in data.items():
                if (device == 'status'):
                    continue
                new_dict = {}
                sequence_numbers = {}
                for seq in device_data['rtts'].keys():
                    sequence_numbers[int(seq)] = ((int(seq) - 1) * interval + self.start_time).strftime(
                        "%d/%m/%Y %H:%M:%S")
                for seq in sorted(list(sequence_numbers.keys())):
                    new_dict[sequence_numbers[seq]] = device_data['rtts'][seq]
                # for seq,rtt in device_data['rtts'].items():
                #     new_dict[((int(seq) -1) * interval + self.start_time).strftime("%d/%m/%Y %H:%M:%S")] = rtt
                data[device]['webui_rtts'] = new_dict
        with open(self.ui_report_dir + '/runtime_ping_data.json', 'w') as f:
            json.dump(data, f, indent=4)
        test_name = self.ui_report_dir.split("/")[-1]
        with open(self.ui_report_dir + '/../../Running_instances/{}_{}_running.json'.format(self.host, test_name),
                  'r') as f:
            run_status = json.load(f)
            if run_status["status"] != "Running":
                logging.info('Test is stopped by the user')
                return False
        return True

    def set_webUI_stop(self):
        with open(self.ui_report_dir + '/runtime_ping_data.json', 'r') as f:
            data = json.load(f)

        if ('status' in data.keys() and data['status'] != 'Aborted'):
            data['status'] = 'Completed'

            with open(self.ui_report_dir + '/runtime_ping_data.json', 'w') as f:
                json.dump(data, f, indent=4)

    def copy_reports(self, report_path):
        logging.info('Copying PDF report and CSVs to webUI result directory')
        for file in os.listdir(report_path):
            if (file.endswith('.csv') or file.endswith('.pdf')):
                shutil.copy2(report_path + '/' + file, self.ui_report_dir)

    def generate_report(self, result_json=None, result_dir='Ping_Plotter_Test_Report', report_path=''):
        if result_json is not None:
            self.result_json = result_json
        logging.info('Generating Report')
        # graph for the above
        self.packets_sent = []
        self.packets_received = []
        self.packets_dropped = []
        self.packet_loss_percent = []
        # self.client_unrechability_percent = []
        self.device_names = []
        self.device_modes = []
        self.device_channels = []
        self.device_min = []
        self.device_max = []
        self.device_avg = []
        self.device_mac = []
        self.device_ips = []
        self.device_bssid = []
        self.device_names_with_errors = []
        self.devices_with_errors = []
        self.report_names = []
        self.remarks = []
        # packet_count_data = {}
        if (self.do_webUI and 'status' in self.result_json.keys()):
            del self.result_json['status']

        for device, device_data in self.result_json.items():
            self.packets_sent.append(int(device_data['sent']))
            self.packets_received.append(int(device_data['recv']))
            self.packets_dropped.append(int(device_data['dropped']))
            self.device_names.append(device_data['name'])
            self.device_modes.append(device_data['mode'])
            self.device_channels.append(device_data['channel'])
            self.device_mac.append(device_data['mac'])
            self.device_ips.append(device_data['ip'])
            self.device_bssid.append(device_data['bssid'])
            if (float(device_data['sent']) == 0):
                self.packet_loss_percent.append(0)
                # self.client_unrechability_percent.append(0)
            else:
                self.packet_loss_percent.append(float(device_data['dropped']) / float(device_data['sent']) * 100)
                # self.client_unrechability_percent.append(float(device_data['dropped']) / (float(self.duration) * 60) * 100)
            t_rtt_values = sorted(list(device_data['rtts'].values()))
            if (t_rtt_values != []):
                while (0.11 in t_rtt_values):
                    t_rtt_values.remove(0.11)
                self.device_avg.append(float(sum(t_rtt_values) / len(t_rtt_values)))
                self.device_min.append(float(min(t_rtt_values)))
                self.device_max.append(float(max(t_rtt_values)))
            else:
                self.device_avg.append(0)
                self.device_min.append(0)
                self.device_max.append(0)
            # self.device_avg.append(float(sum(t_rtt_values) / len(t_rtt_values)))
            # self.device_min.append(float(device_data['min_rtt'].replace(',', '')))
            # self.device_max.append(float(device_data['max_rtt'].replace(',', '')))
            # self.device_avg.append(float(device_data['avg_rtt'].replace(',', '')))
            if (device_data['os'] == 'Virtual'):
                self.report_names.append('{} {}'.format(device, device_data['os'])[0:25])
            else:
                self.report_names.append('{} {} {}'.format(device, device_data['os'], device_data['name'])[0:25])
            if (device_data['remarks'] != []):
                self.device_names_with_errors.append(device_data['name'])
                self.devices_with_errors.append(device)
                self.remarks.append(','.join(device_data['remarks']))
            logging.info('{} {} {}'.format(*self.packets_sent,
                                           *self.packets_received,
                                           *self.packets_dropped))
            logging.info('{} {} {}'.format(*self.device_min,
                                           *self.device_max,
                                           *self.device_avg))

        logging.info('Generating Report')

        report = lf_report(_output_pdf='interop_ping.pdf',
                           _output_html='interop_ping.html',
                           _results_dir_name=result_dir,
                           _path=report_path)
        report_path = report.get_path()
        report_path_date_time = report.get_path_date_time()
        logging.info('path: {}'.format(report_path))
        logging.info('path_date_time: {}'.format(report_path_date_time))

        # setting report title
        report.set_title('Ping Plotter Test Report')
        report.build_banner()

        # test setup info
        if (self.do_webUI):
            self.real_sta_list = self.sta_list
            for resource in self.real_sta_list:
                shelf, r_id, _ = resource.split('.')
                url = 'http://{}:{}/resource/{}/{}?fields=hw version'.format(self.host, self.port, shelf, r_id)
                hw_version = requests.get(url)
                hw_version = hw_version.json()
                if ('resource' in hw_version.keys()):
                    hw_version = hw_version['resource']
                    if ('hw version' in hw_version.keys()):
                        hw_version = hw_version['hw version']
                        print(hw_version)
                        if ('Win' in hw_version):
                            self.windows += 1
                        elif ('Lin' in hw_version):
                            self.linux += 1
                        elif ('Apple' in hw_version):
                            self.mac += 1
                        else:
                            self.android += 1
                    else:
                        logging.warning('Malformed response for hw version query on resource manager.')
                else:
                    logging.warning('Malformed response for hw version query on resource manager.')
        test_setup_info = {
            'SSID': [self.ssid if self.ssid else 'TEST CONFIGURED'][0],
            'Security': [self.security if self.ssid else 'TEST CONFIGURED'][0],
            'Website / IP': self.target,
            'No of Devices': '{} (V:{}, A:{}, W:{}, L:{}, M:{})'.format(len(self.sta_list),
                                                                        len(self.sta_list) - len(self.real_sta_list),
                                                                        self.android, self.windows, self.linux,
                                                                        self.mac),
            'Duration': self.duration
        }
        report.test_setup_table(
            test_setup_data=test_setup_info, value='Test Setup Information')

        # objective and description
        report.set_obj_html(_obj_title='Objective',
                            _obj='''Candela Ping Plotter Test assesses the network connectivity for specified clients by measuring Round
                            Trip data packet Travel time. It also detects issues like packet loss, delays, and
                            response time variations, ensuring effective device communication and identifying
                            connectivity problems.
                            ''')
        report.build_objective()

        # uptime and downtime
        report.set_table_title(
            'Individual Ping Plotter Graph for {} duration:'.format(self.duration)
        )
        report.build_table_title()
        # graph for above
        uptime_graph = self.generate_uptime_graph()
        logging.info('uptime graph name {}'.format(uptime_graph))
        report.set_graph_image(uptime_graph)

        # need to move the graph image to the results directory
        report.move_graph_image()

        # report.set_csv_filename(uptime_graph)
        # report.move_csv_file()
        report.build_graph()

        # individual client report table
        report.set_table_title(
            'Individual client table report:'
        )
        report.build_table_title()

        individual_report_df = pd.DataFrame({
            'Wireless Client': self.report_names,
            'IP Address': self.device_ips,
            'MAC': self.device_mac,
            'BSSID': self.device_bssid,
            'Channel': self.device_channels,
            'Packets Sent': self.packets_sent,
            'Packets Received': self.packets_received,
            'Packet Loss %': self.packet_loss_percent,
            'AVG RTT (ms)': self.device_avg,
            # 'Client Unrechability %': self.client_unrechability_percent
        })
        report.set_table_dataframe(individual_report_df)
        report.build_table()

        # packets sent vs received vs dropped
        report.set_table_title(
            'Packets sent vs packets received vs packets dropped')
        report.build_table_title()
        x_fig_size = 20
        y_fig_size = len(self.device_names) * .5 + 4
        graph = lf_bar_graph_horizontal(_data_set=[self.packets_dropped, self.packets_received, self.packets_sent],
                                        _xaxis_name='Packets Count',
                                        _yaxis_name='Wireless Clients',
                                        _label=[
                                            'Packets Loss', 'Packets Received', 'Packets Sent'],
                                        _graph_image_name='Packets sent vs received vs dropped',
                                        _yaxis_label=self.report_names,
                                        _yaxis_categories=self.report_names,
                                        _yaxis_step=1,
                                        _yticks_font=8,
                                        _graph_title='Packets sent vs received vs dropped',
                                        _title_size=16,
                                        _color=['lightgrey',
                                                'orange', 'steelblue'],
                                        _color_edge=['black'],
                                        _bar_height=0.15,
                                        _figsize=(x_fig_size, y_fig_size),
                                        _legend_loc="best",
                                        _legend_box=(1.0, 1.0),
                                        _dpi=96,
                                        _show_bar_value=False,
                                        _enable_csv=True,
                                        _color_name=['lightgrey', 'orange', 'steelblue'])

        graph_png = graph.build_bar_graph_horizontal()
        logging.info('graph name {}'.format(graph_png))
        report.set_graph_image(graph_png)
        # need to move the graph image to the results directory
        report.move_graph_image()
        report.set_csv_filename(graph_png)
        report.move_csv_file()
        report.build_graph()

        dataframe1 = pd.DataFrame({
            'Wireless Client': self.device_names,
            'MAC': self.device_mac,
            'Channel': self.device_channels,
            'Mode': self.device_modes,
            'Packets Sent': self.packets_sent,
            'Packets Received': self.packets_received,
            'Packets Loss': self.packets_dropped
        })
        report.set_table_dataframe(dataframe1)
        report.build_table()

        # packets rtt graph
        report.set_table_title('Ping RTT Graph')
        report.build_table_title()

        graph = lf_bar_graph_horizontal(_data_set=[self.device_min, self.device_avg, self.device_max],
                                        _xaxis_name='Time (ms)',
                                        _yaxis_name='Wireless Clients',
                                        _label=[
                                            'Min RTT (ms)', 'Average RTT (ms)', 'Max RTT (ms)'],
                                        _graph_image_name='Ping RTT per client',
                                        _yaxis_label=self.report_names,
                                        _yaxis_categories=self.report_names,
                                        _yaxis_step=1,
                                        _yticks_font=8,
                                        _graph_title='Ping RTT per client',
                                        _title_size=16,
                                        _color=['lightgrey',
                                                'orange', 'steelblue'],
                                        _color_edge='black',
                                        _bar_height=0.15,
                                        _figsize=(x_fig_size, y_fig_size),
                                        _legend_loc="best",
                                        _legend_box=(1.0, 1.0),
                                        _dpi=96,
                                        _show_bar_value=False,
                                        _enable_csv=True,
                                        _color_name=['lightgrey', 'orange', 'steelblue'])

        graph_png = graph.build_bar_graph_horizontal()
        logging.info('graph name {}'.format(graph_png))
        report.set_graph_image(graph_png)
        # need to move the graph image to the results directory
        report.move_graph_image()
        report.set_csv_filename(graph_png)
        report.move_csv_file()
        report.build_graph()

        dataframe2 = pd.DataFrame({
            'Wireless Client': self.device_names,
            'MAC': self.device_mac,
            'Channel': self.device_channels,
            'Mode': self.device_modes,
            'Min RTT (ms)': self.device_min,
            'Average RTT (ms)': self.device_avg,
            'Max RTT (ms)': self.device_max
        })
        report.set_table_dataframe(dataframe2)
        report.build_table()

        # realtime ping graphs
        report.set_table_title(' RTT vs Time Plots:')
        report.build_table_title()

        # graphs for above
        self.build_line_graphs(report_path_date_time, report_obj=report)

        # check if there are remarks for any device. If there are remarks, build table else don't
        if (self.remarks != []):
            report.set_table_title('Notes')
            report.build_table_title()
            dataframe3 = pd.DataFrame({
                'Wireless Client': self.device_names_with_errors,
                'Port': self.devices_with_errors,
                'Remarks': self.remarks
            })
            report.set_table_dataframe(dataframe3)
            report.build_table()

        # closing
        report.build_custom()
        report.build_footer()
        report.write_html()
        report.write_pdf()

        if (self.do_webUI):
            self.copy_reports(report_path_date_time)
        webbrowser.open(f"{os.getcwd()}/{report_path_date_time}/combined_graph.html")


def main():
    help_summary = '''\
The Candela Tech ping plotter test assesses the network connectivity for specified clients by measuring Round
Trip data packet travel time. It also detects issues like packet loss, delays, and
response time variations, ensuring effective device communication and identifying
connectivity problems.
    '''
    parser = argparse.ArgumentParser(
        prog='interop_ping.py',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''
            Allows user to run the ping plotter test on a target IP for the given duration and packet interval
            with either selected number of virtual stations or provides the list of available real devices
            and allows the user to select the real devices and run ping plotter test on them.
        ''',
        description='''
    NAME: lf_interop_ping_plotter.py

    PURPOSE: lf_interop_ping_plotter.py will let the user select real devices, virtual devices or both and then allows them to run
    ping plotter test for user given duration and packet interval on the given target IP or domain name and generates realtime ping status and line charts for every device.

    EXAMPLE-1:
    Command Line Interface to run ping plotter test with only virtual clients with eth1 as the default target
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.103 --virtual --num_sta 1 --radio 1.1.wiphy2 --ssid RDT_wpa2 --security wpa2 
    --passwd OpenWifi --ping_interval 1 --ping_duration 1m --server_ip 192.168.1.61 --debug

    EXAMPLE-2:
    Command Line Interface to stop cleaning up stations after the test
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.103 --virtual --num_sta 1 --radio 1.1.wiphy2 --ssid RDT_wpa2 --security wpa2 
    --passwd OpenWifi --ping_interval 1 --ping_duration 1m --server_ip 192.168.1.61 --debug --no_cleanup

    EXAMPLE-3:
    Command Line Interface to run ping plotter test with only real clients
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.103 --real --ping_interval 1 --ping_duration 1m --server_ip 192.168.1.61

    EXAMPLE-4:
    Command Line Interface to run ping plotter test with both real and virtual clients
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.103 --real --virtual --num_sta 1 --radio 1.1.wiphy2 --ssid RDT_wpa2 --security wpa2
    --passwd OpenWifi --ping_interval 1 --ping_duration 1m --server_ip 192.168.1.61

    EXAMPLE-5:
    Command Line Interface to run ping plotter test with a different target
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.63 --real --ping_interval 5 --ping_duration 1m --target 192.168.1.61

    EXAMPLE-6:
    Command Line Interface to run ping plotter test with a Multiple radios
    python3 lf_interop_ping_plotter.py --mgr 192.168.200.145 --ping_interval 1 --target 8.8.8.8 --radios "radio==1.1.wiphy1 num_sta==3 ssid==SVB  passwd==Password@123 security==wpa2" 
    --radios "radio==1.1.wiphy0 num_sta==1 ssid==SVB  passwd==Password@123 security==wpa2"  --debug --virtual

    --no_pre_cleanup
                    Disables generic endpoints cleanup before creation of new endpoints.

            example:
            python3 lf_interop_ping_plotter.py --mgr 192.168.200.145 --ping_interval 1 --target 8.8.8.8 --radios "radio==1.1.wiphy1 num_sta==3 ssid==SVB  passwd==Password@123 security==wpa2" 
            --radios "radio==1.1.wiphy0 num_sta==1 ssid==SVB  passwd==Password@123 security==wpa2"  --debug --virtual --no_pre_cleanup

    --no_cleanup
                    Add this flag to stop cleaning generic endpoints after completion of the test.



    SCRIPT_CLASSIFICATION : Test

    SCRIPT_CATEGORIES: Performance, Functional, Report Generation

    NOTES:
    1.Use './lf_interop_ping.py --help' to see command line usage and options
    2.Use 's','m','h' as suffixes for ping_duration in seconds, minutes and hours respectively
    3.After passing the cli, if --real flag is selected, then a list of available real devices will be displayed on the terminal
    4.Enter the real device resource numbers seperated by commas (,)
    5.For --target, you can specify it as eth1, IP address or domain name (e.g., google.com)

    * For enterprise authentication with multiple radios, please use the following command line arguments:
            eap_method==<eap_method>
                    Add this argument to specify the EAP method

            example:
                    DEFAULT
                    EAP-MD5
                    MSCHAPV2
                    EAP-OTP
                    EAP-GTC
                    EAP-TLS
                    EAP-PEAP
                    EAP-TTLS
                    EAP-SIM
                    EAP-AKA
                    EAP-PSK
                    EAP-IKEV2
                    EAP-FAST
                    WFA-UNAUTH-TLS
                    TTLS PEAP TLS

            --pairwise==[BLANK]
                    Add this argument to specify the type of pairwise cipher

                DEFAULT
                CCMP
                TKIP
                NONE
                CCMP TKIP
                CCMP-256
                GCMP (wpa3)
                GCMP-256 (wpa3)
                CCMP/GCMP-256 (wpa3)

            --groupwise==[BLANK]
                    Add this argument to specify the type of groupwise cipher

                DEFAULT
                CCMP
                WEP104
                WEP40
                GTK_NOT_USED
                GCMP-256 (wpa3)
                CCMP-256 (wpa3)
                GCMP/CCMP-256 (wpa3)
                All

            --key_mgmt==<SAE>
                    Add this flag to give the key management value

                DEFAULT
                NONE
                WPA-PSK
                FT-PSK (11r)
                FT-EAP (11r)
                FT-SAE (11r)
                FT-SAE-EXT-KEY (11r)
                FT-EAP-SHA384 (11r)
                WPA-EAP
                OSEN
                IEEE8021X
                WPA-PSK-SHA256
                WPA-EAP-SHA256
                PSK & EAP 128
                PSK & EAP 256
                PSK & EAP 128/256
                SAE
                SAE-EXT-KEY
                WPA-EAP-SUITE-B
                WPA-EAP-SUITE-B-192
                FILS-SHA256
                FILS-SHA384
                OWE

    STATUS: BETA RELEASE

    VERIFIED_ON:
    Working date    - 06/12/2023
    Build version   - 5.4.7
    kernel version  - 6.2.16+

    License: Free to distribute and modify. LANforge systems must be licensed.
    Copyright 2023 Candela Technologies Inc.
        '''
    )
    required = parser.add_argument_group('Required arguments')
    optional = parser.add_argument_group('Optional arguments')
    webUI_args = parser.add_argument_group('webUI arguments') \
 \
        # optional arguments
    optional.add_argument('--mgr',
                          type=str,
                          help='hostname where LANforge GUI is running',
                          default='localhost')

    optional.add_argument('--target',
                          type=str,
                          help='Target URL or port for ping plotter test',
                          default='1.1.eth1')

    optional.add_argument('--ping_interval',
                          type=str,
                          help='Interval (in seconds) between the echo requests',
                          default='1')

    optional.add_argument('--ping_duration',
                          type=str,
                          help='Duration to run the ping plotter test',
                          default='1m')

    optional.add_argument('--ssid',
                          type=str,
                          help='SSID for connecting the stations')

    optional.add_argument('--mgr_port',
                          type=str,
                          default=8080,
                          help='port on which LANforge HTTP service is running'
                          )

    optional.add_argument('--mgr_passwd',
                          type=str,
                          default='lanforge',
                          help='Password to connect to LANforge GUI')

    optional.add_argument('--server_ip',
                          type=str,
                          help='Upstream for configuring the Interop App')

    optional.add_argument('--security',
                          type=str,
                          default='open',
                          help='Security protocol for the specified SSID: <open | wep | wpa | wpa2 | wpa3>')

    optional.add_argument('--passwd',
                          type=str,
                          default='[BLANK]',
                          help='passphrase for the specified SSID')

    optional.add_argument('--virtual',
                          action="store_true",
                          help='specify this flag if the test should run on virtual clients')

    optional.add_argument('--num_sta',
                          type=int,
                          default=1,
                          help='specify the number of virtual stations to be created.')

    optional.add_argument('--radio',
                          type=str,
                          help='specify the radio to create the virtual stations')

    optional.add_argument(
        '-r', '--radios',
        action='append',
        nargs=1,
        help=(' --radios'
              ' radio==<wiphy radios>, num_sta==<number of stations>'
              ' ssid==<ssid>, passwd==<ssid password>, security==<security> '
              ' eap_method==<mention eap_method>,identity==<mention identity>,'
              ' anonymous==<mention anonymous>,eap_password==<mention eap_password>,'
              ' phase1==<mention phase1>,phase2==<mention phase2>,pk_passwd==<mention pk_passwd>,'
              ' ca_cert==<mention ca_cert>,private_key==<mention private_key>,'
              ' key_mgmt==<mention key_mgmt>,pairwise==<mention pairwise>,group==<mention group>,'
              ' custom_wifi_cmd==<custom_command>'
              )
    )

    optional.add_argument('--real',
                          action="store_true",
                          help='specify this flag if the test should run on real clients')

    optional.add_argument('--use_default_config',
                          action='store_true',
                          help='specify this flag if wanted to proceed with existing Wi-Fi configuration of the devices')

    optional.add_argument('--debug',
                          action="store_true",
                          help='Enable debugging')

    optional.add_argument('--no_cleanup',
                          action="store_true",
                          help='specify this flag to stop cleaning up generic cxs after the test')

    optional.add_argument('--no_pre_cleanup',
                          action="store_true",
                          help='specify this flag to stop cleaning up generic cxs before the test use when mention use_existing_stations argument')

    optional.add_argument('--use_existing_station_list',
                          action="store_true",
                          help='Use existing station instead of trying to create stations.')

    optional.add_argument('--existing_station_list',
                          action='append',
                          nargs=1,
                          help='--existing_station_list [list of stations] , use the stations in the list , multiple station lists may be entered')

    # webUI arguments
    webUI_args.add_argument('--do_webUI',
                            action='store_true',
                            help='specify this flag when triggering a test from webUI')

    webUI_args.add_argument('--resources',
                            help='Specify the real device ports seperated by comma')

    webUI_args.add_argument('--ui_report_dir',
                            help='Specify the results directory to store the reports for webUI')

    # logging configuration:
    parser.add_argument('--log_level', default=None,
                        help='Set logging level: debug | info | warning | error | critical')

    parser.add_argument("--lf_logger_config_json",
                        help="--lf_logger_config_json <json file> , json configuration of logger")

    parser.add_argument('--help_summary', default=None, action="store_true",
                        help='Show summary of what this script does')

    args = parser.parse_args()

    if args.help_summary:
        print(help_summary)
        exit(0)

    # set the logger level to debug
    logger_config = lf_logger_config.lf_logger_config()

    if args.log_level:
        logger_config.set_level(level=args.log_level)

    if args.lf_logger_config_json:
        # logger_config.lf_logger_config_json = "lf_logger_config.json"
        logger_config.lf_logger_config_json = args.lf_logger_config_json
        logger_config.load_lf_logger_config()

    # input sanity
    if (args.virtual is False and args.real is False) or (args.use_existing_station_list):
        if args.existing_station_list is None:
            print('existing stations are required')
            exit(0)
    # if (args.virtual is True and args.radio is None and args.radios is None):
    #     print('--radio required')
    #     exit(0)
    if (args.virtual is True and args.ssid is None) and (args.radio is not None):
        print('--ssid required for virtual stations')
        exit(0)
    if (args.security != 'open' and args.passwd == '[BLANK]') and (args.radio is not None):
        print('--passwd required')
        exit(0)

    # configure = not args.use_default_config # removed connectivity from this script, unblock this line to enable connectivity for real devices
    configure = False  # comment this line to enable connectivity for real devices

    if configure:
        if (args.ssid is None):
            print('--ssid required for Wi-Fi configuration')
            exit(0)

        if (args.security.lower() != 'open' and args.passwd == '[BLANK]'):
            print('--passwd required for Wi-Fi configuration')
            exit(0)

        if (args.server_ip is None):
            print('--server_ip or upstream ip required for Wi-fi configuration')
            exit(0)

    mgr_ip = args.mgr
    mgr_password = args.mgr_passwd
    mgr_port = args.mgr_port
    server_ip = args.server_ip
    ssid = args.ssid
    security = args.security
    password = args.passwd
    num_sta = args.num_sta
    radio = args.radio
    target = args.target
    interval = args.ping_interval
    duration = args.ping_duration
    if ('s' in duration):
        duration = float(duration.replace('s', '')) / 60
        report_duration = '00:00:{:02}'.format(int(args.ping_duration.replace('s', '')))
    elif ('m' in duration):
        duration = float(duration.replace('m', ''))
        report_duration = '00:{:02}:00'.format(int(args.ping_duration.replace('m', '')))
    elif ('h' in duration):
        duration = float(duration.replace('h', '')) * 60
        report_duration = '{:02}:00:00'.format(int(args.ping_duration.replace('h', '')))

    # webUI argument check
    do_webUI = args.do_webUI
    webUI_resources = args.resources
    ui_report_dir = args.ui_report_dir
    # if webUI_resources is not None:
    #     do_webUI = True
    if (do_webUI and webUI_resources is None):
        print('--resources argument is required when --do_webUI is specified')
        exit(0)
    if (do_webUI and ui_report_dir is None):
        print('--ui_report_dir argument is required when --do_webUI is specified')
        exit(0)

    debug = args.debug

    if (debug):
        print('''Specified configuration:
              ip:                       {}
              port:                     {}
              ssid:                     {}
              security:                 {}
              password:                 {}
              target:                   {}
              Ping interval:            {}
              Packet Duration (in min): {}
              virtual:                  {}
              num of virtual stations:  {}
              radio:                    {}
              real:                     {}
              debug:                    {}
              '''.format(mgr_ip, mgr_port, ssid, security, password, target, interval, duration, args.virtual, num_sta,
                         radio, args.real, debug))

    if args.radios and (not args.use_existing_station_list):
        radios = args.radios
        radio_name_list = []
        number_of_stations_per_radio_list = []
        ssid_list = []
        password_list = []
        security_list = []
        pairwise_cipher_list = []
        groupwise_cipher_list = []
        eap_identity_list = []
        eap_password_list = []
        private_key_list = []
        ca_cert_list = []
        pk_passwd_list = []
        eap_phase1_list = []
        eap_phase2_list = []
        eap_method_list = []
        key_mgmt_list = []
        eap_anonymous_identity_list = []
        custom_wifi_cmd_list = []
        # ping object creation
        radio_keys = ['radio', 'security', 'ssid', 'passwd', 'num_sta', 'pairwise_cipher', 'groupwise_cipher',
                      'eap_identity', 'eap_password', 'private_key', 'ca_cert', 'pk_passwd', 'eap_phase1', 'eap_phase2',
                      'eap_method', 'key_mgmt', 'eap_anonymous_identity']
        if (not args.use_existing_station_list):
            for radio_ in radios:
                logger.info("radio_dict before format {}".format(radio_))
                radio_info_dict = dict(
                    map(
                        lambda x: x.split('=='),
                        str(radio_).replace(
                            '"',
                            '').replace(
                            '[',
                            '').replace(
                            ']',
                            '').replace(
                            "'",
                            "").replace(
                            ",",
                            " ").split()))
                logger.debug("radio_dict {}".format(radio_info_dict))
                print("Check dict ==>", radio_info_dict)
                for key in radio_keys:
                    if key not in radio_info_dict:
                        if hasattr(args, f'{key}'):
                            radio_info_dict[f'{key}'] = getattr(args, f'{key}')
                        else:
                            radio_info_dict[f'{key}'] = '[BLANK]'
                logger.info("radio_dict after format {}".format(radio_info_dict))
                radio_name_list.append(radio_info_dict['radio'])
                number_of_stations_per_radio_list.append(int(radio_info_dict['num_sta']))
                ssid_list.append(radio_info_dict.get('ssid'))
                password_list.append(radio_info_dict.get('passwd'))
                security_list.append(radio_info_dict.get('security'))
                pairwise_cipher_list.append(radio_info_dict.get('pairwise_cipher'))
                groupwise_cipher_list.append(radio_info_dict.get('groupwise_cipher'))
                eap_identity_list.append(radio_info_dict.get('eap_identity'))
                eap_password_list.append(radio_info_dict.get('eap_password'))
                private_key_list.append(radio_info_dict.get('private_key'))
                ca_cert_list.append(radio_info_dict.get('ca_cert'))
                pk_passwd_list.append(radio_info_dict.get('pk_passwd'))
                eap_phase1_list.append(radio_info_dict.get('phase1'))
                eap_phase2_list.append(radio_info_dict.get('phase2'))
                eap_method_list.append(radio_info_dict.get('eap_method'))
                key_mgmt_list.append(radio_info_dict.get('key_mgmt'))
                eap_anonymous_identity_list.append(radio_info_dict.get('anonymous'))
                custom_wifi_cmd_list.append(radio_info_dict.get('custom_wifi_cmd'))

        ping = Ping(host=mgr_ip, port=mgr_port, ssid=ssid, security=security, password=password, radio=radio,
                    lanforge_password=mgr_password, target=target, interval=interval, sta_list=[], virtual=args.virtual,
                    real=args.real, existing_sta=args.use_existing_station_list, duration=report_duration,
                    do_webUI=do_webUI, ui_report_dir=ui_report_dir, debug=debug)

    elif args.radio and (not args.use_existing_station_list):
        ping = Ping(host=mgr_ip, port=mgr_port, ssid=ssid, security=security, password=password, radio=radio,
                    lanforge_password=mgr_password, target=target, interval=interval, sta_list=[], virtual=args.virtual,
                    real=args.real, existing_sta=args.use_existing_station_list, duration=report_duration,
                    do_webUI=do_webUI, ui_report_dir=ui_report_dir, debug=debug)

    if args.radios and (not args.use_existing_station_list):
        # creating virtual stations if --virtual flag is specified
        if (not args.no_pre_cleanup):
            ping.cleanup()
        if (args.virtual):
            logging.info('Proceeding to create {} virtual stations on {}'.format(num_sta, radio))
            ping.sta_list = []
            start_id = 0
            for (radio, num_sta,
                 ssid,
                 password,
                 security,
                 pairwise_cipher,
                 groupwise_cipher,
                 eap_identity,
                 eap_password,
                 private_key,
                 ca_cert,
                 pk_passwd,
                 eap_phase1,
                 eap_phase2,
                 eap_method,
                 key_mgmt,
                 eap_anonymous_identity,
                 custom_wifi_cmd
                 ) in \
                    zip(radio_name_list,
                        number_of_stations_per_radio_list,
                        ssid_list,
                        password_list,
                        security_list,
                        pairwise_cipher_list,
                        groupwise_cipher_list,
                        eap_identity_list,
                        eap_password_list,
                        private_key_list,
                        ca_cert_list,
                        pk_passwd_list,
                        eap_phase1_list,
                        eap_phase2_list,
                        eap_method_list,
                        key_mgmt_list,
                        eap_anonymous_identity_list,
                        custom_wifi_cmd_list
                        ):
                station_list = LFUtils.port_name_series(prefix="sta",
                                                        start_id=start_id,
                                                        end_id=start_id + num_sta - 1,
                                                        padding_number=10000,
                                                        radio=radio)

                if not args.no_pre_cleanup:
                    for station in station_list:
                        print('Removing the station {} if exists'.format(station))
                        ping.rm_port(station, check_exists=True)
                    if (not LFUtils.wait_until_ports_disappear(base_url='http://{}:{}'.format(ping.host, ping.port),
                                                               port_list=station_list)):
                        print('All stations are not removed or a timeout occurred.')
                        print('Aborting the test.')
                        exit(1)

                ping.build_stations(radio,
                                    station_list,
                                    ssid,
                                    password,
                                    security,
                                    pairwise_cipher,
                                    groupwise_cipher,
                                    eap_identity,
                                    eap_password,
                                    private_key,
                                    ca_cert,
                                    pk_passwd,
                                    eap_phase1,
                                    eap_phase2,
                                    eap_method,
                                    key_mgmt,
                                    eap_anonymous_identity,
                                    custom_wifi_cmd)
                ping.radio_sta_info[radio] = station_list
                ping.sta_list += station_list
                start_id += len(ping.sta_list)
            if (debug):
                logging.info('Virtual Stations: {}'.format(station_list).replace(
                    '[', '').replace(']', '').replace('\'', ''))

    elif args.radio and (not args.use_existing_station_list):
        # station cleanup
        if (not args.no_pre_cleanup):
            ping.cleanup()
        logging.info('Proceeding to create {} virtual stations on {}'.format(num_sta, radio))
        station_list = LFUtils.portNameSeries(
            prefix_='sta', start_id_=0, end_id_=num_sta - 1, padding_number_=100000, radio=radio)
        ping.sta_list = station_list
        if debug:
            logging.info('Virtual Stations: {}'.format(station_list).replace(
                '[', '').replace(']', '').replace('\'', ''))

        if args.virtual:
            ping.buildstation()

    if (args.real) and (not args.use_existing_station_list):
        # NOTE: Removed connectivity from ping plotter, adding it in mixed traffic test
        Devices = RealDevice(manager_ip=mgr_ip,
                             server_ip=server_ip,
                             ssid_2g='Test Configured',
                             passwd_2g='',
                             encryption_2g='',
                             ssid_5g='Test Configured',
                             passwd_5g='',
                             encryption_5g='',
                             ssid_6g='Test Configured',
                             passwd_6g='',
                             encryption_6g='',
                             selected_bands=['5G'])
        if (configure):
            # Run the event loop
            asyncio.run(Devices.query_all_devices_to_configure_wifi())
            logging.info('{}'.format(*Devices.station_list))
            ping.select_real_devices(real_devices=Devices, real_sta_list=Devices.station_list, base_interop_obj=Devices)
        else:
            Devices.get_devices()
            ping.Devices = Devices
            if (not do_webUI):  # if webUI_resources is not None then do_webUI is True
                ping.select_real_devices(real_devices=Devices)
            else:
                webUI_resources = webUI_resources.split(',')
                ping.select_real_devices(real_devices=Devices, real_sta_list=webUI_resources, base_interop_obj=Devices)

    if args.use_existing_station_list:
        if args.existing_station_list is not None:
            existing_station_lists = []
            for existing_sta_list in args.existing_station_list:
                existing_stations = (
                    str(existing_sta_list)
                    .replace('"', "")
                    .replace("[", "")
                    .replace("]", "")
                    .replace("'", "")
                    .replace(",", " ")
                    .split()
                )

                for existing_sta in existing_stations:
                    existing_station_lists.append(existing_sta)
        else:
            logger.error("--use_station_list set true, --station_list is None Exiting")
            raise Exception(
                "--use_station_list is used in conjunction with a --station_list"
            )
        ping = Ping(
            host=mgr_ip,
            port=mgr_port,
            ssid=ssid,
            security=security,
            password=password,
            radio=radio,
            lanforge_password=mgr_password,
            target=target,
            interval=interval,
            sta_list=[],
            virtual=args.virtual,
            real=args.real,
            existing_sta=args.use_existing_station_list,
            duration=report_duration,
            do_webUI=do_webUI,
            ui_report_dir=ui_report_dir,
            debug=debug,
        )
        if (not args.no_pre_cleanup):
            result = ping.json_get(
            "/generic/")
            if 'endpoints' in result.keys():
                for i in result['endpoints']:
                    for key, val in i.items():
                        if val['name']:
                            req_url = "cli-json/rm_cx"
                            data = {
                                "test_mgr": "default_tm",
                                "cx_name": "CX_" + val['name']
                            }
                            ping.json_post(req_url, data)
                            req_url = "cli-json/rm_endp"
                            data = {
                                "endp_name": val['name']
                            }
                            ping.json_post(req_url, data)


    # check if generic tab is enabled or not
    if (not ping.check_tab_exists()):
        logging.error('Generic Tab is not available.\nAborting the test.')
        exit(0)

    if (args.use_existing_station_list):
        ping.sta_list += existing_station_lists
    else:
        ping.sta_list += ping.real_sta_list

    # creating generic endpoints
    ping.create_generic_endp()

    logging.info('{}'.format(*ping.generic_endps_profile.created_cx))

    # run the test for the given duration
    logging.info('Running the ping plotter test for {} minutes'.format(duration))

    ping.start_time = datetime.now()

    # start generate endpoint
    ping.start_generic()
    time_counter = 0
    ports_data_dict = ping.json_get('/ports/all/')['interfaces']
    ports_data = {}
    for ports in ports_data_dict:
        port, port_data = list(ports.keys())[0], list(ports.values())[0]
        ports_data[port] = port_data

    duration = duration * 60

    loop_timer = 0
    logging.info(ping.result_json)
    rtts = {}
    rtts_list = []
    for station in ping.sta_list:
        rtts[station] = {}
    time.sleep(1)
    while (loop_timer <= duration):
        t_init = datetime.now()
        result_data = ping.get_results()
        # logging.info(result_data)
        if (args.virtual):
            ports_data_dict = ping.json_get('/ports/all/')['interfaces']
            ports_data = {}
            for ports in ports_data_dict:
                port, port_data = list(ports.keys())[0], list(ports.values())[0]
                ports_data[port] = port_data
            if (type(result_data) == dict):
                for station in ping.sta_list:
                    if (station not in ping.real_sta_list):
                        current_device_data = ports_data[station]
                        if (station.split('.')[2] in result_data['name']):
                            ping.result_json[station] = {
                                'command': result_data['command'],
                                'sent': result_data['tx pkts'],
                                'recv': result_data['rx pkts'],
                                'dropped': result_data['dropped'],
                                # 'min_rtt': [result_data['last results'].split('\n')[-2].split()[-1].split('/')[0] if len(result_data['last results']) != 0 and 'min/avg/max' in result_data['last results'] else '0'][0],
                                # 'avg_rtt': [result_data['last results'].split('\n')[-2].split()[-1].split('/')[1] if len(result_data['last results']) != 0 and 'min/avg/max' in result_data['last results'] else '0'][0],
                                # 'max_rtt': [result_data['last results'].split('\n')[-2].split()[-1].split('/')[2] if len(result_data['last results']) != 0 and 'min/avg/max' in result_data['last results'] else '0'][0],
                                'mac': current_device_data['mac'],
                                'ip': current_device_data['ip'],
                                'bssid': current_device_data['ap'],
                                'channel': current_device_data['channel'],
                                'mode': current_device_data['mode'],
                                'name': station,
                                'os': 'Virtual',
                                'remarks': [],
                                'last_result': [result_data['last results'].split('\n')[-2] if len(
                                    result_data['last results']) != 0 else ""][0]
                            }
                            if (len(result_data['last results']) != 0 and 'min/avg/max' in result_data['last results']):
                                temp_last_results = result_data['last results'].split('\n')[
                                                    0: len(result_data['last results']) - 1]
                                drop_count = 0  # let dropped = 0 initially
                                dropped_packets = []
                                for result in temp_last_results:  # sample result - 64 bytes from 192.168.1.61: icmp_seq=28 time=3.66 ms *** drop: 0 (0, 0.000)  rx: 28  fail: 0  bytes: 1792 min/avg/max: 2.160/3.422/5.190
                                    try:
                                        t_result, t_fail = result.split(
                                            '***')  # fetching the first part of the last result e.g., 64 bytes from 192.168.1.61: icmp_seq=28 time=3.66 ms into t_result and the remaining part into t_fail
                                    except:
                                        continue
                                    t_result = t_result.split()
                                    if ('icmp_seq=' not in result and 'time=' not in result):
                                        continue
                                    for t_data in t_result:
                                        if ('icmp_seq=' in t_data):
                                            seq_number = int(t_data.strip('icmp_seq='))
                                        if ('time=' in t_data):
                                            rtt = float(t_data.strip('time='))
                                    rtts[station][seq_number] = rtt
                                    rtts_list.append(rtt)

                                    # finding dropped packets
                                    t_fail = t_fail.split()  # [' drop:', '0', '(0, 0.000)', 'rx:', '28', 'fail:', '0', 'bytes:', '1792', 'min/avg/max:', '2.160/3.422/5.190']
                                    t_drop_val = t_fail[1]  # t_drop_val = '0'
                                    t_drop_val = int(t_drop_val)  # type cast string to int
                                    if (t_drop_val != drop_count):
                                        current_drop_packets = t_drop_val - drop_count
                                        drop_count = t_drop_val
                                        for drop_packet in range(1, current_drop_packets + 1):
                                            dropped_packets.append(seq_number - drop_packet)

                            if (rtts_list == []):
                                rtts_list = [0]
                            min_rtt = str(min(rtts_list))
                            avg_rtt = str(sum(rtts_list) / len(rtts_list))
                            max_rtt = str(max(rtts_list))
                            ping.result_json[station]['min_rtt'] = min_rtt
                            ping.result_json[station]['avg_rtt'] = avg_rtt
                            ping.result_json[station]['max_rtt'] = max_rtt
                            if (list(rtts[station].keys()) != []):
                                required_sequence_numbers = list(range(1, max(rtts[station].keys())))
                                for seq in required_sequence_numbers:
                                    if (seq not in rtts[station].keys()):
                                        if (seq in dropped_packets):
                                            rtts[station][seq] = 0
                                        else:
                                            rtts[station][seq] = 0.11
                            else:
                                ping.result_json[station]['rtts'] = {}
                            ping.result_json[station]['rtts'] = rtts[station]
                            ping.result_json[station]['remarks'] = ping.generate_remarks(ping.result_json[station])
                            # ping.result_json[station]['dropped_packets'] = dropped_packets

            else:
                for station in ping.sta_list:
                    if (station not in ping.real_sta_list):
                        current_device_data = ports_data[station]
                        for ping_device in result_data:
                            ping_endp, ping_data = list(ping_device.keys())[0], list(ping_device.values())[0]
                            if (station.split('.')[2] in ping_endp):
                                ping.result_json[station] = {
                                    'command': ping_data['command'],
                                    'sent': ping_data['tx pkts'],
                                    'recv': ping_data['rx pkts'],
                                    'dropped': ping_data['dropped'],
                                    # 'min_rtt': [ping_data['last results'].split('\n')[-2].split()[-1].split('/')[0] if len(ping_data['last results']) != 0 and 'min/avg/max' in ping_data['last results'] else '0'][0],
                                    # 'avg_rtt': [ping_data['last results'].split('\n')[-2].split()[-1].split('/')[1] if len(ping_data['last results']) != 0 and 'min/avg/max' in ping_data['last results'] else '0'][0],
                                    # 'max_rtt': [ping_data['last results'].split('\n')[-2].split()[-1].split('/')[2] if len(ping_data['last results']) != 0 and 'min/avg/max' in ping_data['last results'] else '0'][0],
                                    'mac': current_device_data['mac'],
                                    'ip': current_device_data['ip'],
                                    'bssid': current_device_data['ap'],
                                    'channel': current_device_data['channel'],
                                    'mode': current_device_data['mode'],
                                    'name': station,
                                    'os': 'Virtual',
                                    'remarks': [],
                                    'last_result': [ping_data['last results'].split('\n')[-2] if len(
                                        ping_data['last results']) != 0 else ""][0]
                                }
                                if (len(ping_data['last results']) != 0 and 'min/avg/max' in ping_data['last results']):
                                    temp_last_results = ping_data['last results'].split('\n')[
                                                        0: len(ping_data['last results']) - 1]
                                    drop_count = 0  # let dropped = 0 initially
                                    dropped_packets = []
                                    for result in temp_last_results:  # sample result - 64 bytes from 192.168.1.61: icmp_seq=28 time=3.66 ms *** drop: 0 (0, 0.000)  rx: 28  fail: 0  bytes: 1792 min/avg/max: 2.160/3.422/5.190
                                        try:
                                            t_result, t_fail = result.split(
                                                '***')  # fetching the first part of the last result e.g., 64 bytes from 192.168.1.61: icmp_seq=28 time=3.66 ms into t_result and the remaining part into t_fail
                                        except:
                                            continue  # first line of ping result
                                        t_result = t_result.split()
                                        if ('icmp_seq=' not in result and 'time=' not in result):
                                            continue
                                        for t_data in t_result:
                                            if ('icmp_seq=' in t_data):
                                                seq_number = int(t_data.strip('icmp_seq='))
                                            if ('time=' in t_data):
                                                rtt = float(t_data.strip('time='))
                                        rtts[station][seq_number] = rtt
                                        rtts_list.append(rtt)

                                        # finding dropped packets
                                        t_fail = t_fail.split()  # [' drop:', '0', '(0, 0.000)', 'rx:', '28', 'fail:', '0', 'bytes:', '1792', 'min/avg/max:', '2.160/3.422/5.190']
                                        t_drop_val = t_fail[1]  # t_drop_val = '0'
                                        t_drop_val = int(t_drop_val)  # type cast string to int
                                        if (t_drop_val != drop_count):
                                            current_drop_packets = t_drop_val - drop_count
                                            drop_count = t_drop_val
                                            for drop_packet in range(1, current_drop_packets + 1):
                                                dropped_packets.append(seq_number - drop_packet)

                                if (rtts_list == []):
                                    rtts_list = [0]
                                min_rtt = str(min(rtts_list))
                                avg_rtt = str(sum(rtts_list) / len(rtts_list))
                                max_rtt = str(max(rtts_list))
                                ping.result_json[station]['min_rtt'] = min_rtt
                                ping.result_json[station]['avg_rtt'] = avg_rtt
                                ping.result_json[station]['max_rtt'] = max_rtt
                                if (list(rtts[station].keys()) != []):
                                    required_sequence_numbers = list(range(1, max(rtts[station].keys())))
                                    for seq in required_sequence_numbers:
                                        if (seq not in rtts[station].keys()):
                                            if (seq in dropped_packets):
                                                rtts[station][seq] = 0
                                            else:
                                                rtts[station][seq] = 0.11
                                else:
                                    ping.result_json[station]['rtts'] = {}
                                ping.result_json[station]['rtts'] = rtts[station]
                                ping.result_json[station]['remarks'] = ping.generate_remarks(ping.result_json[station])
                                # ping.result_json[station]['dropped_packets'] = dropped_packets

        if (args.real):
            if (type(result_data) == dict):
                for station in ping.real_sta_list:
                    current_device_data = Devices.devices_data[station]
                    # logging.info(current_device_data)
                    if (station in result_data['name']):
                        # logging.info(result_data['last results'].split('\n'))
                        ping.result_json[station] = {
                            'command': result_data['command'],
                            'sent': result_data['tx pkts'],
                            'recv': result_data['rx pkts'],
                            'dropped': result_data['dropped'],
                            # 'min_rtt': [result_data['last results'].split('\n')[-2].split()[-1].split(':')[-1].split('/')[0] if len(result_data['last results']) != 0 and 'min/avg/max' in result_data['last results'] else '0'][0],
                            # 'avg_rtt': [result_data['last results'].split('\n')[-2].split()[-1].split(':')[-1].split('/')[1] if len(result_data['last results']) != 0 and 'min/avg/max' in result_data['last results'] else '0'][0],
                            # 'max_rtt': [result_data['last results'].split('\n')[-2].split()[-1].split(':')[-1].split('/')[2] if len(result_data['last results']) != 0 and 'min/avg/max' in result_data['last results'] else '0'][0],
                            'mac': current_device_data['mac'],
                            'ip': current_device_data['ip'],
                            'bssid': current_device_data['ap'],
                            'channel': current_device_data['channel'],
                            'mode': current_device_data['mode'],
                            'name': [current_device_data['user'] if current_device_data['user'] != '' else
                                     current_device_data['hostname']][0],
                            'os': ['Windows' if 'Win' in current_device_data['hw version'] else 'Linux' if 'Linux' in
                                                                                                           current_device_data[
                                                                                                               'hw version'] else 'Mac' if 'Apple' in
                                                                                                                                           current_device_data[
                                                                                                                                               'hw version'] else 'Android'][
                                0],
                            'remarks': [],
                            'last_result': [result_data['last results'].split('\n')[-2] if len(
                                result_data['last results']) != 0 else ""][0]
                        }
                        if (len(result_data['last results']) != 0):
                            temp_last_results = result_data['last results'].split('\n')[
                                                0: len(result_data['last results']) - 1]
                            drop_count = 0  # let dropped = 0 initially
                            dropped_packets = []
                            for result in temp_last_results:  # sample result - 64 bytes from 192.168.1.61: icmp_seq=28 time=3.66 ms *** drop: 0 (0, 0.000)  rx: 28  fail: 0  bytes: 1792 min/avg/max: 2.160/3.422/5.190
                                try:
                                    t_result, t_fail = result.split(
                                        '***')  # fetching the first part of the last result e.g., 64 bytes from 192.168.1.61: icmp_seq=28 time=3.66 ms into t_result and the remaining part into t_fail
                                except:
                                    continue
                                t_result = t_result.split()
                                if ('icmp_seq=' not in result and 'time=' not in result):
                                    continue
                                for t_data in t_result:
                                    if ('icmp_seq=' in t_data):
                                        seq_number = int(t_data.strip('icmp_seq='))
                                    if ('time=' in t_data):
                                        rtt = float(t_data.strip('time='))
                                rtts[station][seq_number] = rtt
                                rtts_list.append(rtt)

                                # finding dropped packets
                                t_fail = t_fail.split()  # [' drop:', '0', '(0, 0.000)', 'rx:', '28', 'fail:', '0', 'bytes:', '1792', 'min/avg/max:', '2.160/3.422/5.190']
                                t_drop_val = t_fail[1]  # t_drop_val = '0'
                                t_drop_val = int(t_drop_val)  # type cast string to int
                                if (t_drop_val != drop_count):
                                    current_drop_packets = t_drop_val - drop_count
                                    drop_count = t_drop_val
                                    for drop_packet in range(1, current_drop_packets + 1):
                                        dropped_packets.append(seq_number - drop_packet)

                        if (rtts_list == []):
                            rtts_list = [0]
                        min_rtt = str(min(rtts_list))
                        avg_rtt = str(sum(rtts_list) / len(rtts_list))
                        max_rtt = str(max(rtts_list))
                        ping.result_json[station]['min_rtt'] = min_rtt
                        ping.result_json[station]['avg_rtt'] = avg_rtt
                        ping.result_json[station]['max_rtt'] = max_rtt
                        if (ping.result_json[station]['os'] == 'Android' and type(rtts) is dict and rtts != {}):
                            if (list(rtts[station].keys()) == []):
                                ping.result_json[station]['sent'] = str(0)
                                ping.result_json[station]['recv'] = str(0)
                                ping.result_json[station]['dropped'] = str(0)
                            else:
                                ping.result_json[station]['sent'] = str(max(list(rtts[station].keys())))
                                ping.result_json[station]['recv'] = str(len(rtts[station].keys()))
                                ping.result_json[station]['dropped'] = str(
                                    int(ping.result_json[station]['sent']) - int(ping.result_json[station]['recv']))
                        if (len(rtts[station].keys()) != 0):
                            required_sequence_numbers = list(range(1, max(rtts[station].keys())))
                            for seq in required_sequence_numbers:
                                if (seq not in rtts[station].keys()):
                                    if (seq in dropped_packets):
                                        rtts[station][seq] = 0
                                    else:
                                        rtts[station][seq] = 0.11
                                # print(station, rtts[station])
                        ping.result_json[station]['rtts'] = rtts[station]
                        ping.result_json[station]['remarks'] = ping.generate_remarks(ping.result_json[station])
                        # ping.result_json[station]['dropped_packets'] = dropped_packets
            else:
                for station in ping.real_sta_list:
                    current_device_data = Devices.devices_data[station]
                    # print('<<<<<<<<<<<<<<<<<<<', current_device_data)
                    for ping_device in result_data:
                        ping_endp, ping_data = list(ping_device.keys())[
                            0], list(ping_device.values())[0]
                        if (station in ping_endp):
                            ping.result_json[station] = {
                                'command': ping_data['command'],
                                'sent': ping_data['tx pkts'],
                                'recv': ping_data['rx pkts'],
                                'dropped': ping_data['dropped'],
                                # 'min_rtt': [ping_data['last results'].split('\n')[-2].split()[-1].split(':')[-1].split('/')[0] if len(ping_data['last results']) != 0 and 'min/avg/max' in ping_data['last results'] else '0'][0],
                                # 'avg_rtt': [ping_data['last results'].split('\n')[-2].split()[-1].split(':')[-1].split('/')[1] if len(ping_data['last results']) != 0 and 'min/avg/max' in ping_data['last results'] else '0'][0],
                                # 'max_rtt': [ping_data['last results'].split('\n')[-2].split()[-1].split(':')[-1].split('/')[2] if len(ping_data['last results']) != 0 and 'min/avg/max' in ping_data['last results'] else '0'][0],
                                'mac': current_device_data['mac'],
                                'ip': current_device_data['ip'],
                                'bssid': current_device_data['ap'],
                                'channel': current_device_data['channel'],
                                'mode': current_device_data['mode'],
                                'name': [current_device_data['user'] if current_device_data['user'] != '' else
                                         current_device_data['hostname']][0],
                                'os': [
                                    'Windows' if 'Win' in current_device_data['hw version'] else 'Linux' if 'Linux' in
                                                                                                            current_device_data[
                                                                                                                'hw version'] else 'Mac' if 'Apple' in
                                                                                                                                            current_device_data[
                                                                                                                                                'hw version'] else 'Android'][
                                    0],
                                'remarks': [],
                                'last_result': [ping_data['last results'].split('\n')[-2] if len(
                                    ping_data['last results']) != 0 else ""][0]
                            }
                            if (len(ping_data['last results']) != 0):
                                temp_last_results = ping_data['last results'].split('\n')[
                                                    0: len(ping_data['last results']) - 1]
                                drop_count = 0  # let dropped = 0 initially
                                dropped_packets = []
                                for result in temp_last_results:
                                    if (
                                            'time=' in result):  # sample result - 64 bytes from 192.168.1.61: icmp_seq=28 time=3.66 ms *** drop: 0 (0, 0.000)  rx: 28  fail: 0  bytes: 1792 min/avg/max: 2.160/3.422/5.190
                                        try:
                                            t_result, t_fail = result.split(
                                                '***')  # fetching the first part of the last result e.g., 64 bytes from 192.168.1.61: icmp_seq=28 time=3.66 ms into t_result and the remaining part into t_fail
                                        except:
                                            continue
                                        t_result = t_result.split()
                                        if ('icmp_seq=' not in result and 'time=' not in result):
                                            continue
                                        for t_data in t_result:
                                            if ('icmp_seq=' in t_data):
                                                seq_number = int(t_data.strip('icmp_seq='))
                                            if ('time=' in t_data):
                                                rtt = float(t_data.strip('time='))
                                        rtts[station][seq_number] = rtt
                                        rtts_list.append(rtt)

                                        # finding dropped packets
                                        t_fail = t_fail.split()  # [' drop:', '0', '(0, 0.000)', 'rx:', '28', 'fail:', '0', 'bytes:', '1792', 'min/avg/max:', '2.160/3.422/5.190']
                                        t_drop_val = t_fail[1]  # t_drop_val = '0'
                                        t_drop_val = int(t_drop_val)  # type cast string to int
                                        if (t_drop_val != drop_count):
                                            current_drop_packets = t_drop_val - drop_count
                                            drop_count = t_drop_val
                                            for drop_packet in range(1, current_drop_packets + 1):
                                                dropped_packets.append(seq_number - drop_packet)

                            if (rtts_list == []):
                                rtts_list = [0]
                            min_rtt = str(min(rtts_list))
                            avg_rtt = str(sum(rtts_list) / len(rtts_list))
                            max_rtt = str(max(rtts_list))
                            ping.result_json[station]['min_rtt'] = min_rtt
                            ping.result_json[station]['avg_rtt'] = avg_rtt
                            ping.result_json[station]['max_rtt'] = max_rtt
                            if (ping.result_json[station]['os'] == 'Android' and type(rtts) is dict and rtts != {}):
                                if (list(rtts[station].keys()) == []):
                                    ping.result_json[station]['sent'] = str(0)
                                    ping.result_json[station]['recv'] = str(0)
                                    ping.result_json[station]['dropped'] = str(0)
                                else:
                                    ping.result_json[station]['sent'] = str(max(list(rtts[station].keys())))
                                    ping.result_json[station]['recv'] = str(len(rtts[station].keys()))
                                    ping.result_json[station]['dropped'] = str(
                                        int(ping.result_json[station]['sent']) - int(ping.result_json[station]['recv']))
                            if (len(rtts[station].keys()) != 0):
                                required_sequence_numbers = list(range(1, max(rtts[station].keys())))
                                for seq in required_sequence_numbers:
                                    if (seq not in rtts[station].keys()):
                                        if (seq in dropped_packets):
                                            rtts[station][seq] = 0
                                        else:
                                            rtts[station][seq] = 0.11
                                    # print(station, rtts[station])
                            ping.result_json[station]['rtts'] = rtts[station]
                            ping.result_json[station]['remarks'] = ping.generate_remarks(ping.result_json[station])
                            # ping.result_json[station]['dropped_packets'] = dropped_packets

        if (ping.do_webUI):
            if (not ping.store_csv()):
                logging.info('Aborted test from webUI')
                break

        time.sleep(1)

        t_end = datetime.now()

        loop_timer += abs(t_init - t_end).total_seconds()
    # time.sleep(duration * 60)

    logging.info('Stopping the test')
    ping.stop_generic()

    # ping.clean_generic_cx()

    if (ping.do_webUI):
        ping.set_webUI_stop()

    if (not args.no_cleanup):
        ping.clean_generic_cx()

    ping.generate_report()


if __name__ == "__main__":
    main()
