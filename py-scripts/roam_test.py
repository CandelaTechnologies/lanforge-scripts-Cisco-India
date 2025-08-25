#!/usr/bin/env python3

from lf_report import lf_report
from lf_graph import lf_bar_graph_horizontal
from lf_graph import lf_bar_graph
import os
import sys
import argparse
import time
import logging
from datetime import datetime
import importlib
import shutil
import pandas as pd
import pyshark
import subprocess
import threading
import csv

# from itertools import combinations # to generate pair combinations for attenuators

logger = logging.getLogger(__name__)
if sys.version_info[0] != 3:
    logger.critical("This script requires Python 3")
    exit(1)

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))
realm = importlib.import_module("py-json.realm")
LFUtils = importlib.import_module("py-json.LANforge.LFUtils")
sta_connect = importlib.import_module("py-scripts.sta_connect2")
Realm = realm.Realm
lf_cleanup = importlib.import_module("py-scripts.lf_cleanup")

lf_logger_config = importlib.import_module("py-scripts.lf_logger_config")


class Roam(Realm):
    def __init__(self,
                 lanforge_ip='localhost',
                 port=8080,
                 sniff_radio='1.1.wiphy0',
                 station_radio='1.1.wiphy0',
                 band='5G',
                 attenuators=[],
                 step=100,
                 max_attenuation=950,
                 upstream='1.1.eth1',
                 ssid=None,
                 security=None,
                 password=None,
                 num_sta=None,
                 station_flag=None,
                 option=None,
                 identity=None,
                 eap_method=None,
                 key_management=None,
                 ca_cert=None,
                 private_key=None,
                 pk_passwd=None,
                 pair_cipher=None,
                 group_cipher=None,
                 ttls_pass=None,
                 sta_type=None,
                 iteration_based=True,
                 duration=None,
                 wait_time=30,
                 sniff_duration=300,
                 channel='AUTO',
                 frequency=-1,
                 iterations=None,
                 roam_timeout=50,
                 bg_scan='simple:10:-65:300:4',
                 disable_restart_dhcp=False,
                 softroam=True,
                 real_devices=True
                 ):
        super().__init__(lanforge_ip, port)

        self.lanforge_ip = lanforge_ip
        self.port = port
        self.upstream = upstream
        self.tshark_process = None

        self.attenuators = attenuators
        self.step = step
        self.max_attenuation = max_attenuation

        self.ssid = ssid
        self.security = security
        self.password = password
        self.num_sta = num_sta
        self.station_flag = station_flag
        self.option = option
        self.identity = identity
        # new
        self.eap_method = eap_method
        self.key_management = key_management
        self.ca_cert = ca_cert
        self.private_key = private_key
        self.pk_passwd = pk_passwd
        self.pair_cipher = pair_cipher
        self.group_cipher = group_cipher
        self.ttls_pass = ttls_pass
        self.sta_type = sta_type
        # new_end
        self.iteration_based = iteration_based
        self.duration = duration
        self.wait_time = wait_time
        self.channel = channel
        self.frequency = frequency
        self.iterations = iterations
        self.soft_roam = softroam

        self.real_devices = real_devices
        self.sniff_radio = sniff_radio
        self.sniff_duration = sniff_duration
        self.station_radio = station_radio
        self.band = band
        self.bg_scan = bg_scan
        self.disable_restart_dhcp = disable_restart_dhcp

        # reporting variable
        self.roam_data = {}
        self.bssid_based_totals = {}
        self.roam_bssid_info = {}
        self.station_based_roam_count = {}
        self.sta_roam_count = {}
        self.final_data = {}
        self.sta_mac = {}
        output = []
        self.atten_serial_ = []
        self.roam_timeout = roam_timeout

        # if (len(self.attenuators) == 1):
        #     logging.error('Cannot perform roaming with only one attenuator. Please provide atleast two attenuators.')
        #     exit(1)
        self.attenuator_combinations = []
        print("attenuators:- ", self.attenuators)  # ['1.1.3000', '1.1.3002']
        for item in self.attenuators:
            # Remove the curly braces and split the string
            item = item.strip("{}")
            key_value_pairs = item.split(":")

            # Extract the key and clean it
            key = key_value_pairs[0].strip("'")
            key_parts = list(map(int, key.split('.')))
            self.atten_serial_.append(key)  # Add the original key to the list of keys

            # Extract the values (tuples inside set) and clean them
            values = key_value_pairs[1].strip("{}").split("),")

            # Process each tuple and create the final output
            for value in values:
                value = value.strip("()").split(',')
                output.append(key_parts + list(map(int, value)))
        print("output:- ", output)
        print("atten_serial:- ", self.atten_serial_)
        attenuators = output + [output[0]]
        for atten_index in range(len(attenuators) - 1):
            self.attenuator_combinations.append((attenuators[atten_index], attenuators[atten_index + 1]))
            print("attenuator_combinations:- ", self.attenuator_combinations)  # [('1.1.3000', '1.1.3002'), ('1.1.3002', '1.1.3000')]
        logging.info('Test will be performed on the APs with the following attenuator combinations {}'.format(
            self.attenuator_combinations))  # [('1.1.3000', '1.1.3002'), ('1.1.3002', '1.1.3000')]

        all_attenuators = self.attenuator_list()
        print("all_attenuators", all_attenuators)  # ALl atten
        if (all_attenuators is None or all_attenuators == []):
            logging.error(
                'There are no attenuators in the given LANforge {}. Exiting the test.'.format(self.lanforge_ip))
            exit(1)
        else:
            for atten_serial in all_attenuators:
                atten_serial_name, atten_values = list(atten_serial.keys())[0], list(atten_serial.values())[0]
                if (atten_serial_name not in self.atten_serial_):
                    if (atten_values['state'] != 'Phantom'):
                        logging.info(
                            'Attenuator {} is not in the test attenuators list. Setting the attenuation value to max.'.format(
                                atten_serial_name))
                        self.set_atten(atten_serial_name, 950)
        print("Initial Active and passive atten set")
        self.set_attenuators(output[0], output[1])

        self.sniff_radio_resource, self.sniff_radio_shelf, self.sniff_radio_port, _ = self.name_to_eid(
            self.sniff_radio)

        self.monitor = self.new_wifi_monitor_profile(
            resource_=self.sniff_radio_resource, up_=False)
        self.create_monitor()

        self.staConnect = sta_connect.StaConnect2(host=self.lanforge_ip, port=self.port,
                                                  outfile="sta_connect2.csv")

        self.cx_profile = self.new_l3_cx_profile()
        self.cx_profile.host = self.lanforge_ip
        self.cx_profile.port = self.port
        self.cx_profile.name_prefix = 'ROAM-'
        self.cx_profile.side_a_min_bps = '1000000'
        self.cx_profile.side_a_max_bps = '1000000'
        self.cx_profile.side_b_min_bps = '1000000'
        self.cx_profile.side_b_max_bps = '1000000'

        self.attenuator_increments = list(
            range(0, self.max_attenuation + 1, self.step))
        if (self.max_attenuation not in self.attenuator_increments):
            self.attenuator_increments.append(self.max_attenuation)

        self.attenuator_decrements = list(
            range(self.max_attenuation, -1, -self.step))
        if (0 not in self.attenuator_decrements):
            self.attenuator_decrements.append(0)

        print("attenuator_increments", self.attenuator_increments)
        print("attenuator_decrements", self.attenuator_decrements)

    def create_cx(self):
        self.cx_profile.create(endp_type='lf_udp',
                               side_a=self.station_list,
                               side_b=self.upstream)

    def start_cx(self):
        self.cx_profile.start_cx()

    def stop_cx(self):
        for cx_name in self.cx_profile.created_cx.keys():
            print(cx_name)
            self.stop_cx(cx_name)

    def set_atten_idx(self, eid, atten_ddb, atten_idx='all'):

        eid_toks = self.name_to_eid(eid, non_port=True)
        req_url = "cli-json/set_attenuator"
        data = {
            "shelf": eid_toks[0],
            "resource": eid_toks[1],
            "serno": eid_toks[2],
            "atten_idx": atten_idx,
            "val": atten_ddb,
        }
        # print("JJJJJJJ", data)
        self.json_post(req_url, data)

    def attenuator_list(self):
        response = self.json_get("/atten/list")
        print("atten list", response)
        data = []
        if 'attenuators' in response:
            data = response["attenuators"]
        elif 'attenuator' in response:
            dict_ = {}
            dict_[response['attenuator']["name"]] = response['attenuator']
            data.append(dict_)
        return data

    def set_attenuators(self, atten1, atten2):
        logging.info('Setting attenuation to {} for attenuator {}'.format(
            0, atten1))
        for idx in atten1[3:]:
            print("idx active", idx)
            print("active_attenuator", atten1[2])
            self.set_atten_idx(
                f"{atten1[0]}.{atten1[1]}.{atten1[2]}", 0,
                idx - 1)

        logging.info(
            'Setting active attenuator as {}'.format(atten1[2]))
        self.active_attenuator = atten1

        logging.info(
            'Setting passive attenuator as {}'.format(atten2[2]))
        self.passive_attenuator = atten2

        logging.info('Setting attenuation to {} for attenuator {}'.format(
            self.max_attenuation, atten2[2]))
        for idx in atten2[3:]:
            print("idx active", idx)
            print("passive_attenuator", atten1[2])
            self.set_atten_idx(
                f"{atten2[0]}.{atten2[1]}.{atten2[2]}", self.max_attenuation,
                idx - 1)

        # for atten in self.atten_serial_:
        #     if (atten not in [atten1, atten2]):
        #         logging.info('Setting unused attenuator {} value to maximum attenuation.'.format(atten))
        #         self.set_atten_idx(atten, self.max_attenuation)

    def get_port_data(self, station, field):
        shelf, resource, port = station.split('.')
        # data1 = self.json_get(f"/port/{shelf}/{resource}/{port}")
        # print("data1:- ", data1)
        data = self.json_get(
            '/port/{}/{}/{}?fields={}'.format(shelf, resource, port, field))
        if (data is not None and 'interface' in data.keys() and data['interface'] is not None):
            return data['interface'][field]
        else:
            logging.warning(
                'Station {} not found. Removing it from test.'.format(station))
            return None

    def cleanup(self):
        # self.cx_profile.cleanup()
        # self.cx_profile.cleanup_prefix()
        # self.cx_profile.cleanup()
        # self.cx_profile.cleanup_prefix()
        lf_clean_obj = lf_cleanup.lf_clean(host=self.lanforge_ip)
        lf_clean_obj.resource = 'all'
        lf_clean_obj.sta_clean()

    # def cleanup(self):
    #     # self.cleanup.sta_clean()
    #     lf_cleanup.sta_clean(host=self.lanforge_ip, port=self.port, resource='all')
    # self.monitor.cleanup(desired_ports=['moni0'])

    def create_monitor(self):
        self.cleanup()
        self.monitor.create(resource_=self.sniff_radio_resource,
                            radio_=self.sniff_radio_port, channel=self.channel, frequency=self.frequency,
                            name_='moni0')

    def start_sniff(self, capname='roam_test.pcap'):
        self.monitor.admin_up()
        c = f"tshark -i moni0 -w /home/lanforge/roam_test.pcap"
        try:
            print("RUNNING TSHARK")
            self.tshark_process = subprocess.Popen(c, shell=True)
        except Exception as e:
            print(e, "In start_sniff Exception")
        # self.monitor.start_sniff(capname=capname, duration_sec=self.sniff_duration, flags=0x1)

    def stop_sniff(self):
        try:
            self.tshark_process.terminate()
        except Exception as e:
            print(e, "In stop_sniff Exception")
        try:
            return_code = self.tshark_process.returncode
            print("RETURN CODE", return_code)

        except BaseException as err:
            print(err, "ERRORR")

        self.monitor.admin_down()

    def get_bssids(self):
        bssids = []
        removable_stations = []
        print('---------------------', self.station_list)
        for station in self.get_station_list():
            bssid = self.get_port_data(station, 'ap')
            print("BSSID:- ", bssid)
            if bssid == 'NA':
                print("BSSID NA")
                time.sleep(10)
                bssid = self.get_port_data(station, 'ap')
            if (bssid is not None):
                bssids.append(bssid)
            else:
                removable_stations.append(station)
        for station in removable_stations:
            self.station_list.remove(station)
        return bssids

    def get_sta_bssids(self):
        sta_bssids = {}
        for station in self.get_station_list():
            bssid = self.get_port_data(station, 'ap')
            if bssid == 'NA':
                time.sleep(3)
                bssid = self.get_port_data(station, 'ap')
            if (bssid is not None):
                sta_bssids[f'{station}'] = bssid
        return sta_bssids

    def get_signal_strength(self, station):
        signal = self.get_port_data(station, 'signal')
        if signal == 'NA':
            time.sleep(3)
            signal = self.get_port_data(station, 'signal')
        if (signal is not None):
            return int(signal.split(' ')[0])

    def monitor_sta_scan(self):
        for station_name in self.station_list:
            station = (station_name.split(".")[2])
            cmd_exec = False
            row_cnt = 0
            sta_bssids = self.get_sta_bssids()
            before_bssid = sta_bssids[f'{station_name}']
            target_strength = int(self.bg_scan.split(':')[2])
            while True:
                signal_strength = self.get_signal_strength(station=station_name)
                if signal_strength is not None:
                    if signal_strength <= target_strength:
                        result = subprocess.check_output(f"wpa_cli -i {station} scan_results", shell=True, text=True)
                        # Save to a file named after the station
                        with open(f"wpa_sta_scan_{station}.txt", "a") as file:
                            file.write(
                                f"_________________________________________________________________________________________________{station} with signal strength {signal_strength}\n")
                            file.write(result)
                            row_cnt += 1
                        time.sleep(2)
                        # print(f"Saved scan results for {station}")
                        cmd_exec = True
                    elif (cmd_exec and signal_strength > target_strength):
                        while signal_strength > target_strength and signal_strength == 0:
                            continue
                        sta_bssids = self.get_sta_bssids()
                        after_bssid = sta_bssids[f'{station_name}']
                        result = subprocess.check_output(f"wpa_cli -i {station} scan_results", shell=True, text=True)
                        # Save to a file named after the station
                        with open(f"wpa_sta_scan_{station}.txt", "a") as file:
                            file.write(
                                f"_______________________________________________________________________________________{before_bssid} ------> {after_bssid}______________________{station} with signal strength {signal_strength}\n")
                            file.write(result)
                            row_cnt += 1
                        print(f"Signal strength for {station} is {signal_strength} dBm. Skipping scan...")
                        print(f"Number of Rows appended for wpa_sta_scan_{station} is {row_cnt}.")
                        break
                else:
                    print(f"Could not retrieve signal strength for {station}.")

    # get existing stations list
    def get_station_list(self):
        sta = self.staConnect.station_list()
        if sta == "no response":
            return "no response"
        sta_list = []
        for i in sta:
            for j in i:
                sta_list.append(j)
        return sta_list

    def create_clients(self, start_id=0, sta_prefix='sta'):
        station_profile = self.new_station_profile()

        if self.station_flag is not None:
            _flags = self.station_flag.split(',')
            for flags in _flags:
                logger.info(f"Selected Flags: '{flags}'")
                station_profile.set_command_flag("add_sta", flags, 1)

        radio = self.station_radio
        sta_list = self.get_station_list()
        print("Available list of stations on lanforge-GUI :", sta_list)
        logging.info(str(sta_list))
        if not sta_list:
            print("No stations are available on lanforge-GUI")
            logging.info("No stations are available on lanforge-GUI")
        else:
            station_profile.cleanup(sta_list, delay=1)
            self.wait_until_ports_disappear(sta_list=sta_list,
                                            debug_=True)
        print("Creating stations.")
        logging.info("Creating stations.")
        station_list = LFUtils.portNameSeries(prefix_=sta_prefix, start_id_=start_id,
                                              end_id_=self.num_sta - 1, padding_number_=10000,
                                              radio=radio)
        if self.sta_type == "normal":
            station_profile.set_command_flag("add_sta", "power_save_enable", 1)
            if not self.soft_roam:
                station_profile.set_command_flag("add_sta", "disable_roam", 1)
            if self.soft_roam:
                print("Soft roam true")
                logging.info("Soft roam true")
                if self.option == "otds":
                    print("OTDS present")
                    station_profile.set_command_flag(
                        "add_sta", "ft-roam-over-ds", 1)

        if self.sta_type == "11r-sae-802.1x":
            dut_passwd = "[BLANK]"
        print("Security:- ", self.password)
        station_profile.use_security(self.security, self.ssid, self.password)
        station_profile.set_number_template("00")

        station_profile.set_command_flag("add_sta", "create_admin_down", 1)

        station_profile.set_command_param("set_port", "report_timer", 1500)

        station_profile.set_command_flag("set_port", "rpt_timer", 1)

        if self.disable_restart_dhcp:
            station_profile.set_command_flag("set_port", "no_dhcp_restart", 1)
            station_profile.set_command_flag("set_port", "no_ifup_post", 1)
            station_profile.set_command_flag("set_port", "use_dhcp", 1)
            station_profile.set_command_flag("set_port", "current_flags", 1)
            station_profile.set_command_flag("set_port", "dhcp", 1)
            station_profile.set_command_flag("set_port", "dhcp_rls", 1)
            station_profile.set_command_flag("set_port", "no_dhcp_conn", 1)
            station_profile.set_command_flag("set_port", "skip_ifup_roam", 1)
        if self.sta_type == "11r":
            station_profile.set_command_flag("add_sta", "80211u_enable", 0)
            station_profile.set_command_flag("add_sta", "8021x_radius", 1)
            if not self.soft_roam:
                station_profile.set_command_flag("add_sta", "disable_roam", 1)
            if self.soft_roam:
                print("Soft roam true")
                logging.info("Soft roam true")
                if self.option == "otds":
                    print("OTDS present")
                    station_profile.set_command_flag(
                        "add_sta", "ft-roam-over-ds", 1)
            station_profile.set_command_flag("add_sta", "power_save_enable", 1)
            station_profile.set_wifi_extra(key_mgmt="FT-PSK     ",
                                           pairwise="",
                                           group="",
                                           psk="",
                                           eap="",
                                           identity="",
                                           passwd="",
                                           pin="",
                                           phase1="NA",
                                           phase2="NA",
                                           pac_file="NA",
                                           private_key="NA",
                                           pk_password="NA",
                                           hessid="00:00:00:00:00:01",
                                           realm="localhost.localdomain",
                                           client_cert="NA",
                                           imsi="NA",
                                           milenage="NA",
                                           domain="localhost.localdomain",
                                           roaming_consortium="NA",
                                           venue_group="NA",
                                           network_type="NA",
                                           ipaddr_type_avail="NA",
                                           network_auth_type="NA",
                                           anqp_3gpp_cell_net="NA")
        if self.sta_type == "11r-sae":
            station_profile.set_command_flag("add_sta", "ieee80211w", 2)
            station_profile.set_command_flag("add_sta", "80211u_enable", 0)
            station_profile.set_command_flag("add_sta", "8021x_radius", 1)
            if not self.soft_roam:
                station_profile.set_command_flag("add_sta", "disable_roam", 1)
            if self.soft_roam:
                if self.option == "otds":
                    station_profile.set_command_flag(
                        "add_sta", "ft-roam-over-ds", 1)
            station_profile.set_command_flag("add_sta", "power_save_enable", 1)
            station_profile.set_wifi_extra(key_mgmt="FT-SAE     ",
                                           pairwise="",
                                           group="",
                                           psk="",
                                           eap="",
                                           identity="",
                                           passwd="",
                                           pin="",
                                           phase1="NA",
                                           phase2="NA",
                                           pac_file="NA",
                                           private_key="NA",
                                           pk_password="NA",
                                           hessid="00:00:00:00:00:01",
                                           realm="localhost.localdomain",
                                           client_cert="NA",
                                           imsi="NA",
                                           milenage="NA",
                                           domain="localhost.localdomain",
                                           roaming_consortium="NA",
                                           venue_group="NA",
                                           network_type="NA",
                                           ipaddr_type_avail="NA",
                                           network_auth_type="NA",
                                           anqp_3gpp_cell_net="NA")
        if self.sta_type == "11r-sae-802.1x":
            station_profile.set_command_flag("set_port", "rpt_timer", 1)
            station_profile.set_command_flag("add_sta", "ieee80211w", 2)
            station_profile.set_command_flag("add_sta", "80211u_enable", 0)
            station_profile.set_command_flag("add_sta", "8021x_radius", 1)
            if not self.soft_roam:
                station_profile.set_command_flag("add_sta", "disable_roam", 1)
            if self.soft_roam:
                if self.option == "otds":
                    station_profile.set_command_flag(
                        "add_sta", "ft-roam-over-ds", 1)
            station_profile.set_command_flag("add_sta", "power_save_enable", 1)
            station_profile.set_wifi_extra(key_mgmt="FT-EAP     ",
                                           pairwise="[BLANK]",
                                           group="[BLANK]",
                                           psk="[BLANK]",
                                           eap="TTLS",
                                           identity=self.identity,
                                           passwd=self.ttls_pass,
                                           pin="",
                                           phase1="NA",
                                           phase2="NA",
                                           pac_file="NA",
                                           private_key="NA",
                                           pk_password="NA",
                                           hessid="00:00:00:00:00:01",
                                           realm="localhost.localdomain",
                                           client_cert="NA",
                                           imsi="NA",
                                           milenage="NA",
                                           domain="localhost.localdomain",
                                           roaming_consortium="NA",
                                           venue_group="NA",
                                           network_type="NA",
                                           ipaddr_type_avail="NA",
                                           network_auth_type="NA",
                                           anqp_3gpp_cell_net="NA")
        if self.sta_type == "11r-wpa2-802.1x":
            station_profile.set_command_flag("set_port", "rpt_timer", 1)
            station_profile.set_command_flag("add_sta", "ieee80211w", 1)
            station_profile.set_command_flag("add_sta", "80211u_enable", 0)
            station_profile.set_command_flag("add_sta", "8021x_radius", 1)
            if not self.soft_roam:
                station_profile.set_command_flag("add_sta", "disable_roam", 1)
            if self.soft_roam:
                if self.option == "otds":
                    station_profile.set_command_flag(
                        "add_sta", "ft-roam-over-ds", 1)
            station_profile.set_command_flag("add_sta", "power_save_enable", 1)
            station_profile.set_wifi_extra(key_mgmt="FT-EAP     ",
                                           pairwise="[BLANK]",
                                           group="[BLANK]",
                                           psk="[BLANK]",
                                           eap="TTLS",
                                           identity=self.identity,
                                           passwd=self.ttls_pass,
                                           pin="",
                                           phase1="NA",
                                           phase2="NA",
                                           pac_file="NA",
                                           private_key="NA",
                                           pk_password="NA",
                                           hessid="00:00:00:00:00:01",
                                           realm="localhost.localdomain",
                                           client_cert="NA",
                                           imsi="NA",
                                           milenage="NA",
                                           domain="localhost.localdomain",
                                           roaming_consortium="NA",
                                           venue_group="NA",
                                           network_type="NA",
                                           ipaddr_type_avail="NA",
                                           network_auth_type="NA",
                                           anqp_3gpp_cell_net="NA")

        if self.sta_type == "11r-sae-ext-key":
            station_profile.set_command_flag("add_sta", "ieee80211w", 2)
            station_profile.set_command_flag("add_sta", "80211u_enable", 0)
            station_profile.set_command_flag("add_sta", "8021x_radius", 1)
            if not self.soft_roam:
                station_profile.set_command_flag("add_sta", "disable_roam", 1)
            if self.soft_roam:
                if self.option == "otds":
                    station_profile.set_command_flag(
                        "add_sta", "ft-roam-over-ds", 1)
            station_profile.set_command_flag("add_sta", "power_save_enable", 1)
            station_profile.set_wifi_extra(key_mgmt="FT-SAE-EXT-KEY     ",
                                           pairwise="GCMP-256",
                                           group="GCMP-256",
                                           psk=self.password,
                                           eap="",
                                           identity="",
                                           passwd="",
                                           pin="",
                                           phase1="NA",
                                           phase2="NA",
                                           pac_file="NA",
                                           private_key="NA",
                                           pk_password="NA",
                                           hessid="00:00:00:00:00:01",
                                           realm="localhost.localdomain",
                                           client_cert="NA",
                                           imsi="NA",
                                           milenage="NA",
                                           domain="localhost.localdomain",
                                           roaming_consortium="NA",
                                           venue_group="NA",
                                           network_type="NA",
                                           ipaddr_type_avail="NA",
                                           network_auth_type="NA",
                                           anqp_3gpp_cell_net="NA")

        # new_added
        if self.sta_type == "custom":
            station_profile.set_command_flag("set_port", "rpt_timer", 1)
            station_profile.set_command_flag("add_sta", "ieee80211w", 1)
            station_profile.set_command_flag("add_sta", "80211u_enable", 0)
            station_profile.set_command_flag("add_sta", "8021x_radius", 1)
            if not self.soft_roam:
                station_profile.set_command_flag("add_sta", "disable_roam", 1)
            if self.soft_roam:
                if self.option == "otds":
                    station_profile.set_command_flag(
                        "add_sta", "ft-roam-over-ds", 1)
            station_profile.set_command_flag("add_sta", "power_save_enable", 1)
            print("IN CUSTOMMMMMMMMMMMMMMMMMM")
            station_profile.set_wifi_extra(key_mgmt=self.key_management,
                                           pairwise=self.pair_cipher,
                                           group=self.group_cipher,
                                           eap=self.eap_method,
                                           identity=self.identity,
                                           passwd=self.ttls_pass,
                                           private_key=self.private_key,
                                           pk_password=self.pk_passwd,
                                           ca_cert=self.ca_cert)

        # #new complete
        station_profile.create(radio=radio, sta_names_=station_list)
        print("Waiting for ports to appear")
        logging.info("Waiting for ports to appear")
        self.wait_until_ports_appear(sta_list=station_list)

        if self.soft_roam:
            for sta_name in station_list:
                sta = sta_name.split(".")[2]  # TODO:  Use name_to_eid
                bgscan = {
                    "shelf": 1,
                    # TODO:  Do not hard-code resource, get it from radio eid I think.
                    "resource": 1,
                    "port": str(sta),
                    "type": 'NA',
                    "text": f'bgscan="{self.bg_scan}"'
                }

                print(bgscan)
                logging.info(str(bgscan))
                self.json_post("/cli-json/set_wifi_custom", bgscan)

        station_profile.admin_up()
        print("Waiting for ports to admin up")
        logging.info("Waiting for ports to admin up")
        if self.wait_for_ip(station_list):
            print("All stations got IPs")
            logging.info("All stations got IPs")
            self.station_list = station_list
            # exit()
            return True
        else:
            print("Stations failed to get IPs")
            logging.info("Stations failed to get IPs")
            return False

    def soft_roam_test(self):
        print("attenuator_combinations",
              self.attenuator_combinations)  # [('1.1.3000', '1.1.3002'), ('1.1.3002', '1.1.3000')]
        for atten_set in self.attenuator_combinations:
            self.roam_data[tuple(map(tuple, atten_set))] = {}
        for station in self.station_list:
            self.station_based_roam_count[station] = 0
            self.sta_roam_count[station] = 0
        for current_iteration in range(1, self.iterations + 1):
            logging.info(
                'Initiating iteration {}'.format(current_iteration))
            for atten_set in self.attenuator_combinations:
                print("atten_set in attenuator_combinations", tuple(map(tuple, atten_set)))  # ('1.1.3000', '1.1.3002')
                current_iteration_roam_data = {}
                self.roam_data[tuple(map(tuple, atten_set))][current_iteration] = current_iteration_roam_data

                # for displaying purpose
                print('========================================================================')
                print('Roaming test started on the attenuator combination {} - {}'.format(atten_set[0], atten_set[1]))
                print('========================================================================')

                atten1, atten2 = atten_set
                print("atten1, atten2", atten1, atten2)  # 1.1.3000 1.1.3002
                self.set_attenuators(atten1=atten1, atten2=atten2)

                if (self.iteration_based):
                    logging.info(
                        'Performing Roaming Test for {} iterations.'.format(self.iterations))

                    before_iteration_bssid_data = self.get_bssids()

                    for attenuator_change_index in range(len(self.attenuator_increments)):
                        for idx in self.active_attenuator[3:]:
                            print("idx active", idx)
                            print("active_attenuator", self.active_attenuator[2])
                            logging.info('Setting the attenuation to {} for attenuator {}'.format(
                                self.attenuator_increments[attenuator_change_index], self.active_attenuator))
                            self.set_atten_idx(
                                str(self.active_attenuator[2]), self.attenuator_increments[attenuator_change_index],
                                idx - 1)
                        for idx in self.passive_attenuator[3:]:
                            print("idx passive", idx)
                            print("passive_attenuator", self.passive_attenuator[2])
                            logging.info('Setting the attenuation to {} for attenuator {}'.format(
                                self.attenuator_decrements[attenuator_change_index], self.passive_attenuator))
                            self.set_atten_idx(
                                str(self.passive_attenuator[2]), self.attenuator_decrements[attenuator_change_index],
                                idx - 1)

                        logging.info(
                            'Waiting for {} seconds before monitoring the stations'.format(self.wait_time))
                        time.sleep(self.wait_time)

                        monitoring_thread = threading.Thread(target=self.monitor_sta_scan, daemon=True)
                        monitoring_thread.start()
                        print("Monitoring started in a separate thread.")

                        logging.info('Monitoring the stations')
                        current_step_bssid_data = self.get_bssids()
                        print("current_step_bssid_data:- ", current_step_bssid_data)

                        for bssid_index in range(len(current_step_bssid_data)):
                            if (self.station_list[bssid_index] not in current_iteration_roam_data.keys()):
                                if (before_iteration_bssid_data[bssid_index] != current_step_bssid_data[bssid_index]):
                                    if self.station_list[bssid_index] in self.sta_roam_count:
                                        self.sta_roam_count[self.station_list[bssid_index]] += 1
                                    else:
                                        self.sta_roam_count[self.station_list[bssid_index]] = 1
                                    current_iteration_roam_data[self.station_list[bssid_index]] = {
                                        'BSSID before iteration': before_iteration_bssid_data[bssid_index],
                                        'BSSID after iteration': current_step_bssid_data[bssid_index],
                                        'Signal Strength': self.get_port_data(self.station_list[bssid_index], 'signal'),
                                        'Status': 'PASS' if before_iteration_bssid_data[bssid_index] !=
                                                            current_step_bssid_data[bssid_index] else 'FAIL'
                                    }
                                    if self.station_list[bssid_index] not in self.roam_bssid_info:
                                        self.roam_bssid_info[self.station_list[bssid_index]] = {
                                            'BSSID_before': [],
                                            'BSSID_after': [],
                                            'Signal': [],
                                            'Status': []

                                        }
                                    self.roam_bssid_info[self.station_list[bssid_index]]['BSSID_before'].append(
                                        before_iteration_bssid_data[bssid_index])
                                    self.roam_bssid_info[self.station_list[bssid_index]]['BSSID_after'].append(
                                        current_step_bssid_data[bssid_index])
                                    self.roam_bssid_info[self.station_list[bssid_index]]['Signal'].append(
                                        current_iteration_roam_data[self.station_list[bssid_index]]['Signal Strength'])
                                    self.roam_bssid_info[self.station_list[bssid_index]]['Status'].append(
                                        current_iteration_roam_data[self.station_list[bssid_index]]['Status'])
                                    print('Before Iteration BSSID-------------',
                                          before_iteration_bssid_data[bssid_index])
                                    # if current_step_bssid_data[bssid_index]=="NA":
                                    #     a=before_iteration_bssid_data[bssid_index]
                                    # print('After Iteration BSSID-------------', a)

                                    print('After Iteration BSSID-------------', current_step_bssid_data[bssid_index])
                                    print('-------------', self.roam_bssid_info)
                                    if (current_step_bssid_data[bssid_index] in self.bssid_based_totals):
                                        self.bssid_based_totals[current_step_bssid_data[bssid_index]] += 1
                                    else:
                                        self.bssid_based_totals[current_step_bssid_data[bssid_index]] = 1

                    print(self.bssid_based_totals)
                    logging.info('Iteration {} complete'.format(current_iteration))
                    logging.info('{}'.format(current_iteration_roam_data))
                    logging.info('{}'.format(self.roam_data))
                    self.roam_data[tuple(map(tuple, atten_set))][current_iteration] = current_iteration_roam_data

                    self.active_attenuator, self.passive_attenuator = self.passive_attenuator, self.active_attenuator
                else:
                    logging.info(
                        'Duration based roaming test is still under development.')
        print(current_iteration_roam_data)
        logging.info('Stopping sniffer')
        self.stop_sniff()
        print("sleeping 10 seconds for a check")
        time.sleep(10)
        print("Sleep for 10 seconds completed..")
        logging.info(self.roam_data)

    def get_mac(self):
        mac_list = []
        response = super().json_get('/port/list?fields=_links,alias,mac,port+type')
        for sta in self.station_list:
            for x in range(len(response['interfaces'])):
                for k, v in response['interfaces'][x].items():
                    if v['alias'] == sta.split('.')[2]:
                        mac_list.append(v['mac'])
                        self.sta_mac[sta] = v['mac']
        del response
        return mac_list

    def calculate_roam_time(self, pcap_file, mac_list):
        print('pcap_dest', pcap_file)
        print('Mac_addr', mac_list)
        for mac in mac_list:
            if (mac == ''):
                continue
            display_filter = f'(((wlan.addr == {mac}) or (wlan.fc.type_subtype == 12) or (wlan.addr == {mac} and eapol)) && !(wlan.fc.type_subtype == 0x000e)) && !(wlan.fc.type_subtype == 0x000d) && !(wlan.fc.type_subtype == 0x0000) && !(wlan.fc.type_subtype == 0x0001) && !(wlan.fc.type_subtype == 0x000c) && wlan.fc.type == 0 && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype == 0x0004)'
            print("Display Filter Used", display_filter)
            # try:
            #     capture = pyshark.FileCapture(input_file=pcap_f ile, display_filter=display_filter)
            # except Exception as e:
            #     print(e, "EEEEEEEEEEEERRRRRRRRRR")
            # e=f'tshark -r {pcap_file} -Y "(((wlan.addr == {mac}) or (wlan.addr == {mac} and eapol)) && !(wlan.fc.type_subtype == 0x000e) && !(wlan.fc.type_subtype == 0x000d) && !(wlan.fc.type_subtype == 0x0000) && !(wlan.fc.type_subtype == 0x0001) && !(wlan.fc.type_subtype == 0x000c) && wlan.fc.type == 0 && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype == 0x0004))"'
            # print(e,"COMMAND")
            # tshark_process=subprocess.Popen(e, shell=True)
            # print(tshark_process,"WWWWWWWWWWWWWWWWWWWWWWWWWW")

            # Get the current working directory
            # current_directory = os.getcwd()
            # print("current_directory", current_directory)

            # e=f'tshark -r {pcap_file} -Y "frame contains 0x000b or frame contains 0x0001" -T fields -e frame.time_epoch > epoch_times.txt'
            f = f'tshark -r {pcap_file}  -Y "(((wlan.addr == {mac}) or (wlan.fc.type_subtype == 12) or (wlan.addr == {mac} and eapol)) && !(wlan.fc.type_subtype == 0x000e) && !(wlan.fc.type_subtype == 0x000d) && !(wlan.fc.type_subtype == 0x0000) && !(wlan.fc.type_subtype == 0x0001) && !(wlan.fc.type_subtype == 0x000c) && wlan.fc.type == 0 && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype == 0x0004))" -T fields   -e frame.number   -e frame.time_epoch   -e wlan.addr   -e wlan.fc.type   -e wlan.fc.type_subtype   -e wlan.ssid   -e eapol   -e wlan.fixed.auth_seq  -E header=y   -E separator=,   -E quote=d   > output.csv'
            print(f, "COMMAND")
            tshark_process = subprocess.Popen(f, shell=True)
            tshark_process.wait()
            # print(tshark_process, "WWWWWWWWWWWWWWWWWWWWWWWWWW")
            l = 0
            latest_auth_time = ''
            latest_res_time = ''
            roam_times = []
            # print(capture, "CCCCCCCCCCCCCCCCC")
            # Get the current working directory
            current_directory = os.getcwd()
            print("current_directory", current_directory)
            base_dir = '/home/lanforge'
            source = os.path.join(current_directory, f'output.csv')
            destination_dir = os.path.join(base_dir, 'lanforge-scripts', 'py-scripts')
            destination = os.path.join(destination_dir, self.report_path_date_time, f'output.csv')
            print("destination", destination)
            if os.path.isfile(source):
                shutil.move(source, destination)
                print("File moved successfully!")
            csv_file_path = destination
            print("csv_file_path:- ", csv_file_path)
            with open(csv_file_path, mode='r') as file:
                # Create a CSV DictReader object
                csv_dict_reader = csv.DictReader(file)

                for row in csv_dict_reader:
                    try:
                        # print("j", row)
                        frame_type_subtype = row.get('wlan.fc.type_subtype', '')
                        frame_time_epoch = row.get('frame.time_epoch', '')
                        fixed_auth_seq = row.get('wlan.fixed.auth_seq', '')
                        print("Subtype: ", frame_type_subtype, "Subtype(type): ", type(frame_type_subtype),
                              "Epoch Time: ", frame_time_epoch, "Epoch Time(Type): ", type(frame_time_epoch),
                              "Auth Sequence Code: ", fixed_auth_seq, "Auth Sequence Code(Type): ",
                              type(fixed_auth_seq))
                        # print("JITUUUUU", frame_type_subtype, frame_time_epoch, fixed_auth_seq)
                        # Authentication req = frame subtype (0x000b) or 11
                        if int(frame_type_subtype, 0) == 11 and int(fixed_auth_seq, 0) == 1:
                            latest_auth_time = frame_time_epoch
                        print("latest_auth_time", latest_auth_time)
                    except Exception as e:
                        print(e, "Calculate roam time exception 1")
                    try:
                        # Reassociation Request (0x0002)
                        # print(len(roam_times), "len roam time 0")
                        # print(roam_times, "yyyyyyyyyyyyyyyyyyyy 0")
                        if int(frame_type_subtype, 0) == 2:
                            print("Reassociation Request (0x00000002)")
                            if (len(roam_times) == 0):
                                # print(len(roam_times), "len roam time 1")
                                # print(roam_times, "yyyyyyyyyyyyyyyyyyyy 1")
                                roam_times.append([latest_auth_time])

                                print("roam_times 2", roam_times)
                            else:
                                roam_times.insert(len(roam_times), [latest_auth_time])
                                print("roam_times 23", roam_times)
                    except Exception as e:
                        print(e, "Calculate roam time exception 2")
                    try:
                        # Reassociation Response (0x0003)
                        if int(frame_type_subtype, 0) == 3:
                            print("Reassociation Response (0x00000003)")
                            latest_res_time = frame_time_epoch
                            print("latest_res_time", latest_res_time)
                            if roam_times == []:
                                roam_times.append(['', latest_res_time])
                                print(roam_times, "roam_times jk")
                            else:
                                if roam_times[-1][0] == latest_auth_time:
                                    roam_times[-1].append(latest_res_time)
                                    print(roam_times, "roam_times sg")
                    except Exception as e:
                        print(e, "Calculate roam time exception 3")
                    l += 1
            roam_diff_calcs = []
            start_time = []
            end_time = []
            print("roam_times", roam_times)
            for timestamps in roam_times:
                print("timestamps", timestamps)
                if len(timestamps) != 1:
                    starttime, endtime = timestamps[0], timestamps[-1]
                    if len(starttime) == 0:
                        roam_diff_calcs.append('Missing Authentication or Request Packet')
                        continue
                    else:
                        starttime = float(starttime)
                    if len(endtime) == 0:
                        roam_diff_calcs.append('Missing Reassociation Response')
                        continue
                    else:
                        endtime = float(endtime)

                    starttimes = datetime.fromtimestamp(starttime)
                    endtimes = datetime.fromtimestamp(endtime)
                    roam_diff_calcs.append((endtimes - starttimes).microseconds * 0.001)
                    start_time.append(starttimes)
                    end_time.append(endtimes)
            print(mac, '\t-\t', roam_diff_calcs)
            self.final_data[mac] = {'roam_time': roam_diff_calcs, 'start_time': start_time, 'end_time': end_time}
            # capture.close()

        print(''.join(f'{k}-{v}\n' for k, v in self.final_data.items()))
        print(self.final_data)

    def generate_report(self, result_json=None, result_dir='Roam_Test_Report', report_path=''):
        # self.stop_thread = True
        if result_json is not None:
            self.roam_data = result_json

        total_attempted_roams = len(self.station_list) * self.iterations * len(self.attenuator_combinations)
        total_successful_roams = 0
        for atten_set in self.attenuator_combinations:
            for iteration_values in self.roam_data[tuple(map(tuple, atten_set))].values():
                total_successful_roams += len(iteration_values)
        total_failed_roams = total_attempted_roams - total_successful_roams

        bssid_based_totals = self.bssid_based_totals
        station_based_roam_count = {}
        for combination_data in self.roam_data.values():
            for station_data in combination_data.values():
                if (list(station_data.values()) != []):
                    station, station_values = list(station_data.keys())[0], list(station_data.values())[0]
                    if station.startswith('1.1.sta'):
                        # calculating station based roam count
                        if (station in self.station_based_roam_count):
                            self.station_based_roam_count[station] += 1
                        else:
                            self.station_based_roam_count[station] = 1
                else:
                    logging.info('No roams in between {}'.format(combination_data))

        print(bssid_based_totals)
        print(self.station_based_roam_count)

        # total_auth_failed_roams = 0

        # calculating roam stats

        logging.info('Generating Report')

        report = lf_report(_output_pdf='roam_test.pdf',
                           _output_html='roam_test.html',
                           _results_dir_name=result_dir,
                           _path=report_path)
        report_path = report.get_path()
        self.report_path_date_time = report.get_path_date_time()
        # print("patttthhhh", self.report_path_date_time)
        logging.info('path: {}'.format(report_path))
        logging.info('path_date_time: {}'.format(self.report_path_date_time))

        # setting report title
        report.set_title('Roam Test Report')
        report.build_banner()

        # test setup info
        test_setup_info = {
            'SSID': [self.ssid if self.ssid else 'TEST CONFIGURED'][0],
            'Security': [self.security if self.ssid else 'TEST CONFIGURED'][0],
            'Station Radio': [self.station_radio if self.station_radio else 'TEST CONFIGURED'][0],
            'Sniffer Radio': [self.sniff_radio if self.sniff_radio else 'TEST CONFIGURED'][0],
            'Station Type': self.sta_type,
            'Iterations': self.iterations,
            'No of Devices': len(self.station_list),
            # 'No of Devices': '{} (V:{}, A:{}, W:{}, L:{}, M:{})'.format(len(self.sta_list), len(self.sta_list) - len(self.real_sta_list), self.android, self.windows, self.linux, self.mac),
        }
        report.test_setup_table(
            test_setup_data=test_setup_info, value='Test Setup Information')

        # objective and description
        report.set_obj_html(_obj_title='Objective',
                            _obj='''The Candela Roam test uses the 802.11r Fast BSS Transition roam method to create and roam multiple WiFi stations 
                            between two or more APs with the same SSID on either the same channel or different channels. The user can run 
                            multiple roam iterations over extended durations,with the test measuring the roam time and average roam time for each station. 
                            The test can be conducted with different security methods, allowing users to compare roaming performance.By default,the pass/fail
                            threshold for the roam time is set to 50 milliseconds.Additionally, a customizable roam threshold option allows users to adjust threshold values as needed.
                            ''')
        report.build_objective()

        report.set_obj_html('Pass/Fail Criteria:',
                            '<b>The following are the criteria for PASS the test :</b><br><br>'
                            '1. The BSSID of the station should change after roaming from one AP to another.<br>'
                            '2. The station should not experience any disconnections during/after the roaming process.<br>'
                            f'3. The duration of the roaming process should be less than {self.roam_timeout} ms.<br>'
                            '<br>'
                            '<b>The following are the criteria for FAIL the test :</b><br><br>'
                            '1. The BSSID of the station remains unchanged after roaming from one AP to another.<br>'
                            '2. No roaming occurs, as all stations are connected to the same AP.<br>'
                            '3. The captured packet does not contain a Reassociation Response Frame.<br>'
                            '4. The station experiences disconnection during/after the roaming process.<br>'
                            f'5. The duration of the roaming process exceeds {self.roam_timeout} ms.<br>'
                            '<br>'
                            )

        report.build_objective()
        report.set_obj_html('Roam Time Calculation:',
                            '<b>Roam time calculation measures the delay between the Reassociation Response and the subsequent Authentication Request within the pcap file.</b><br><br>'
                            'Roam Time (ms) = Timestamp of Reassociation Response - Timestamp of Authentication Request    <br>'
                            )

        report.build_objective()
        report.set_table_title(
            '<b>Station based Successful and Failed Roams</b>')
        report.build_table_title()
        report.set_obj_html('',
                            f"<b>NOTE:<br>1. The below chart represents comprehensive information regarding clients who passed or failed migration-based roaming, including a count of each.</b>"
                            )
        report.build_objective()
        report.set_table_title(
            'Migration based Pass/Fail Roam Status')
        report.build_table_title()
        base_dir = '/home/lanforge'
        base_dir = os.path.join(base_dir, 'lanforge-scripts', 'py-scripts')
        table = {
            'Station ID': [],
            'Before Roam BSSID': [],
            'After Roam BSSID': [],
            # 'Start Timestamp': [],
            # 'End Timestamp': [],
            'Roam Time (ms)': [],
            'PASS/FAIL': []
        }

        for station in self.station_list:
            station = (station.split(".")[2])
            source = os.path.join(base_dir, f'wpa_sta_scan_{station}.txt')
            # destination_dir = os.path.join(base_dir, 'lanforge-scripts', 'py-scripts')
            destination = os.path.join(base_dir, f'{report.date_time_directory}', f'wpa_sta_scan_{station}.txt')
            if os.path.isfile(source):
                shutil.move(source, destination)
                # removing print for sta scan
                # print(f" wpa_sta_scan_{station}.txt file moved successfully!")
        base_dir = '/home/lanforge'
        source = os.path.join(base_dir, f'roam_test.pcap')
        destination_dir = os.path.join(base_dir, 'lanforge-scripts', 'py-scripts')
        destination = os.path.join(destination_dir, f'{report.date_time_directory}', f'roam_test.pcap')

        if os.path.isfile(source):
            print("SOURCE1 ", source)
            print("DESTINATION1 ", destination)
            shutil.move(source, destination)
            print("File moved successfully!")

        else:
            print(f"Source file does not exist else 2: {source}")
            print(destination, "DESTINATION else 2")
            if os.path.isfile(destination):
                print("file check in destination again ", destination)
            else:
                if os.path.isfile(source):
                    print("in else else file check in source ", source)
                    print("DESTINATION check in else else  ", destination)
                    shutil.move(source, destination)
                else:
                    print(f"Source file does not exist else else last warning in FAIL 2: {source}")
        mac_list = self.get_mac()
        self.calculate_roam_time(destination, mac_list)

        # status_list = []
        max_len = len(self.roam_bssid_info[f'{self.station_list[0]}']['BSSID_before'])
        for key, values in self.final_data.items():
            if len(values['roam_time']) < max_len:
                values['roam_time'].extend(['-'] * (max_len - len(values['roam_time'])))
            # if len(values['start_time']) < max_len:
            #    values['start_time'].extend(['-']*(max_len - len(values['start_time'])))
            # if len(values['end_time']) < max_len :
            #     values['end_time'].extend(['-']*(max_len - len(values['end_time'])))
            if len(values['roam_time']) > max_len:
                values['roam_time'] = values['roam_time'][:max_len]
            # if len(values['start_time']) > max_len :
            #     values['start_time'] = values['start_time'][:max_len]
            # if len(values['end_time']) > max_len:
            #     values['end_time'] = values['end_time'][:max_len]

        for sta in self.roam_bssid_info:
            bssid_before_list = self.roam_bssid_info[sta]['BSSID_before']
            bssid_after_list = self.roam_bssid_info[sta]['BSSID_after']
            # signal_list = self.roam_bssid_info[sta]['Signal']

            status_list = []
            status_list.extend(
                ['Success' if isinstance(i, (int, float)) and float(i) <= int(self.roam_timeout) else 'Failed' for i in
                 self.final_data[self.sta_mac[sta]]['roam_time']])
            table['PASS/FAIL'].extend(status_list)
            table['Roam Time (ms)'].extend(self.final_data[self.sta_mac[sta]]['roam_time'])
            # table['Start Timestamp'].extend(self.final_data[self.sta_mac[sta]]['start_time'])
            # table['End Timestamp'].extend(self.final_data[self.sta_mac[sta]]['end_time'])
            print(bssid_before_list, bssid_after_list, status_list)
            for bssid_before, bssid_after in zip(bssid_before_list, bssid_after_list):
                table['Station ID'].append(sta)
                table['Before Roam BSSID'].append(bssid_before)
                table['After Roam BSSID'].append(bssid_after)
                # table['Signal'].append(signal)

        print("Final Result:- ", table)
        target_len = len(table['Station ID'])
        for key, value in table.items():
            if len(value) > target_len:
                table[key] = value[:target_len]
            elif len(value) < target_len:
                table[key] = value + ['-'] * (target_len - len(value))
        test_setup_pass_fail = pd.DataFrame(table)
        pass_cnt, fail_cnt = 0, 0
        for i in table['PASS/FAIL']:
            if i == 'Success':
                pass_cnt += 1
            else:
                fail_cnt += 1
        dataset = []
        dataset.append([0, fail_cnt])
        dataset.append([pass_cnt, 0])

        roam_graph = lf_bar_graph(_data_set=dataset,
                                  _xaxis_categories=['Pass', 'Fail'],
                                  _label=['Fail', 'Pass'],
                                  _xaxis_name='Roam Status based on Roam Time',
                                  _yaxis_name='Count',
                                  # _remove_border=['left'],
                                  # _show_bar_value=True,
                                  _title_size=10,
                                  _color=['red', 'forestgreen'],
                                  _figsize=(9, 5),
                                  _graph_title='Migration based Pass/Fail Roam Status',
                                  _graph_image_name='Roam_time',
                                  )
        graph_png = roam_graph.build_bar_graph()
        report.set_graph_image(graph_png)
        report.move_graph_image()
        # report.set_csv_filename(graph_png)
        # report.move_csv_file()
        report.build_graph()

        table = {
            'Total Roams Success ': pass_cnt,
            'Total Roams Failed ': fail_cnt
        }

        test_setup = pd.DataFrame(table, index=[0])
        report.set_table_dataframe(test_setup)
        report.build_table()

        report.set_obj_html('',
                            f"<br><b>2. Below table is based on the roam time Pass/Fail criteria. For exapmle, if a client roams from one BSSID to another and the process takes longer than the threshold roam time, it is countered as a failed roam.</b>"
                            )
        report.build_objective()

        report.set_table_dataframe(test_setup_pass_fail)
        report.pass_failed_build_table()

        # Migration Totals
        report.set_table_title(
            'Total Roams attempted based on the roams')
        report.build_table_title()
        report.set_obj_html('',
                            f"<b>NOTE:<br>1. The below chart presents comprehensive information regarding total number of roams attempted by clients,based on BSSID,including a count of these attempts.</b><br>"
                            )
        report.build_objective()
        # graph for above
        total_roams_graph = lf_bar_graph_horizontal(
            _data_set=[[total_attempted_roams], [total_successful_roams], [total_failed_roams]],
            _xaxis_name='Roam Count',
            _yaxis_name='Wireless Clients',
            _label=[
                'Attempted Roams', 'Successful Roams', 'Failed Roams'],
            _graph_image_name='Total Roams attempted based on the roams',
            _yaxis_label=['Stations'],
            _yaxis_categories=['Stations'],
            _yaxis_step=1,
            _yticks_font=6,
            _graph_title='Total Roams attempted based on the roams',
            _title_size=10,
            _color=['orange',
                    'darkgreen', 'red'],
            _color_edge=['black'],
            _bar_height=0.15,
            _legend_loc="best",
            _legend_box=(1.0, 1.0),
            _dpi=96,
            _show_bar_value=False,
            _enable_csv=True,
            _color_name=['orange', 'darkgreen', 'red'])

        total_roams_graph_png = total_roams_graph.build_bar_graph_horizontal()
        logging.info('graph name {}'.format(total_roams_graph_png))
        report.set_graph_image(total_roams_graph_png)
        # need to move the graph image to the results directory
        report.move_graph_image()
        report.set_csv_filename(total_roams_graph_png)
        report.move_csv_file()
        report.build_graph()
        report.set_obj_html('',
                            f"2. The below table is based on BSSID. For exapmle, if a client roams from one AP BSSID to another, it will count as one roam based on the BSSID change.</b>"
                            )
        report.build_objective()
        # Table data
        table = {
            'Total Attemped Roams': total_attempted_roams,
            'Total Successful Roams': total_successful_roams,
            'Total Failed Roams': total_failed_roams
        }
        # print('Total Roams Attempted vs Successful vs Failed :', table)
        test_setup = pd.DataFrame(table, index=[0])
        report.set_table_dataframe(test_setup)
        report.build_table()

        # bssid based roam count
        report.set_table_title(
            '<b>Migration-based BSSID Successful vs Failed</b>')
        report.build_table_title()
        report.set_obj_html('',
                            f"<b>NOTE:<br>1. The below chart presents comprehensive information regarding clients who successfully or unsuccessfully roamed from one BSSID to another, including a count of each.</b><br>"
                            )
        report.build_objective()
        # graph for above
        bssid_based_total_attempted_roams = [total_attempted_roams // 2] * len(list(bssid_based_totals.values()))
        bssid_based_failed_roams = [bssid_based_total_attempted_roams[roam] - list(bssid_based_totals.values())[roam]
                                    for roam in range(len(bssid_based_totals.values()))]
        print(bssid_based_total_attempted_roams)
        print(bssid_based_failed_roams)
        print(bssid_based_totals.values())
        print(bssid_based_totals.keys())
        bssid_based_graph = lf_bar_graph_horizontal(_data_set=[list(bssid_based_totals.values())],
                                                    _xaxis_name='Roam Count',
                                                    _yaxis_name="BSSID's",
                                                    _label=['Roams'],
                                                    _graph_image_name='Migration-based BSSID Successful vs Failed',
                                                    _yaxis_label=list(bssid_based_totals.keys()),
                                                    _yaxis_categories=list(bssid_based_totals.keys()),
                                                    _yaxis_step=1,
                                                    _yticks_font=6,
                                                    _graph_title='Migration-based BSSID Successful vs Failed',
                                                    _title_size=10,
                                                    _color=['darkgreen', 'darkgreen', 'red'],
                                                    _color_edge=['black'],
                                                    _bar_height=0.15,
                                                    _legend_loc="best",
                                                    _legend_box=(1.0, 1.0),
                                                    _dpi=96,
                                                    _show_bar_value=False,
                                                    _enable_csv=True,
                                                    _color_name=['darkgreen', 'darkgreen', 'red'])

        bssid_based_graph_png = bssid_based_graph.build_bar_graph_horizontal()
        logging.info('graph name {}'.format(bssid_based_graph_png))
        report.set_graph_image(bssid_based_graph_png)
        # need to move the graph image to the results directory
        report.move_graph_image()
        report.set_csv_filename(bssid_based_graph_png)
        report.move_csv_file()
        report.build_graph()
        report.set_obj_html('',
                            f"<b>2. The below table is based on BSSID roam criteria. For exapmle, if a client roams from one AP BSSID to another, it will count as one BSSID-based roam.</b>"
                            )
        report.build_objective()
        table = {
            'BSSID': list(bssid_based_totals.keys()),
            'Successful Roams': list(bssid_based_totals.values())
        }
        print('BSSID based Successful Roams', table)
        test_setup = pd.DataFrame(table)
        report.set_table_dataframe(test_setup)
        report.build_table()

        # station based roam count
        report.set_table_title(
            '<b>Migration-based Station Successful vs Failed</b>')
        report.build_table_title()
        report.set_obj_html('',
                            f"<b>NOTE:<br>1. The below chart represents comprehensive information regarding each client's successful or unsuccessful roaming attempts, including a count of each.</b><br>"
                            )
        report.build_objective()
        # graph for above
        station_based_total_attempted_roams = [total_attempted_roams // len(self.station_list)] * len(self.station_list)
        station_based_failed_roams = []
        station_based_success_roams = []
        for station in self.station_list:
            station_based_failed_roams.append(
                (total_attempted_roams // len(self.station_list)) - self.sta_roam_count[station])
            station_based_success_roams.append(self.sta_roam_count[station])
        print(station_based_success_roams)
        print(station_based_total_attempted_roams)
        print(station_based_failed_roams)
        print(self.station_based_roam_count.values())
        print(self.station_based_roam_count.keys())
        station_based_graph = lf_bar_graph_horizontal(
            _data_set=[station_based_total_attempted_roams, list(self.sta_roam_count.values()),
                       station_based_failed_roams],
            _xaxis_name='Roam Count',
            _yaxis_name='Wireless Clients',
            _label=['Total', 'Successful', 'Failed'],
            _graph_image_name='Migration-based Station Successful vs Failed',
            _yaxis_label=list(self.station_based_roam_count.keys()),
            _yaxis_categories=list(self.station_based_roam_count.keys()),
            _yaxis_step=1,
            _yticks_font=6,
            _graph_title='Migration-based Station Successful vs Failed',
            _title_size=10,
            _color=['orange', 'darkgreen', 'red'],
            _color_edge=['black'],
            _bar_height=0.15,
            _legend_loc="best",
            _legend_box=(1.0, 1.0),
            _dpi=96,
            _show_bar_value=False,
            _enable_csv=True,
            _color_name=['orange', 'darkgreen', 'red'])

        station_based_graph_png = station_based_graph.build_bar_graph_horizontal()
        logging.info('graph name {}'.format(station_based_graph_png))
        report.set_graph_image(station_based_graph_png)
        # need to move the graph image to the results directory
        report.move_graph_image()
        report.set_csv_filename(station_based_graph_png)
        report.move_csv_file()
        report.build_graph()

        report.set_obj_html('Clients Information',
                            "The table below represents comprehensive information regarding Clients, including its MAC address, Total Roams Attempted,Total Roams Successful and Total Roams Failed. The below table is based on per-station roam criteria. For exapmle, if a multiple client's roams from one AP BSSID to another,each roam will be counted individually."
                            )
        report.build_objective()
        table = {
            'Station ID ': self.station_list,
            'MAC': self.get_mac(),
            'Total Roams Attempted': station_based_total_attempted_roams,
            'Total Roams Successful': station_based_success_roams,
            'Total Roams Failed': station_based_failed_roams
        }

        test_setup = pd.DataFrame(table)
        report.set_table_dataframe(test_setup)
        report.build_table()

        report.set_table_title(
            'Average Roam Time per each Station')
        report.build_table_title()
        report.set_obj_html('',
                            f"The table below represents comprehensive information regarding average roam time of each client.</b><br>"
                            )
        report.build_objective()
        table = {
            'Stations': self.station_list,
            'Average Roam Time (ms)': [
                (sum(value for value in self.final_data[self.sta_mac[sta]]['roam_time'] if value != '-') / len(
                    [value for value in self.final_data[self.sta_mac[sta]]['roam_time'] if value != '-']) if len(
                    [value for value in self.final_data[self.sta_mac[sta]]['roam_time'] if value != '-']) > 0 else 0)
                for sta in self.station_list
            ]
        }

        test_setup = pd.DataFrame(table)
        report.set_table_dataframe(test_setup)
        report.build_table()

        # closing
        report.build_custom()
        report.build_footer()
        report.write_html()
        report.write_pdf()


def main():
    help_summary = '''
'''
    parser = argparse.ArgumentParser(
        prog='roam_test.py',
    )
    required = parser.add_argument_group('Required Arguments')

    required.add_argument('--ssid',
                          help='SSID of the APs',
                          required=False)
    required.add_argument('--security',
                          help='Encryption type for the SSID',
                          required=False)
    required.add_argument('--password',
                          help='Key/Password for the SSID',
                          required=False)
    required.add_argument('--sta_radio',
                          help='Station Radio',
                          default='1.1.wiphy0',
                          required=False)
    required.add_argument('--band',
                          help='eg. --band "2G", "5G" or "6G"',
                          default="5G")
    required.add_argument('--num_sta',
                          help='Number of Stations',
                          type=int,
                          default=1,
                          required=False)
    required.add_argument('--option',
                          help='eg. --option "ota',
                          type=str,
                          default="ota",
                          required=False)
    required.add_argument('--identity',
                          help='Radius server identity',
                          type=str,
                          default="testuser",
                          required=False)
    required.add_argument('--eap_method',
                          help='EAP Method for EAP',
                          type=str,
                          default="TTLS",
                          required=False)
    required.add_argument('--key_management',
                          help='Key Management for EAP',
                          type=str,
                          default="DEFAULT",
                          required=False)
    required.add_argument('--ca_cert',
                          help='ca-cert',
                          type=str,
                          default="./home/lanforge/ca.pem",
                          required=False)
    required.add_argument('--private_key',
                          help='Private Key for Ent',
                          type=str,
                          default="./home/lanforge/client.p12",
                          required=False)
    required.add_argument('--pk_passwd',
                          help='Private Key Password for Ent',
                          type=str,
                          default="whatever",
                          required=False)
    required.add_argument('--pair_cipher',
                          help='Pair Cipher for Ent',
                          type=str,
                          default="[BLANK]",
                          required=False)
    required.add_argument('--group_cipher',
                          help='Group Cipher for Ent',
                          type=str,
                          default="[BLANK]",
                          required=False)

    required.add_argument('--ttls_pass',
                          help='Radius Server passwd',
                          type=str,
                          default="testpasswd",
                          required=False)
    required.add_argument('--sta_type',
                          type=str,
                          help="provide the type of"
                               " client you want to create i.e 11r,11r-sae,"
                               " 11r-sae-802.1x, 11r-wpa2-802.1x, 11r-sae-ext-key, custom or simple as none", default="11r")

    optional = parser.add_argument_group('Optional Arguments')

    optional.add_argument('--mgr',
                          help='LANforge IP',
                          default='localhost')
    optional.add_argument('--port',
                          help='LANforge port',
                          type=int,
                          default=8080)
    optional.add_argument('--upstream',
                          help='Upstream Port',
                          default='1.1.eth1')
    optional.add_argument('--step',
                          help='Attenuation increment/decrement step size',
                          type=int,
                          default=10)
    optional.add_argument('--max_attenuation',
                          help='Maximum attenuation value (dBm) for the attenuators',
                          type=int,
                          default=95)
    optional.add_argument('--attenuators',
                          nargs='+',
                          help='Attenuator serials',
                          required=True)
    optional.add_argument('--iterations',
                          help='Number of iterations to perform roam test',
                          type=int,
                          default=2)
    optional.add_argument('--wait_time',
                          help='Waiting time (seconds) between iterations',
                          type=int,
                          default=15)
    optional.add_argument('--roam_timeout',
                          help='Threshold time(in milli seconds) to determine if the roam attempt succeeds or fails',
                          type=int,
                          default=50)
    optional.add_argument('--channel',
                          help='Channel',
                          type=str,
                          default='AUTO')
    optional.add_argument('--frequency',
                          help='Frequency',
                          type=int,
                          default=-1)
    optional.add_argument('--station_list',
                          help='List of stations to perform roam test (comma seperated)')
    optional.add_argument('--station_flag',
                          help='station flags to add. eg: --station_flag use-bss-transition',
                          required=False,
                          default=None)
    optional.add_argument('--bg_scan',
                          help='Background scan filter',
                          required=False,
                          default='simple:10:-65:300:4')
    optional.add_argument('--sniff_radio',
                          help='Sniffer Radio',
                          default='1.1.wiphy0')
    optional.add_argument('--sniff_duration',
                          help='Sniff duration',
                          type=int,
                          default=300)
    optional.add_argument('--disable_restart_dhcp',
                          help='This disables Restart Dhcp on connect flag in Station Misc config',
                          action='store_true')
    parser.add_argument('--help_summary',
                        help='Show summary of what this script does',
                        default=None,
                        action="store_true")

    # logging configuration:
    parser.add_argument('--log_level', default=None,
                        help='Set logging level: debug | info | warning | error | critical')

    parser.add_argument("--lf_logger_config_json",
                        help="--lf_logger_config_json <json file> , json configuration of logger")

    args = parser.parse_args()

    # help summary
    if (args.help_summary):
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

    if args.disable_restart_dhcp:
        disable_restart_dhcp = True
    else:
        disable_restart_dhcp = False
    if (args.station_list is not None):
        stations = args.station_list.split(',')
        roam_test = Roam(
            lanforge_ip=args.mgr,
            port=args.port,
            sniff_radio=args.sniff_radio,
            attenuators=args.attenuators,
            step=args.step,
            max_attenuation=args.max_attenuation,
            sniff_duration=args.sniff_duration,
            upstream=args.upstream,
            wait_time=args.wait_time,
            channel=args.channel,
            frequency=args.frequency,
            iterations=args.iterations,
            roam_timeout=args.roam_timeout,
            bg_scan=args.bg_scan
        )
        roam_test.station_list = stations
        logging.info('Selected stations\t{}'.format(stations))
    else:
        roam_test = Roam(
            lanforge_ip=args.mgr,
            port=args.port,
            sniff_radio=args.sniff_radio,
            station_radio=args.sta_radio,
            band=args.band,
            attenuators=args.attenuators,
            step=args.step,
            max_attenuation=args.max_attenuation,
            sniff_duration=args.sniff_duration,
            upstream=args.upstream,
            ssid=args.ssid,
            security=args.security,
            password=args.password,
            num_sta=args.num_sta,
            station_flag=args.station_flag,
            option=args.option,
            identity=args.identity,
            # new
            eap_method=args.eap_method,
            key_management=args.key_management,
            ca_cert=args.ca_cert,
            private_key=args.private_key,
            pk_passwd=args.pk_passwd,
            pair_cipher=args.pair_cipher,
            group_cipher=args.group_cipher,
            # new complete
            ttls_pass=args.ttls_pass,
            sta_type=args.sta_type,
            wait_time=args.wait_time,
            channel=args.channel,
            frequency=args.frequency,
            iterations=args.iterations,
            roam_timeout=args.roam_timeout,
            bg_scan=args.bg_scan,
            disable_restart_dhcp=disable_restart_dhcp
        )
        logging.info(
            'Starting sniffer with roam_test.pcap')
        roam_test.start_sniff(
            capname='roam_test.pcap')

        roam_test.create_clients()
        # roam_test.create_cx()
        # roam_test.start_cx()

    if (roam_test.soft_roam):
        logging.info('Initiating soft roam test')

        # roam_test.soft_roam_test()
        try:
            roam_test.soft_roam_test()
        except Exception as e:
            roam_test.stop_sniff()
            print(e, "soft_roam_test Exception")
        # roam_test.stop_cx()

    roam_test.generate_report()


if __name__ == '__main__':
    main()

