#!/usr/bin/env python3
"""
NAME: create_station.py

PURPOSE: create_station.py will create a variable number of stations, and connect them to a specified wireless network.

EXAMPLE:
         # For creating station with multiple radio with different securities

            eap_method,identity,anonymous,eap_passwd,phase1,phase2,pk_password,ca_cert,private_key,key_mgmt,pairwise,group,sta_flag,pk_password,mode

            create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>'
                                                   --radios 'radio==1.1.wiphy2,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>,eap_method==<TTLS|PEAP>,key_mgmt==<key mgmt>'

SCRIPT_CLASSIFICATION:  Creation

SCRIPT_CATEGORIES:   Functional

NOTES:
        Does not create cross connects
        Mainly used to determine how to create a station

        * We can also specify the mode for the stations using "--mode" argument

            --mode   1
                {"auto"   : "0",
                "a"      : "1",
                "b"      : "2",
                "g"      : "3",
                "abg"    : "4",
                "abgn"   : "5",
                "bgn"    : "6",
                "bg"     : "7",
                "abgnAC" : "8",
                "anAC"   : "9",
                "an"     : "10",
                "bgnAC"  : "11",
                "abgnAX" : "12",
                "bgnAX"  : "13"}

            example:
                    create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>,mode==6'

            --station_flag  <staion_flags>
                add_sta_flags = {
                "osen_enable"          :  Enable OSEN protocol (OSU Server-only Authentication)
                "ht40_disable"         :  Disable HT-40 even if hardware and AP support it.
                "ht160_enable"         :  Enable HT160 mode.
                "disable_sgi"          :  Disable SGI (Short Gu
                "hs20_enable"          :  Enable Hotspot 2.0 (HS20) feature.  R
                "txo-enable"           :  Enable/disable tx-offloads, typically managed by set_wifi_txo command
                "custom_conf"          :  Use Custom wpa_supplicant config file.
                "ibss_mode"            :  Station should be in IBSS mode.
                "mesh_mode"            :  Station should be in MESH mode.
                "wds-mode"             :  WDS station (sort of like a lame mesh), not supported on ath10k
                "scan_ssid"            :  Enable SCAN-SSID flag in wpa_supplicant.
                "passive_scan"         :  Use passive scanning (don't send probe requests).
                "lf_sta_migrate"       :  OK-To-Migrate (Allow station migration between LANforge radios)
                "disable_fast_reauth"  :  Disable fast_reauth option for virtual stations.
                "power_save_enable"    :  Station should enable power-save.  May not work in all drivers/configurations.
                "disable_roam"         :  Disable automatic station roaming based on scan results.
                "no-supp-op-class-ie"  :  Do not include supported-oper-class-IE in assoc requests.  May work around AP bugs.
                "use-bss-transition"   :  Enable BSS transition.
                "ft-roam-over-ds"      :  Roam over DS when AP supports it.
                "disable_ht80"         :  Disable HT80 (for AC chipset NICs only)}
                "80211r_pmska_cache"   :  Enable PMSKA caching for WPA2 (Related to 802.11r)

            example:
                     create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>,mode==6,station_flag==power_save_enable'

            --country_code 840

                United States   :   840     |       Dominican Rep   :   214     |      Japan (JE2)     :   397     |      Portugal        :   620
                Albania         :   8       |       Ecuador         :   218     |      Jordan          :   400     |      Pueto Rico      :   630
                Algeria         :   12      |       Egypt           :   818     |      Kazakhstan      :   398     |      Qatar           :   634
                Argentina       :   32      |       El Salvador     :   222     |      North Korea     :   408     |      Romania         :   642
                Bangladesh      :   50      |       Estonia         :   233     |      South Korea     :   410     |      Russia          :   643
                Armenia         :   51      |       Finland         :   246     |      South Korea     :   411     |      Saudi Arabia    :   682
                Australia       :   36      |       France          :   250     |      Kuwait          :   414     |      Singapore       :   702
                Austria         :   40      |       Georgia         :   268     |      Latvia          :   428     |      Slovak Republic :   703
                Azerbaijan      :   31      |       Germany         :   276     |      Lebanon         :   422     |      Slovenia        :   705
                Bahrain         :   48      |       Greece          :   300     |      Liechtenstein   :   438     |      South Africa    :   710
                Barbados        :   52      |       Guatemala       :   320     |      Lithuania       :   440     |      Spain           :   724
                Belarus         :   112     |       Haiti           :   332     |      Luxembourg      :   442     |      Sweden          :   752
                Belgium         :   56      |       Honduras        :   340     |      Macau           :   446     |      Switzerland     :   756
                Belize          :   84      |       Hong Kong       :   344     |      Macedonia       :   807     |      Syria           :   760
                Bolivia         :   68      |       Hungary         :   348     |      Malaysia        :   458     |      Taiwan          :   158
                BiH             :   70      |       Iceland         :   352     |      Mexico          :   484     |      Thailand        :   764
                Brazil          :   76      |       India           :   356     |      Monaco          :   492     |      Trinidad &Tobago:   780
                Brunei          :   96      |       Indonesia       :   360     |      Morocco         :   504     |      Tunisia         :   788
                Bulgaria        :   100     |       Iran            :   364     |      Netherlands     :   528     |      Turkey          :   792
                Canada          :   124     |       Ireland         :   372     |      Aruba           :   533     |      U.A.E.          :   784
                Chile           :   152     |       Israel          :   376     |      New Zealand     :   554     |      Ukraine         :   804
                China           :   156     |       Italy           :   380     |      Norway          :   578     |      United Kingdom  :   826
                Colombia        :   170     |       Jamaica         :   388     |      Oman            :   512     |      Uruguay         :   858
                Costa Rica      :   188     |       Japan           :   392     |      Pakistan        :   586     |      Uzbekistan      :   860
                Croatia         :   191     |       Japan (JP1)     :   393     |      Panama          :   591     |      Venezuela       :   862
                Cyprus          :   196     |       Japan (JP0)     :   394     |      Peru            :   604     |      Vietnam         :   704
                Czech Rep       :   203     |       Japan (JP1-1)   :   395     |      Philippines     :   608     |      Yemen           :   887
                Denmark         :   208     |       Japan (JE1)     :   396     |      Poland          :   616     |      Zimbabwe        :   716

            --no_pre_cleanup
                    Disables station cleanup before creation of stations

            example:
                    create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>' --no_pre_cleanup


            --cleanup
                    Add this flag to clean up stations after creation

            example:
                    create_station.py --mgr <lanforge ip> --radio wiphy1 --start_id 2 --num_stations 1 --ssid <ssid> --passwd <password>
                    --security wpa2 --cleanup

        * For enterprise authentication
            --eap_method <eap_method>
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

            --pairwise_cipher [BLANK]
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

            --groupwise_cipher [BLANK]
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

            --eap_identity <eap_identity>
                    Add this argument to specify the username of radius server

            --eap_password <eap_password>
                    Add this argument to specify the password of radius server

            --pk_passwd <private_key_passsword>
                    Add this argument to specify the private key password
                    Required only for TLS

            --ca_cert <path_to_certificate>
                    Add this argument to specify the certificate path
                    Required only for TLS

            example:
                    /home/lanforge/ca.pem

            --private_key <path_to_private_key>
                    Add this argument to specify the private key path
                    Required only for TLS

            example:
                    /home/lanforge/client.p12

            --key_mgmt <SAE>
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

STATUS: Functional

VERIFIED_ON:   9-JUN-2023,
             GUI Version:  5.4.6
             Kernel Version: 5.19.17+

LICENSE:
          Free to distribute and modify. LANforge systems must be licensed.
          Copyright 2023 Candela Technologies Inc

INCLUDE_IN_README: False

"""
import subprocess
import sys
import os
import importlib
import argparse
import pprint
import logging
import subprocess
import time
import shutil
import datetime


logger = logging.getLogger(__name__)
if sys.version_info[0] != 3:
    logger.critical("This script requires Python 3")
    exit(1)

sys.path.append(os.path.join(os.path.abspath(__file__ + "../../../")))

lfcli_base = importlib.import_module("py-json.LANforge.lfcli_base")
LFCliBase = lfcli_base.LFCliBase
LFUtils = importlib.import_module("py-json.LANforge.LFUtils")
realm = importlib.import_module("py-json.realm")
Realm = realm.Realm
lf_cleanup = importlib.import_module("py-scripts.lf_cleanup")
lf_logger_config = importlib.import_module("py-scripts.lf_logger_config")
lf_modify_radio = importlib.import_module("py-scripts.lf_modify_radio")
add_sta = importlib.import_module("py-json.LANforge.add_sta")
gen_cxprofile = importlib.import_module("py-json.gen_cxprofile")
GenCXProfile = gen_cxprofile.GenCXProfile


class CreateStation(Realm):
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
                 _ssid=None,
                 _bssid=None,
                 _security=None,
                 _password=None,
                 _host=None,
                 _port=None,
                 _mode=0,
                 _eap_method=None,
                 _eap_identity=None,
                 _eap_anonymous_identity="[BLANK]",
                 _eap_password=None,
                 _eap_phase1="[BLANK]",
                 _eap_phase2="[BLANK]",
                 _pk_passwd=None,
                 _ca_cert=None,
                 _private_key=None,
                 _key_mgmt=None,
                 _pairwise_cipher=None,
                 _groupwise_cipher=None,
                 _sta_list=None,
                 _sta_flags=None,
                 _number_template="00000",
                 _radio="wiphy0",
                 _proxy_str=None,
                 _debug_on=False,
                 _up=True,
                 _set_txo_data=None,
                 _exit_on_error=False,
                 _exit_on_fail=False,
                 _command=None,
                 _custom_wifi_cmd=None,
                 _ieee80211w=1,
                 _extra_securities=None):
        super().__init__(_host,
                         _port)
        self.host = _host
        self.port = _port
        self.ssid = _ssid
        self.bssid = _bssid
        self.security = _security
        self.password = _password
        self.mode = _mode
        self.ieee80211w = _ieee80211w
        self.extra_securities = _extra_securities
        if _mode:
            if str.isalpha(_mode):
                self.mode = add_sta.add_sta_modes[_mode]

        self.stations_build_start_time = 0

        # self.eap_method = _eap_method
        if _eap_method in self.EAP_METHOD_MAP:
            self.eap_method = self.EAP_METHOD_MAP[_eap_method]
        else:
            self.eap_method = _eap_method
        self.eap_identity = _eap_identity
        self.eap_anonymous_identity = _eap_anonymous_identity
        self.eap_password = _eap_password
        self.eap_phase1 = _eap_phase1
        self.eap_phase2 = _eap_phase2
        self.pk_passwd = _pk_passwd
        self.ca_cert = _ca_cert
        self.private_key = _private_key
        # self.key_mgmt = _key_mgmt
        # self.pairwise_cipher = _pairwise_cipher
        # self.groupwise_cipher = _groupwise_cipher
        if _key_mgmt in self.KEY_MGMT_MAP:
            self.key_mgmt = self.KEY_MGMT_MAP[_key_mgmt]
        else:
            self.key_mgmt = _key_mgmt

        if _pairwise_cipher in self.PAIRWISE_CIPHER_MAP:
            self.pairwise_cipher = self.PAIRWISE_CIPHER_MAP[_pairwise_cipher]
        else:
            self.pairwise_cipher = _pairwise_cipher

        if _groupwise_cipher in self.GROUPWISE_CIPHER_MAP:
            self.groupwise_cipher = self.GROUPWISE_CIPHER_MAP[_groupwise_cipher]
        else:
            self.groupwise_cipher = _groupwise_cipher
        self.sta_list = _sta_list
        self.sta_flags = _sta_flags
        self.radio = _radio
        self.timeout = 120
        self.number_template = _number_template
        self.debug = _debug_on
        self.up = _up
        self.set_txo_data = _set_txo_data
        self.custom_wifi_cmd = _custom_wifi_cmd
        self.command = _command
        self.generic_endps_profile = self.new_generic_endp_profile()
        self.generic_endps_profile.type = 'generic'
        # self.generic_endps_profile.name_prefix  = "zoom"
        self.station_profile = self.new_station_profile()
        self.station_profile.lfclient_url = self.lfclient_url
        self.station_profile.ssid = self.ssid
        self.station_profile.bssid = self.bssid
        self.station_profile.ssid_pass = self.password,
        self.station_profile.security = self.security
        self.station_profile.number_template_ = self.number_template
        self.station_profile.mode = self.mode
        # if self.sta_flags is not None:
        #     self.station_profile.desired_add_sta_flags = self.sta_flags
        #     self.station_profile.desired_add_sta_mask = self.sta_flags

        if self.sta_flags is not None:
            _flags = self.sta_flags.split(',')
            for flags in _flags:
                logger.info(f"Selected Flags: '{flags}'")
                self.station_profile.set_command_flag("add_sta", flags, 1)

    def cleanup(self):
        sta_lst = [list(station.keys())[0] for station in self.station_list()]
        for station in sta_lst:
            print('Removing the station {} if exists'.format(station))
            self.rm_port(station, check_exists=True)
        if (not LFUtils.wait_until_ports_disappear(base_url=self.station_profile.lfclient_url, port_list=self.sta_list,
                                                   debug=self.debug)):
            print('All stations are not removed or a timeout occurred.')
            print('Aborting the test.')
            exit(1)

    def print_wifi_messages(self, time_stamp):
        response = self.json_get("wifi-msgs/since=time/{}".format(time_stamp))
        for wifi_messages in response['wifi-messages']:
            for message in wifi_messages.values():
                timestamp = str(message['time-stamp'])
                print(datetime.datetime.fromtimestamp(int(timestamp[:-3])).strftime('%Y-%m-%d %H:%M:%S'), end=" : ")
                print(message['text'])

    def build(self):
        # Build stations

        self.stations_build_start_time = int(time.time())
        print("stating creation started at {}".format(self.stations_build_start_time))

        self.station_profile.use_security(security_type=self.security,
                                          ssid=self.ssid,
                                          passwd=self.password)
        self.station_profile.set_number_template(self.number_template)
        print("Creating stations")
        self.station_profile.set_command_flag("add_sta", "create_admin_down", 1)
        print("extra security:- ", self.extra_securities)
        if self.extra_securities:
            self.station_profile.add_security_extra(security=self.extra_securities)
        if not self.password:
            self.password = "[BLANK]"
        if not self.key_mgmt:
            self.key_mgmt = "DEFAULT"
        if not self.pairwise_cipher:
            self.pairwise_cipher = "DEFAULT"
        if not self.groupwise_cipher:
            self.groupwise_cipher = "DEFAULT"
        if not self.eap_method:
            self.eap_method = "DEFAULT"
        if not self.eap_identity:
            self.eap_identity = ""
        if not self.eap_password:
            self.eap_password = ""
        if not self.private_key:
            self.private_key = ""
        if not self.ca_cert:
            self.ca_cert = ""
        if not self.pk_passwd:
            self.pk_passwd = ""
        if not self.eap_phase1:
            self.eap_phase1 = ""
        if not self.eap_phase2:
            self.eap_phase2 = ""
        if not self.eap_anonymous_identity:
            self.eap_anonymous_identity = ""
        # if not self.psk:
        #     self.psk = ""

        # Configure station 802.1X settings
        if not self.eap_method or self.eap_method == "DEFAULT":
            # Not 802.1X, but user may have specified other parameters
            #
            # When add support for other parameters, need to be careful here.
            # Default from args is currently 'None' when unspecified
            if self.key_mgmt != "DEFAULT":
                # For whatever reason, setting the key mgmt here (using 'set_wifi_extra')
                # clears the 'Key/Phrase' field set by 'add_sta'. Following workaround uses
                # the 'set_wifi_extra' command's 'psk' parameter to set the 'WPA PSK'
                # field in the 'Advanced Configuration' tab
                #
                # Hack to get around unfortunate argparse/initializer default settings which
                # would result in 'null' password when password is not specified
                if not self.password:
                    self.password = "[BLANK]"
                # if not self.pairwise_cipher:
                #     self.pairwise_cipher="DEFAULT"
                # if not self.groupwise_cipher:
                #     self.groupwise_cipher="DEFAULT"
                # if not self.psk:
                #     self.psk=""
                #

                # Have to set 'Advanced/802.1X' flag in order for 'psk' argument to take.
                # This works around limitation in the GUI which does a check for 'Key/Phrase'
                # length when WPA/WPA2/WPA3 enabled (but that field is sadly also cleared here)
                self.station_profile.set_wifi_extra(key_mgmt=self.key_mgmt,
                                                    psk=self.password,
                                                    pairwise=self.pairwise_cipher,
                                                    group=self.groupwise_cipher
                                                    )
                # self.station_profile.set_command_flag(command_name="add_sta", param_name="80211u_enable", value=0)
                self.station_profile.set_command_flag(command_name="add_sta", param_name="8021x_radius",
                                                      value=1)  # Enable Advanced/802.1X flag
            else:
                print("In condition for no key management, therefore no additional changes on the go")
        else:
            if self.eap_method == 'TLS':
                self.station_profile.set_wifi_extra(key_mgmt=self.key_mgmt,
                                                    pairwise=self.pairwise_cipher,
                                                    group=self.groupwise_cipher,
                                                    eap=self.eap_method,
                                                    identity=self.eap_identity,
                                                    passwd=self.eap_password,
                                                    private_key=self.private_key,
                                                    ca_cert=self.ca_cert,
                                                    pk_password=self.pk_passwd,
                                                    phase1=self.eap_phase1,
                                                    phase2=self.eap_phase2)
            elif self.eap_method == 'TTLS' or self.eap_method == 'PEAP':
                self.station_profile.set_wifi_extra(key_mgmt=self.key_mgmt,
                                                    pairwise=self.pairwise_cipher,
                                                    group=self.groupwise_cipher,
                                                    eap=self.eap_method,
                                                    identity=self.eap_identity,
                                                    anonymous_identity=self.eap_anonymous_identity,
                                                    passwd=self.eap_password,
                                                    phase1=self.eap_phase1,
                                                    phase2=self.eap_phase2)
            elif self.eap_method != 'DEFAULT' or self.key_mgmt != "DEFAULT":
                self.station_profile.set_wifi_extra(key_mgmt=self.key_mgmt,
                                                    pairwise=self.pairwise_cipher,
                                                    group=self.groupwise_cipher,
                                                    psk=self.password,
                                                    eap=self.eap_method,
                                                    identity=self.eap_identity,
                                                    anonymous_identity=self.eap_anonymous_identity,
                                                    passwd=self.eap_password,
                                                    private_key=self.private_key,
                                                    ca_cert=self.ca_cert,
                                                    pk_password=self.pk_passwd,
                                                    phase1=self.eap_phase1,
                                                    phase2=self.eap_phase2)
            # Security type comes in one of following formats (possibly capitalized),
            # so need to check if substring:
            #   'type'
            #   '<type1|type2>'
            if 'wpa3' in self.security or 'WPA3' in self.security:
                self.station_profile.set_command_param("add_sta", "ieee80211w", 2)
            elif self.ieee80211w:
                self.station_profile.set_command_param("add_sta", "ieee80211w", self.ieee80211w)

            self.desired_add_sta_flags = []
            self.desired_add_sta_flags_mask = []
            self.station_profile.set_command_flag(command_name="add_sta", param_name="8021x_radius",
                                                  value=1)  # enable 802.1x flag
            # self.station_profile.set_command_flag(command_name="add_sta", param_name="80211r_pmska_cache", value=1)  # enable 80211r_pmska_cache flag

        self.station_profile.set_command_param(
            "set_port", "report_timer", 1500)
        self.station_profile.set_command_flag("set_port", "rpt_timer", 1)
        if self.set_txo_data is not None:
            self.station_profile.set_wifi_txo(
                txo_ena=self.set_txo_data["txo_enable"],
                tx_power=self.set_txo_data["txpower"],
                pream=self.set_txo_data["pream"],
                mcs=self.set_txo_data["mcs"],
                nss=self.set_txo_data["nss"],
                bw=self.set_txo_data["bw"],
                retries=self.set_txo_data["retries"],
                sgi=self.set_txo_data["sgi"],
            )

        if self.station_profile.create(radio=self.radio,
                                       sta_names_=self.sta_list,
                                       debug=self.debug,
                                       up_=self.up):
            self._pass("Stations created.")
        else:
            self._fail("Stations not properly created.")
        # Custom Wifi setting
        if self.custom_wifi_cmd:
            for sta in self.sta_list:
                self.set_custom_wifi(resource=int(sta.split('.')[1]),
                                     station=str(sta.split('.')[2]),
                                     cmd=self.custom_wifi_cmd)

        if self.up:
            self.station_profile.admin_up()
            if not LFUtils.wait_until_ports_admin_up(base_url=self.lfclient_url,
                                                     port_list=self.station_profile.station_names,
                                                     debug_=self.debug,
                                                     timeout=10):
                self._fail("Unable to bring all stations up")
                return
            if self.wait_for_ip(station_list=self.station_profile.station_names, timeout_sec=-1):
                self._pass("All stations got IPs", print_=True)
                self._pass("Station build finished", print_=True)
                if self.command is not None:
                    try:
                        if '.' in self.sta_list[0]:
                            sta_name = (self.sta_list[0]).split('.')[2]
                            full_command = f"sudo su -c '/home/lanforge/vrf_exec.bash {sta_name} {self.command}'"
                            logger.info(f"Executing: {full_command}")
                            result = subprocess.run([f"{full_command}"], shell=True, check=True, text=True,
                                                    capture_output=True)
                            logger.info(f"Command executed successfully:\n{result.stdout}")
                    except subprocess.CalledProcessError as e:
                        logger.info(f"Cannot Execute command {e}")
            else:
                self._fail("Stations failed to get IPs", print_=True)
                self._fail("FAIL: Station build failed", print_=True)
                logger.info("Please re-check the configuration applied")

    def modify_radio(self, mgr, radio, antenna, channel, tx_power, country_code):
        shelf, resource, radio, *nil = LFUtils.name_to_eid(radio)

        modify_radio = lf_modify_radio.lf_modify_radio(lf_mgr=mgr)
        modify_radio.set_wifi_radio(_resource=resource,
                                    _radio=radio,
                                    _shelf=shelf,
                                    _antenna=antenna,
                                    _channel=channel,
                                    _txpower=tx_power,
                                    _country_code=country_code)

    def get_station_list(self):
        response = super().json_get("/port/list?fields=_links,alias,device,port+type")
        available_stations = []
        for interface_name in response['interfaces']:
            # print('sta' in list(interface_name.keys())[0])
            if ('sta' in list(interface_name.keys())[0]):
                available_stations.append(list(interface_name.keys())[0])
        return (available_stations)


def parse_args():
    parser = LFCliBase.create_basic_argparse(  # see create_basic_argparse in ../py-json/LANforge/lfcli_base.py
        prog='create_station.py',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''\
         Create stations
            ''',

        description='''\

NAME: create_station.py

PURPOSE: create_station.py will create a variable number of stations, and connect them to a specified wireless network.

EXAMPLE:
         # For creating the single stations

            create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>'

         # For creating the multiple stations

            create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==10,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>'

         # For creating the stations with radio settings like anteena, channel, etc.

            create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>,radio_antenna==4,
            radio_channel==6'

         # For station enabled with additional flags

           create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>,station_flag==<staion_flags>'
            --station_flag <staion_flags>

         # For creating station with enterprise authentication with TLS

            create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>,eap_method==EAP-TLS,eap_identity==<username>,eap_password==<password>,
            pk_passwd==<password>,key_mgmt==<key mgmt>,ca_cert==<path>,private_key==<path>,pairwise_cipher==<cipher>,groupwise_cipher==<cipher>'

         # For creating station with enterprise authentication with TTLS or PEAP

            create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>,eap_method==<EAP-TTLS|EAP-PEAP>,
            eap_identity==<username>,eap_password==<password>,key_mgmt==<key mgmt>,pairwise_cipher==<cipher>,groupwise_cipher==<cipher>'

        # CLI to Connect Clients with given custom wifi command.

            create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>,
            custom_wifi_cmd=='bgscan="simple:50:-65:300"'

        # For creating station with multiple radio with different securities

            eap_method,identity,anonymous,eap_passwd,phase1,phase2,pk_password,ca_cert,private_key,key_mgmt,pairwise,group,sta_flag,pk_password,mode

            create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>' 
                                                   --radios 'radio==1.1.wiphy2,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>,eap_method==<TTLS|PEAP>,key_mgmt==<key mgmt>' 

SCRIPT_CLASSIFICATION:  Creation

SCRIPT_CATEGORIES:   Functional 

NOTES: 
        Does not create cross connects 
        Mainly used to determine how to create a station

        * We can also specify the mode for the stations using "--mode" argument

            --mode   1
                {"auto"   : "0",
                "a"      : "1",
                "b"      : "2",
                "g"      : "3",
                "abg"    : "4",
                "abgn"   : "5",
                "bgn"    : "6",
                "bg"     : "7",
                "abgnAC" : "8",
                "anAC"   : "9",
                "an"     : "10",
                "bgnAC"  : "11",
                "abgnAX" : "12",
                "bgnAX"  : "13"}

            example:
                    create_station.py --mgr <lanforge ip> --radio wiphy1 --start_id 2 --num_stations 1 --ssid <ssid> --passwd <password> 
                    --security wpa2 --mode 6

            --station_flag  <staion_flags>
                add_sta_flags = {
                "osen_enable"          :  Enable OSEN protocol (OSU Server-only Authentication)
                "ht40_disable"         :  Disable HT-40 even if hardware and AP support it.
                "ht160_enable"         :  Enable HT160 mode.
                "disable_sgi"          :  Disable SGI (Short Gu
                "hs20_enable"          :  Enable Hotspot 2.0 (HS20) feature.  R
                "txo-enable"           :  Enable/disable tx-offloads, typically managed by set_wifi_txo command
                "custom_conf"          :  Use Custom wpa_supplicant config file.
                "ibss_mode"            :  Station should be in IBSS mode.
                "mesh_mode"            :  Station should be in MESH mode.
                "wds-mode"             :  WDS station (sort of like a lame mesh), not supported on ath10k
                "scan_ssid"            :  Enable SCAN-SSID flag in wpa_supplicant.
                "passive_scan"         :  Use passive scanning (don't send probe requests).
                "lf_sta_migrate"       :  OK-To-Migrate (Allow station migration between LANforge radios)
                "disable_fast_reauth"  :  Disable fast_reauth option for virtual stations.
                "power_save_enable"    :  Station should enable power-save.  May not work in all drivers/configurations.
                "disable_roam"         :  Disable automatic station roaming based on scan results.
                "no-supp-op-class-ie"  :  Do not include supported-oper-class-IE in assoc requests.  May work around AP bugs.
                "use-bss-transition"   :  Enable BSS transition.
                "ft-roam-over-ds"      :  Roam over DS when AP supports it.
                "disable_ht80"         :  Disable HT80 (for AC chipset NICs only)}
                "80211r_pmska_cache"   :  Enable PMSKA caching for WPA2 (Related to 802.11r)

            example:
                    create_station.py --mgr <lanforge ip> --radio wiphy1 --start_id 2 --num_stations 1 --ssid <ssid> --passwd <password> 
                    --security wpa2 --station_flag power_save_enable

            --country_code 840
                United States   :   840     |       Dominican Rep   :   214     |      Japan (JE2)     :   397     |      Portugal        :   620
                Albania         :   8       |       Ecuador         :   218     |      Jordan          :   400     |      Pueto Rico      :   630
                Algeria         :   12      |       Egypt           :   818     |      Kazakhstan      :   398     |      Qatar           :   634
                Argentina       :   32      |       El Salvador     :   222     |      North Korea     :   408     |      Romania         :   642
                Bangladesh      :   50      |       Estonia         :   233     |      South Korea     :   410     |      Russia          :   643
                Armenia         :   51      |       Finland         :   246     |      South Korea     :   411     |      Saudi Arabia    :   682
                Australia       :   36      |       France          :   250     |      Kuwait          :   414     |      Singapore       :   702
                Austria         :   40      |       Georgia         :   268     |      Latvia          :   428     |      Slovak Republic :   703
                Azerbaijan      :   31      |       Germany         :   276     |      Lebanon         :   422     |      Slovenia        :   705
                Bahrain         :   48      |       Greece          :   300     |      Liechtenstein   :   438     |      South Africa    :   710
                Barbados        :   52      |       Guatemala       :   320     |      Lithuania       :   440     |      Spain           :   724
                Belarus         :   112     |       Haiti           :   332     |      Luxembourg      :   442     |      Sweden          :   752
                Belgium         :   56      |       Honduras        :   340     |      Macau           :   446     |      Switzerland     :   756
                Belize          :   84      |       Hong Kong       :   344     |      Macedonia       :   807     |      Syria           :   760
                Bolivia         :   68      |       Hungary         :   348     |      Malaysia        :   458     |      Taiwan          :   158
                BiH             :   70      |       Iceland         :   352     |      Mexico          :   484     |      Thailand        :   764
                Brazil          :   76      |       India           :   356     |      Monaco          :   492     |      Trinidad &Tobago:   780   
                Brunei          :   96      |       Indonesia       :   360     |      Morocco         :   504     |      Tunisia         :   788
                Bulgaria        :   100     |       Iran            :   364     |      Netherlands     :   528     |      Turkey          :   792
                Canada          :   124     |       Ireland         :   372     |      Aruba           :   533     |      U.A.E.          :   784
                Chile           :   152     |       Israel          :   376     |      New Zealand     :   554     |      Ukraine         :   804
                China           :   156     |       Italy           :   380     |      Norway          :   578     |      United Kingdom  :   826
                Colombia        :   170     |       Jamaica         :   388     |      Oman            :   512     |      Uruguay         :   858
                Costa Rica      :   188     |       Japan           :   392     |      Pakistan        :   586     |      Uzbekistan      :   860
                Croatia         :   191     |       Japan (JP1)     :   393     |      Panama          :   591     |      Venezuela       :   862
                Cyprus          :   196     |       Japan (JP0)     :   394     |      Peru            :   604     |      Vietnam         :   704
                Czech Rep       :   203     |       Japan (JP1-1)   :   395     |      Philippines     :   608     |      Yemen           :   887
                Denmark         :   208     |       Japan (JE1)     :   396     |      Poland          :   616     |      Zimbabwe        :   716

            --no_pre_cleanup
                    Disables station cleanup before creation of stations

            example:
                    create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>' --no_pre_cleanup


            --cleanup
                    Add this flag to clean up stations after creation

            example:
                    create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>' --cleanup
                    
            extra_securities:-
            example:
                    create_station.py --mgr <lanforge ip> --radios 'radio==1.1.wiphy1,num_sta==1,ssid==<ssid>,passwd==<password>,security==<wpa2|wpa3>,extra_securities==<[wpa|wpa2|wpa3]>'

        * For enterprise authentication
            --eap_method <eap_method>
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

            --pairwise_cipher [BLANK]
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

            --groupwise_cipher [BLANK]
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

            --eap_identity <eap_identity>
                    Add this argument to specify the username of radius server

            --eap_password <eap_password>
                    Add this argument to specify the password of radius server

            --pk_passwd <private_key_passsword>
                    Add this argument to specify the private key password
                    Required only for TLS

            --ca_cert <path_to_certificate>
                    Add this argument to specify the certificate path
                    Required only for TLS

            example:
                    /home/lanforge/ca.pem

            --private_key <path_to_private_key>
                    Add this argument to specify the private key path
                    Required only for TLS

            example:
                    /home/lanforge/client.p12

            --key_mgmt < SAE | FT-SAE (11r) >
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

STATUS: Functional

VERIFIED_ON:   9-JUN-2023,
             GUI Version:  5.4.6
             Kernel Version: 5.19.17+

LICENSE:
          Free to distribute and modify. LANforge systems must be licensed.
          Copyright 2023 Candela Technologies Inc

INCLUDE_IN_README: False

''')
    required = parser.add_argument_group('required arguments')
    required.add_argument('--start_id',
                          help='Specify the station starting id \n e.g: --start_id <value> default 0',
                          default=0)
    required.add_argument(
        '-r', '--radios',
        action='append',
        nargs=1,
        help=(' --radios'
              ' radio==<wiphy radios>, num_sta==<number of stations>'
              ' ssid==<ssid>, passwd==<ssid password>, security==<security> '
              ' eap_method==<mention eap_method>,identity==<mention identity>,'
              ' anonymous==<mention anonymous>,eap_passwd==<mention eap_passwd>,'
              ' phase1==<mention phase1>,phase2==<mention phase2>,pk_passwd==<mention pk_passwd>,'
              ' ca_cert==<mention ca_cert>,private_key==<mention private_key>,'
              ' key_mgmt==<mention key_mgmt>,pairwise_cipher==<mention pairwise>,groupwise_cipher==<mention group>'
              ' sta_flag==<mention sta_flag>,mode==<mention mode>,custom_wifi_cmd==<custom_command>,extra_securities==<extra_securities>'
              )
    )

    optional = parser.add_argument_group('Optional arguments')
    optional.add_argument("--create_admin_down",
                          help='Create ports in admin down state.',
                          action='store_true')
    optional.add_argument("--bssid",
                          type=str,
                          help="AP BSSID. For example, \"00:00:00:00:00:00\".",
                          default="DEFAULT")  # TODO: Fix 'null' when not set issue (REST server-side issue)
    optional.add_argument('--mode',
                          help='Mode for your station (as a number)',
                          default=0)
    optional.add_argument('--station_flag',
                          help='station flags to add. eg: --station_flag ht40_disable',
                          required=False,
                          default=None)
    optional.add_argument("--radio_antenna",
                          help='Number of spatial streams: \n'
                               ' default = -1 \n'
                               ' 0 Diversity (All) \n'
                               ' 1 Fixed-A (1x1) \n'
                               ' 4 AB (2x2) \n'
                               ' 7 ABC (3x3) \n'
                               ' 8 ABCD (4x4) \n'
                               ' 9 (8x8) \n',
                          default='-1')
    optional.add_argument("--radio_channel",
                          help='Radio Channel: \n'
                               ' default: AUTO \n'
                               ' e.g:   --radio_channel 6 (2.4G) \n'
                               '\t--radio_channel 36 (5G) \n',
                          default='AUTO')
    optional.add_argument("--radio_tx_power",
                          help='Radio tx-power \n'
                               ' default: AUTO system defaults',
                          default='AUTO')
    optional.add_argument("--country_code",
                          help='Radio Country Code:\n'
                               'e.g: \t--country_code 840')
    optional.add_argument("--eap_method",
                          type=str,
                          help='Enter EAP method e.g: EAP-TLS')
    optional.add_argument("--eap_identity",
                          "--radius_identity",
                          dest="eap_identity",
                          type=str,
                          help="This is synonymous with the RADIUS username.")
    optional.add_argument("--eap_anonymous_identity",
                          type=str,
                          help="",
                          default="[BLANK]")  # TODO: Fix root cause of 'null' when not set issue (REST server-side issue)
    optional.add_argument("--eap_password",
                          "--radius_passwd",
                          dest="eap_password",
                          type=str,
                          help="This is synonymous with the RADIUS user's password.")
    optional.add_argument("--eap_phase1",
                          type=str,
                          help="EAP Phase 1 (outer authentication, i.e. TLS tunnel) parameters.\n"
                               "For example, \"peapver=0\" or \"peapver=1 peaplabel=1\".\n"
                               "Some WPA Enterprise setups may require \"auth=MSCHAPV2\"",
                          default="[BLANK]")  # TODO: Fix root cause of 'null' when not set issue (REST server-side issue)
    optional.add_argument("--eap_phase2",
                          type=str,
                          help="EAP Phase 2 (inner authentication) parameters.\n"
                               "For example, \"autheap=MSCHAPV2 autheap=MD5\" for EAP-TTLS.",
                          default="[BLANK]")  # TODO: Fix root cause of 'null' when not set issue (REST server-side issue)
    optional.add_argument("--pk_passwd",
                          type=str,
                          help='Enter the private key password')
    optional.add_argument("--ca_cert",
                          type=str,
                          help='Enter path for certificate e.g: /home/lanforge/ca.pem')
    optional.add_argument("--private_key",
                          type=str,
                          help='Enter private key path e.g: /home/lanforge/client.p12')
    optional.add_argument("--key_mgmt",
                          type=str,
                          help='Add the key management value\n'
                              'DEFAULT\n'
                              'NONE\n'
                              'WPA-PSK\n'
                              'FT-PSK (11r)\n'
                              'FT-EAP (11r)\n'
                              'FT-SAE (11r)\n'
                              'FT-SAE-EXT-KEY (11r)\n'
                              'FT-EAP-SHA384 (11r)\n'
                              'WPA-EAP\n'
                              'OSEN\n'
                              'IEEE8021X\n'
                              'WPA-PSK-SHA256\n'
                              'WPA-EAP-SHA256\n'
                              'PSK & EAP 128\n'
                              'PSK & EAP 256\n'
                              'PSK & EAP 128/256\n'
                              'SAE\n'
                              'SAE-EXT-KEY\n'
                              'WPA-EAP-SUITE-B\n'
                              'WPA-EAP-SUITE-B-192\n'
                              'FILS-SHA256\n'
                              'FILS-SHA384\n'
                              'OWE'
                          )
    optional.add_argument("--pairwise_cipher",
                          help='Pairwise Ciphers\n'
                               'DEFAULT\n'
                               'CCMP\n'
                               'TKIP\n'
                               'NONE\n'
                               'CCMP-TKIP\n'
                               'CCMP-256\n'
                               'GCMP (wpa3)\n'
                               'GCMP-256 (wpa3)\n'
                               'CCMP/GCMP-256 (wpa3)',
                          default='[BLANK]')
    optional.add_argument("--groupwise_cipher",
                          help='Groupwise Ciphers\n'
                               'DEFAULT\n'
                               'CCMP\n'
                               'TKIP\n'
                               'WEP104\n'
                               'WEP40\n'
                               'GTK_NOT_USED\n'
                               'GCMP-256 (wpa3)\n'
                               'CCMP-256 (wpa3)\n'
                               'GCMP/CCMP-256 (wpa3)\n'
                               'ALL',
                          default='[BLANK]')
    optional.add_argument("--no_pre_cleanup",
                          help='Add this flag to stop cleaning up before station creation',
                          action='store_true')
    optional.add_argument("--cleanup",
                          help='Add this flag to clean up stations after creation',
                          action='store_true')
    optional.add_argument("--custom_wifi_cmd",
                          help="Mention the custom wifi command.")
    optional.add_argument("--command",
                          help="Specify a custom WiFi command to execute. For example: --command 'firefox <gateway ip>'."
                               "This will run the specified command using: sudo ./vrf_exec.bash <station_name> <your_command>."
                          )
    return parser.parse_args()


def validate_args(args):
    if args.radios is None:
        exit(1)
        print("--radios required")

    # if args.eap_method is not None:
    #     if args.eap_identity is None:
    #         print("--eap_identity required")
    #         exit(1)
    #     elif args.eap_password is None:
    #         print("--eap_password required")
    #         exit(1)
    #     elif args.key_mgmt is None:
    #         print("--key_mgmt required")
    #         exit(1)
    #     elif args.eap_method == 'TLS':
    #         if args.pk_passwd is None:
    #             print("--pk_passwd required")
    #             exit(1)
    #         elif args.ca_cert is None:
    #             print('--ca_cert required')
    #             exit(1)
    #         elif args.private_key is None:
    #             print('--private_key required')
    #             exit(0)

    #     # Only need to check WPA3 ciphers because user requests 802.1X authentication.
    #     # Personal WPA3 always uses SAE, so default '[BLANK]' is fine if ciphers
    #     # aren't specified.
    #     #
    #     # Security type comes in one of following formats (possibly capitalized),
    #     # so need to check if substring:
    #     #   'type'
    #     #   '<type1|type2>'
    #     if 'wpa3' in args.security or 'WPA3' in args.security:
    #         if args.pairwise_cipher == '[BLANK]':
    #             print('--pairwise_cipher required')
    #             exit(1)
    #         elif args.groupwise_cipher == '[BLANK]':
    #             print('--groupwise_cipher required')
    #             exit(1)Add this flag to stop cleaning up before station creation


def main():
    args = parse_args()

    # validate_args(args)
    logger_config = lf_logger_config.lf_logger_config()
    # set the logger level to requested value
    logger_config.set_level(level=args.log_level)
    logger_config.set_json(json_file=args.lf_logger_config_json)

    station_list = []
    radio, ssid, security, password = [], [], [], []
    radio_list, num_sta_list, ssid_list, password_list, security_list = [], [], [], [], []
    eap_method_list, eap_identity_list, eap_anonymous_identity_list, eap_password_list = [], [], [], []
    eap_phase1_list, eap_phase2_list, pk_passwd_list, ca_cert_list = [], [], [], []
    private_key_list, key_mgmt_list, pairwise_cipher_list, groupwise_cipher_list = [], [], [], []
    station_flag_list, mode_list, custom_wifi_cmd_list, command_list, extra_securities_list = [], [], [], [], []
    ieee80211w_list = []
    for radio_ in args.radios:
        radio_keys = ['radio', 'security', 'ssid', 'passwd', 'num_sta']
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
        logger.info("radio_dict after format {}".format(radio_info_dict))
        for key in radio_keys:
            if key not in radio_info_dict:
                if hasattr(args, f'{key}'):
                    radio_info_dict[f'{key}'] = getattr(args, f'{key}')
                else:
                    logger.critical(
                        "missing argument, for the {}, all of the following need to be present {} ".format(
                            key, radio_info_dict))
                    exit(1)
        radio_list.append(radio_info_dict['radio'])
        num_sta_list.append(int(radio_info_dict['num_sta']))
        ssid_list.append(radio_info_dict.get('ssid'))
        password_list.append(radio_info_dict.get('passwd'))
        security_list.append(radio_info_dict.get('security'))
        if 'extra_securities' in radio_info_dict:
            extra_securities_list.append(radio_info_dict['extra_securities'])
        else:
            extra_securities_list.append(None)

        if 'eap_method' in radio_info_dict:
            eap_method_list.append(radio_info_dict['eap_method'])
        else:
            eap_method_list.append(None)

        if 'eap_identity' in radio_info_dict:
            eap_identity_list.append(radio_info_dict['eap_identity'])
        else:
            eap_identity_list.append('[BLANK]')

        if 'anonymous' in radio_info_dict:
            eap_anonymous_identity_list.append(radio_info_dict['anonymous'])
        else:
            eap_anonymous_identity_list.append('[BLANK]')

        if 'eap_password' in radio_info_dict:
            eap_password_list.append(radio_info_dict['eap_password'])
        else:
            eap_password_list.append('[BLANK]')

        if 'eap_phase1' in radio_info_dict:
            eap_phase1_list.append(radio_info_dict['eap_phase1'])
        else:
            eap_phase1_list.append('[BLANK]')

        if 'eap_phase2' in radio_info_dict:
            eap_phase2_list.append(radio_info_dict['eap_phase2'])
        else:
            eap_phase2_list.append('[BLANK]')

        if 'pk_passwd' in radio_info_dict:
            pk_passwd_list.append(radio_info_dict['pk_passwd'])
        else:
            pk_passwd_list.append('[BLANK]')

        if 'ca_cert' in radio_info_dict:
            ca_cert_list.append(radio_info_dict['ca_cert'])
        else:
            ca_cert_list.append('[BLANK]')

        if 'private_key' in radio_info_dict:
            private_key_list.append(radio_info_dict['private_key'])
        else:
            private_key_list.append('[BLANK]')

        if 'key_mgmt' in radio_info_dict:
            key_mgmt_list.append(radio_info_dict['key_mgmt'])
        else:
            key_mgmt_list.append(None)

        if 'pairwise_cipher' in radio_info_dict:
            pairwise_cipher_list.append(radio_info_dict['pairwise_cipher'])
        else:
            pairwise_cipher_list.append('[BLANK]')

        if 'groupwise_cipher' in radio_info_dict:
            groupwise_cipher_list.append(radio_info_dict['groupwise_cipher'])
        else:
            groupwise_cipher_list.append('[BLANK]')

        if 'sta_flag' in radio_info_dict:
            station_flag_list.append(",".join(flag.strip() for flag in radio_info_dict['sta_flag'].split('&')))
        else:
            station_flag_list.append(None)

        if 'mode' in radio_info_dict:
            mode_list.append(radio_info_dict['mode'])
        else:
            mode_list.append('[BLANK]')

        if "custom_wifi_cmd" in radio_info_dict:
            custom_wifi_cmd_list.append(radio_info_dict['custom_wifi_cmd'])
        else:
            custom_wifi_cmd_list.append(None)
        logger.debug("radio_dict {}".format(radio_info_dict))

        if "ieee80211w" in radio_info_dict:
            ieee80211w_list.append(radio_info_dict['ieee80211w'])
        else:
            ieee80211w_list.append(None)
    print('llllllllllllll',station_flag_list)
    start_id = 0
    if args.start_id != 0:
        start_id = int(args.start_id)
    clean_once = False
    station_data = {}
    create_station = None
    for (radio, num_sta, ssid, password, security, eap_method, eap_identity, eap_anonymous_identity, eap_password,
         eap_phase1, eap_phase2, pk_passwd, ca_cert, private_key, key_mgmt, pairwise_cipher, groupwise_cipher,
         station_flag, mode, wifi_cmd, extra_securities, ieee80211w) \
            in zip(radio_list, num_sta_list, ssid_list, password_list, security_list, eap_method_list,
                   eap_identity_list, eap_anonymous_identity_list, eap_password_list, eap_phase1_list, eap_phase2_list,
                   pk_passwd_list, ca_cert_list, private_key_list, key_mgmt_list, pairwise_cipher_list,
                   groupwise_cipher_list, station_flag_list, mode_list, custom_wifi_cmd_list, extra_securities_list, ieee80211w_list):
        end_id = start_id + num_sta - 1
        sta_list = LFUtils.port_name_series(prefix="sta",
                                            start_id=start_id,
                                            end_id=end_id,
                                            padding_number=10000,
                                            radio=radio)

        print("station_list {}".format(sta_list))
        station_list.extend(sta_list)
        create_station = CreateStation(_host=args.mgr,
                                       _port=args.mgr_port,
                                       _bssid=args.bssid,
                                       _ssid=ssid,
                                       _password=password,
                                       _security=security,
                                       _eap_method=eap_method,
                                       _eap_identity=eap_identity,
                                       _eap_anonymous_identity=eap_anonymous_identity,
                                       _eap_password=eap_password,
                                       _eap_phase1=eap_phase1,
                                       _eap_phase2=eap_phase2,
                                       _pk_passwd=pk_passwd,
                                       _ca_cert=ca_cert,
                                       _private_key=private_key,
                                       _key_mgmt=key_mgmt,
                                       _pairwise_cipher=pairwise_cipher,
                                       _groupwise_cipher=groupwise_cipher,
                                       _sta_list=sta_list,
                                       _sta_flags=station_flag,
                                       _mode=mode,
                                       _radio=radio,
                                       _up=(not args.create_admin_down),
                                       _set_txo_data=None,
                                       _proxy_str=args.proxy,
                                       _custom_wifi_cmd=wifi_cmd,
                                       _command=args.command,
                                       _debug_on=args.debug,
                                       _ieee80211w=ieee80211w,
                                       _extra_securities=extra_securities)
        if not clean_once and not args.no_pre_cleanup:
            if not args.no_pre_cleanup:
                create_station.cleanup()
                for station in sta_list:
                    logging.info('Removing the station {} if exists'.format(station))
                    create_station.generic_endps_profile.created_cx.append(
                        'CX_generic-{}'.format(station.split('.')[2]))
                    create_station.generic_endps_profile.created_endp.append(
                        'generic-{}'.format(station.split('.')[2]))
                    create_station.rm_port(station, check_exists=True)

                logging.info('Cleanup Successful')
                clean_once = True

        else:
            already_available_stations = create_station.get_station_list()
            if len(already_available_stations) > 0:
                used_indices = [int(station_id.split('sta')[1]) for station_id in already_available_stations]
                for new_station in sta_list:
                    if new_station in already_available_stations:
                        print('Some stations are already existing in the LANforge from the given start id.')
                        print('You can create stations from the start id {}'.format(max(used_indices) + 1))
                        exit(1)
        create_station.modify_radio(mgr=args.mgr,
                                    radio=radio,
                                    antenna=args.radio_antenna,
                                    channel=args.radio_channel,
                                    tx_power=args.radio_tx_power,
                                    country_code=args.country_code)
        create_station.build()

        start_id = end_id + 1
        # fetch the station data
        for sta in sta_list:
            eid = create_station.name_to_eid(sta)
            sta_url = "/port/%s/%s/%s" % (eid[0], eid[1], eid[2])
            station_info = create_station.json_get(sta_url)
            dict_data = station_info["interface"]
            temp_dict = {}
            for i in ["ip", "mac", "ap"]:
                temp_dict[i] = dict_data[i]
            station_data[sta] = temp_dict
    print("station data", station_data)
    for key, value in station_data.items():
        print(f"{key}: {value}")
    if args.cleanup:
        print("Post Cleanup")
        create_station.cleanup()


if __name__ == "__main__":
    main()
