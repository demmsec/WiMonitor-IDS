import pyshark
import httplib, urllib

capture = pyshark.LiveCapture(interface='eth1', decode_as={'udp.port==5555': 'aruba_erm', 'aruba_erm.type==0': 'aruba_erm_type3'})

deauthlist = []

for packet in capture.sniff_continuously(packet_count=0):
    try:
        if packet['wlan'].fc_subtype == "12":
            print "deauth - %s" % (packet['wlan'].bssid)
            try:
                deauthlist.append(packet['wlan'].bssid)
            except:
                print "Could not add BSSID to list"
            if deauthlist.count(packet['wlan'].bssid) > 50:
                message = "Deauth Attack in progress - %s deauth packets - Target: %s" % (deauthlist.count(packet['wlan'].bssid), packet['wlan'].bssid)
                #send alert
                conn = httplib.HTTPSConnection("api.pushover.net:443")
                conn.request("POST", "/1/messages.json",
                urllib.urlencode({
                    "token": "enter-yours",
                    "user": "enter-yours",
                    "message": message,
                  }), { "Content-type": "application/x-www-form-urlencoded" })
                conn.getresponse()
                deauthlist = []
    except:
        print "derp"
