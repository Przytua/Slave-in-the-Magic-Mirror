__author__ = 'lukaszprzytula'

import drm
sap = drm.FairPlaySAP('airtunesd')
sap.stage = 0

fpaes64 = 'RlBMWQECAQAAAAA8AAAAACLG0a0O1TjJuG0vRoV3MeYAAAAQTD/h7nKkgRZzbna2Hfb3UJUqFY/5r/LP/Zjztjt3nCcCq8gl'
# RlBMWQECAQAAAAA8AAAAACLG0a0O1TjJuG0vRoV3MeYAAAAQTD/h7nKkgRZzbna2Hfb3UJUqFY/5r/LP/Zjztjt3nCcCq8gl

fpaes = fpaes64.decode("base64")
print fpaes
# FPLY<"?ѭ?8ɸm/F?w1?L???r??snv???P?*????????;w?'??%

key = sap.decrypt_key(fpaes)
print key
print ":".join("{:02x}".format(ord(c)) for c in key)