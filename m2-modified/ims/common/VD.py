import os
import json
import ast
import sys
import sqlite3

#readJsonfile = sys.argv[1]
def readFrame(json_data):
	vulnearbleList = []
	#with open(readJsonfile) as json_data:
	frame = json.loads(json_data)
	if frame[1]["1"].startswith("os"):
		osframe = 1
	else:
		osframe = len(frame) - 1
	os_frame = frame[osframe]

	osName, osVersion = get_os(os_frame)
	c = 0
	package_list = []
	package_names = []
	for i in range(2, len(frame)):
		package_name, package_version, arch = get_package(frame[i])
		#vulnearbleList += getVulnerability(package_name, package_version, osName, osVersion, arch)
		package_list.append({"name":package_name, "version": package_version})
		package_names.append(package_name)
        vulnearbleList = getVulnerability_db(package_names, package_list, osName, osVersion)

	for vulnearblePackage in vulnearbleList:
		print("----------------------------------------")
		print("ID => ", vulnearblePackage["id"])
		#print("Summary => ", vulnearblePackage["summary"])
		print("OS Name => ", vulnearblePackage["osName"])
		print("Package Name => ", vulnearblePackage["pName"])
		print("Package Version => ", vulnearblePackage["pVersion"])
		#print("Severity => ", vulnearblePackage["severity"])
		#print("Category => ", vulnearblePackage["category"])

	print("----------------------------------------")
	print("Vulnerable Packages = ", len(vulnearbleList))
	print("Total Packages = ", len(frame)-2)
	return vulnearbleList

def get_os(f):
	#return os, version
	return f["5"], f["6"]

def get_package(f):
	#return package, version, arch required
	return f["3"],f["5"], f["6"]

def getVulnerability(pName, pVersion, osName, osVersion, arch):
	vulnerableP = 0
	print_list = []

	with open("op.json") as json_data:
		usn_json = json.load(json_data)
		# for os_names in usn_json:
		if osName in ["rhel", "centos"]:
			os_names = "RHSA"
		elif osName == "ubuntu":
			os_names = "usn"
		else:
			os_names = "deb"


		dataset = usn_json[os_names]
		for id_val in dataset:
			notice_obj = dataset[id_val]

			if "fixes" in notice_obj.keys():
				fixes = notice_obj["fixes"]

				for fix in fixes:
					fix_os = fix["os"]
					fix_packages = fix["packages"]
					
					if osName == fix_os["name"]:

						for fix_package in fix_packages:
							# print("usn package version = ",fix_package["release"])
							# print("frame package version = ",pVersion)
							fix_dict = {}
							if pName == fix_package["name"] and pVersion == fix_package["release"]:

								if "id" in notice_obj.keys():
									# print("id = ",notice_obj["id"])
									fix_dict["id"] = notice_obj["id"]

								# print("package name = ", pName)
								# print("package Version = ", pVersion)
								# print("OS name = ", osName)
								fix_dict["pName"] = pName
								fix_dict["pVersion"] = pVersion
								fix_dict["osName"] = osName
								fix_dict["summary"] = notice_obj["summary"]

								if "severity" in notice_obj.keys():
									fix_dict["severity"] = notice_obj["severity"]

								if "category" in notice_obj.keys():
									fix_dict["category"] = notice_obj["category"]

								print_list.append(fix_dict)

	final_set = [ast.literal_eval(el1) for el1 in set([str(el2) for el2 in print_list])]
	return final_set

def getVulnerability_db(package_names, packages, osName, osVersion):
	vul_list = []
        conn = sqlite3.connect('/home/bmi-introspect/securityNotices.db')
        cur = conn.cursor()
	placeholder= '?' # For SQLite. See DBAPI paramstyle.
	placeholders= ', '.join(placeholder for unused in package_names)
        query = "SELECT * FROM packages WHERE os_name='{}' AND name IN ({})".format(osName, placeholders)
	data = cur.execute(query, package_names)
	for row in data:	
		for package in packages:
                     	version_rel = row[3] + '-' + row[4]
			if row[2] == package['name'] and version_rel == package['version']:
				vul_list.append({"id": row[1], "pName": package['name'], "pVersion": package['version'], 
						 "osName": osName})
	final_set = [ast.literal_eval(el1) for el1 in set([str(el2) for el2 in vul_list])]
	return final_set





			
