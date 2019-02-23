import json
import sqlite3
import argparse
from pprint import pprint

def get_package_os(fixes):
    """Gets package and OS information for a single OS"""
    packages = []
    if fixes.get('packages') is None or fixes.get('os') is None:
        return packages
    for package in fixes['packages']:
        packages.append({"name": package['name'], 'version': package['version'], 
		'release': package['release'], 'os_name': fixes['os']['name'], 
		'os_version':fixes['os']['version'], 'os_arch': fixes['os']['architecture']})
    return packages

def get_vul_info(vul_info):
    """Gets package information for all OS"""
    packages = []
    if vul_info.get('fixes') is None:
        return packages
    for fixes in vul_info['fixes']:
        packages.extend(get_package_os(fixes))
    return packages

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--jsonfile',
        dest='jsonfile',
        type=str,
        default={},
        help='Security Notices file in JSON format.'
    )
    parser.add_argument(
        '--db',
        dest='db',
        type=str,
        default={},
        help='Location of DB.'
    )
    
    args = parser.parse_args()
    file = args.jsonfile
    db = args.db

    with open(file) as json_data:
        data = json.load(json_data)
        packages = {}
        for dist, vuls in data.items():    
             # Get complete package information for all Vul_ids
            for vul_id, vul_info in vuls.items():
                packages[vul_id] = get_vul_info(vul_info)
        populateDB(db, packages)
        json_data.close()

def populateDB(db, packages):
    """Populate database with security notice information"""
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    print "opened db successfully"
    for vul_id, package in packages.items():
        for info in package:
            cur.execute('''INSERT INTO packages(name, version, release, vulnerabilityId, OS_name, OS_version)
			    VALUES(?,?,?,?,?,?);''', (info['name'], info['version'], info['release'], vul_id, info['os_name'], info['os_version']))
          
    conn.commit()
    conn.close()

main()
