from flask import Flask,jsonify,request
from python_modules import locate_ip_address
from python_modules import autonomous_system_number
from python_modules import reverse_dns_lookup
from python_modules import dns_lookup
from python_modules import scan_popular_ports
from python_modules import scan_top_open_ports
from python_modules import port_scan
from python_modules import port_service_version_scan
from python_modules import scan_open_vulnerability
from python_modules import scan_ftp_vulnerability
from python_modules import scan_ssh_vulnarability
from python_modules import scan_telnet_vulnerability
from python_modules import scan_smtp_vulnerability
from python_modules import scan_dns_vulnerability
from python_modules import scan_http_vulnerability
from python_modules import scan_pop3_vulnerability
from python_modules import scan_imap_vulnerability
from python_modules import scan_snmp_vulnerability
from python_modules import scan_ldap_vulnerability
from python_modules import scan_https_vulnerability
from python_modules import scan_smb_vulnerability
from python_modules import scan_smtp_ssl_vulnerability
from python_modules import scan_imap_ssl_vulnerability
from python_modules import scan_pop3_ssl_vulnerability
from python_modules import scan_mysql_vulnerability
from python_modules import scan_rdp_vulnerability
from python_modules import scan_oracle_db_vulnerability
from python_modules import scan_mssql_vulnerability
from python_modules import scan_mongo_db_vulnerability
from python_modules import scan_redis_vulnerability
app = Flask(__name__)

@app.route("/",methods=["GET"])
def welcome_message():
    return jsonify(message=f"hello world!!!",success=True)


@app.route("/load_coordinates", methods=["GET"])
def load_coordinates():
    latitude = request.args.get("latitude", 37.7749)
    longitude = request.args.get("longitude", -122.4194)
    map_url = f"https://www.google.com/maps?q={latitude},{longitude}"
    return jsonify(message="Use this link to view the coordinates", url=map_url, success=True)


@app.route("/autonomous_system_number",methods=["GET"])
def asn_info():
    ip_address = request.args.get("ip_address")
    if not ip_address:
        return jsonify(message="no ip address received",success=False)
    result = autonomous_system_number.get_asn(str(ip_address))
    return jsonify(message=f"autonomous system number for {ip_address}",asn=result,success=True)

@app.route("/locate_ip",methods=["GET"])
def locate_ip():
    ip_address = request.args.get("ip_address")
    if not ip_address:
        return jsonify(message="no ip address received",success=False)
    result = locate_ip_address.get_geolocation(str(ip_address))
    return jsonify(message=f"geo location for {ip_address}",coordinates=result,success=True)

    
@app.route("/reverse_dns_lookup",methods=["GET"])
def get_hostname():
    ip_address = request.args.get("ip_address")
    if not ip_address:
        return jsonify(message="no ip address received",success=False)
    result = reverse_dns_lookup.get_domain_name(str(ip_address))
    return jsonify(message="reverse dns success",r_dns = result,success=True)

@app.route("/dns_lookup",methods=["GET"])
def get_ip():
    domain = request.args.get("domain")
    if not domain:
        return jsonify(message="no domain name received",success=False)
    result = dns_lookup.get_ip_of_domain(str(domain))
    return jsonify(message="dns success",dns = result,success=True)

@app.route("/check_popular_ports",methods=["GET"])
def check_top_protocol():
    ip_address = request.args.get("ip_address")
    if not ip_address:
        return jsonify(message="no ip address received",success=False)
    result = scan_popular_ports.check_top_protocol_ports(str(ip_address))
    return jsonify(message="popular port scan success",scan_result = result,success=True)
        
@app.route("/scan_top_open_ports",methods=["GET"])
def check_top_1000_ports():
    ip_address = request.args.get("ip_address")
    if not ip_address:
        return jsonify(message="no ip address received",success=False)
    result = scan_top_open_ports.scan_open_ports(str(ip_address))
    if len(result)<1:
        return jsonify(message="open port scan success",scan_result = "no open ports found",success=True)
    return jsonify(message="open  port scan success",scan_result = result,success=True)

@app.route("/port_scan",methods=["GET"])
def port_status():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = port_scan.check_port_status(str(ip_address),int(port))
    return jsonify(message="port scan success",port_status = result,success=True)

@app.route("/port_service_version_scan",methods=["GET"])
def port_service_version():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = port_service_version_scan.find_service_version(str(ip_address),int(port))
    return jsonify(message="port service version scan success",port_status = result,success=True)

@app.route("/scan_open_vulnerabilities",methods=["GET"])
def scan_vulnerability():
    ip_address = request.args.get("ip_address")
    if not ip_address:
        return jsonify(message="no ip address received",success=False)
    result = scan_open_vulnerability.scan_vulnerabilities(str(ip_address))
    return jsonify(message="scan open vulnerability success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_ftp",methods=["GET"])
def scan_ftp_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_ftp_vulnerability.scan_vulnerable_ftp(str(ip_address),int(port))
    return jsonify(message="scan vulnerable ftp success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_ssh",methods=["GET"])
def scan_ssh_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_ssh_vulnarability.scan_vulnerable_ssh(str(ip_address),int(port))
    return jsonify(message="scan vulnerable ssh success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_telnet",methods=["GET"])
def scan_telnet_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_telnet_vulnerability.scan_vulnerable_telnet(str(ip_address),int(port))
    return jsonify(message="scan vulnerable telnet success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_smtp",methods=["GET"])
def scan_smtp_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_smtp_vulnerability.scan_vulnerable_smtp(str(ip_address),int(port))
    return jsonify(message="scan vulnerable smtp success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_dns",methods=["GET"])
def scan_dns_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_dns_vulnerability.scan_vulnerable_dns(str(ip_address),int(port))
    return jsonify(message="scan vulnerable dns success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_http",methods=["GET"])
def scan_http_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_http_vulnerability.scan_vulnerable_http(str(ip_address),int(port))
    return jsonify(message="scan vulnerable http success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_pop3",methods=["GET"])
def scan_pop3_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_pop3_vulnerability.scan_vulnerable_pop3(str(ip_address),int(port))
    return jsonify(message="scan vulnerable pop3 success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_imap",methods=["GET"])
def scan_imap_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_imap_vulnerability.scan_vulnerable_imap(str(ip_address),int(port))
    return jsonify(message="scan vulnerable imap success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_snmp",methods=["GET"])
def scan_snmp_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_snmp_vulnerability.scan_vulnerable_snmp(str(ip_address),int(port))
    return jsonify(message="scan vulnerable snmp success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_ldap",methods=["GET"])
def scan_ldap_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_ldap_vulnerability.scan_vulnerable_ldap(str(ip_address),int(port))
    return jsonify(message="scan vulnerable ldap success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_https",methods=["GET"])
def scan_https_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_https_vulnerability.scan_vulnerable_https(str(ip_address),int(port))
    return jsonify(message="scan vulnerable https success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_smb",methods=["GET"])
def scan_smb_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_smb_vulnerability.scan_vulnerable_smb(str(ip_address),int(port))
    return jsonify(message="scan vulnerable smb success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_smtp_ssl",methods=["GET"])
def scan_smtp_ssl_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_smtp_ssl_vulnerability.scan_vulnerable_smtp_submission(str(ip_address),int(port))
    return jsonify(message="scan vulnerable smtp ssl success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_imap_ssl",methods=["GET"])
def scan_imap_ssl_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_imap_ssl_vulnerability.scan_vulnerable_imap_ssl(str(ip_address),int(port))
    return jsonify(message="scan vulnerable imap ssl success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_pop3_ssl",methods=["GET"])
def scan_pop3_ssl_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_pop3_ssl_vulnerability.scan_vulnerable_pop3_ssl(str(ip_address),int(port))
    return jsonify(message="scan vulnerable pop3 ssl success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_mysql",methods=["GET"])
def scan_mysql_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_mysql_vulnerability.scan_vulnerable_mysql(str(ip_address),int(port))
    return jsonify(message="scan vulnerable mysql success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_rdp",methods=["GET"])
def scan_rdp_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_rdp_vulnerability.scan_vulnerable_rdp(str(ip_address),int(port))
    return jsonify(message="scan vulnerable rdp success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_oracle_db",methods=["GET"])
def scan_oracle_db_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_oracle_db_vulnerability.scan_vulnerable_oracledb(str(ip_address),int(port))
    return jsonify(message="scan vulnerable oracle db success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_mssql",methods=["GET"])
def scan_mssql_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_mssql_vulnerability.scan_vulnerable_mssql(str(ip_address),int(port))
    return jsonify(message="scan vulnerable mssql success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_mongodb",methods=["GET"])
def scan_mongodb_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_mongo_db_vulnerability.scan_vulnerable_mongodb(str(ip_address),int(port))
    return jsonify(message="scan vulnerable mongodb success",vulnerability = result,success=True)

@app.route("/scan_vulnerable_redis",methods=["GET"])
def scan_redis_vulnerabilities():
    ip_address = request.args.get("ip_address")
    port = request.args.get("port")
    if not ip_address and not port:
        return jsonify(message="no ip address and port received",success=False)
    if not ip_address or not port:
        return jsonify(message="no ip address or port received",success=False)
    result = scan_redis_vulnerability.scan_vulnerable_redis(str(ip_address),int(port))
    return jsonify(message="scan vulnerable redis success",vulnerability = result,success=True)


if __name__ == "__main__":
    app.run(debug=True)