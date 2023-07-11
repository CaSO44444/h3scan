#导入库
import queue
import threading
import nmap
import time

threads = []
scanResult = []
ips = []

class Host_Nmap(object):
    def __init__(self, scanIp):
        self.scanIp = scanIp

    def host_start(self):
        nm=nmap.PortScanner()
        nm.scan(hosts=self.scanIp, arguments='-sn -T4')
        alive_hosts = nm.all_hosts()
        scanResult.append(alive_hosts)

class MyThread(threading.Thread):

    def __init__(self, inputi):
        self.inputi = inputi
        threading.Thread.__init__(self)

    def run(self):
        while True:
            if self.inputi.qsize() > 0:
                self.ip = self.inputi.get()
                self.host_Nmap = Host_Nmap(self.ip)
                self.host_Nmap.host_start()
            else:
                break

class Mscan(object):

    def start_nmap_scan(self, ip_file):
        q = queue.Queue(0)
        lists = self.parse_file(ip_file)
        for ip_list in lists:
            q.put(ip_list)
        for j in range(80):
            threads.append(MyThread(q))
        for x in threads:
            x.start()
        for y in threads:
            y.join()

        result_filename = 'result.txt'
        with open(result_filename, 'w') as result_file:
            for result in scanResult:
                result_file.write("%s\n" % result)

        return scanResult

    def parse_file(self, ip_file):
        with open(ip_file) as data:
            for raw_ip in data.readlines():
                raw_ip = raw_ip.strip()
                ips.append(raw_ip)
            return ips

if __name__ == '__main__':
    ip_file = 'iplist.txt'
    start = time.time()
    Mscan = Mscan()
    print(Mscan.start_nmap_scan(ip_file))
    end = time.time()
    print("Total time: " + str(end - start))