###################################
##   Port scanner,               ##
##   vulnerabilities scanner.    ##
##   Developer: Aharon chetrit.  ##
###################################

import socket
from socket import getservbyname, getservbyport
import subprocess
import time 

class Scanner_ports():
    
    def __init__(self,host,port,time_out_c=0.5):
        self.host=host
        self.port=port
        self.baners_verision=[]
        self.counter=0
        self.time_out_c=float(time_out_c)
        
    def port_scaner(self,host,port):
        try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(self.time_out_c)
            sock.connect((host,port))
            try:
                service_baner = sock.recv(1024).decode()
                self.baners_verision.append(service_baner.replace('\n','').replace('\r','')+' on host '+host)
            except:
                service_baner=''
            try:
                port_name = getservbyport(port)
            except:
                port_name = ''
            print('{+}'+' port '+port_name+' '+str(port)+" is open! "+service_baner[:-1])
            self.counter=1

        except socket.error:
            pass


    def get_host_name(self,name): 
        host_by_name=socket.gethostbyname(name)
        return host_by_name


    def range_of_ports(self,strat_range_port,end_range_port,host):
        strat_range_port=int(strat_range_port)
        end_range_port=int(end_range_port)
        host=self.get_host_name(host)
        name=self.get_host_by_adrr(host)
        if name:
            print('\nscannig for open ports on '+host+' '+name+' Scan...')
        else:
            print('\nscannig for open ports on '+host+' Scan...')
            
        print('='*50)
        for i in range(strat_range_port,end_range_port+1):
            self.port_scaner(host,i)
        if self.counter==0:
            print("not found..")
        self.counter=0
        print('-'*50)
            


    def ip_range(self,start_ip,end_ip):
        start_ip=start_ip.split('.')
        end_ip=end_ip.split('.')

        list_ip_range=[]
        for i in range(len(start_ip)):
            if start_ip[i]!=end_ip[i]:
                if i == 3:
                    for n in range(int(start_ip[i]),int(end_ip[i])+1):
                        end_ip[i]=str(n)
                        list_ip_range.append(str(end_ip)[1:-1].replace(', ','.').replace("'",''))
                    break

                if i == 2:
                    for n in range(int(end_ip[i])):
                        end_ip[i]=n
                        for j in range(255):
                            end_ip[i+1]=j
                            list_ip_range.append(str(end_ip)[1:-1].replace(', ','.').replace("'",''))
                    break
        return list_ip_range



    def scaning_for_ports_open(self): 
        if '-'in self.host:
            if '-'in self.port:
                self.port=self.port.split('-')
                start_port=self.port[0]
                end_port=self.port[-1]
            else:
                start_port=int(self.port)
                end_port=self.port
            host=self.host.split('-')
            start_ip=host[0]
            end_ip=host[-1]
            ranges=self.ip_range(start_ip,end_ip)
            if int(start_port) != int(end_port):
                print('true')
                print('\nEstimated time: '+self.time_cal(int(end_port)-int(start_port),len(ranges)*self.time_out_c))
            else:
                print('\nEstimated time: '+self.time_cal(1,len(ranges)*self.time_out_c))
                
            for i in ranges:
                 self.range_of_ports(start_port,end_port,i,)
            print('end.')
    
        else:
            if '-'in self.port:
                self.port=self.port.split('-')
                start_port=self.port[0]
                end_port=self.port[-1]
            else:
                start_port=int(self.port)
                end_port=self.port
            if int(start_port) != int(end_port):
                print('\nEstimated time: '+self.time_cal(int(end_port)-int(start_port),1*self.time_out_c))
            else:
                print('\nEstimated time: '+self.time_cal(1,self.time_out_c))
                
            host=self.get_host_name(self.host)
            self.range_of_ports(start_port,end_port,host)
            print('end.')
            
            
    def get_host_by_adrr(self,host):
        p = subprocess.Popen('nslookup '+host, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        name = False
        for i in p.stdout.readlines():
            i=i.decode()
            if 'Name:' in i:
                name=i.split('Name:')[-1].strip()
                break
        return name

    def time_cal(self,second,multiple):
        second=(int(second)*float(multiple))
        h=second/60/60
        m=(h-int(h)+0.00001)*100*60/100
        s=(m-int(m)+0.00001)*100*60/100
        if h>24:
            d=int(int(h)/24)
            h=h%24
            test=['Days '+str(d)+', ',str(int(h)),str(int(m)),str(int(s))]
        else:
            test=[str(int(h)),str(int(m)),str(int(s))]
        current_time=''
        for i in test:
            if len(i)<2:
                current_time+='0'+i+':'
            else:
                current_time+=i+':'
        if current_time[-1]==':':
            current_time=current_time[:-1]
        return current_time

    
    def scan_for_vulnerabilities(self,path):
        vulnerabilities=[]
        with open(path,'r')as file:
            for i in file:
                vulnerabilities.append(i.replace('\r','').replace('\n',''))
        
        self.scaning_for_ports_open()
        p=len(self.baners_verision)-1
        print('\n\nvulnerabilities')
        print('='*50)
        count=0

        for i in self.baners_verision:
            v=str(i).split(' on host')
            v=v[0]
            if v in vulnerabilities:
                print(i)
                count=1
        if count==0:
            print('not found vulnerabilities')




def main():
    out=''
    out+=('='*16+' Ports & vulnerabilities '+'='*16)+'\n'
    out+=(f"{'|':<56}|\n") 
    out+=(f"| To scan for one port and one target               (1) |\n")
    out+=(f"| To scan range of ports on one target              (2) |\n")
    out+=(f"| To scan for one port on multiple targets          (3) |\n")
    out+=(f"| To scan range of ports on multiple targets        (4) |\n")
    out+=(f"| To scan vulnerabilities enter -v after your choice    |\n")
    out+=(f"| To set time out enter -t<time> after your choice      |\n")
    out+=('-'*57)+'\n'
    print(out)
    while True:
        time.sleep(0.5)
        p=input('Select a number: ')
        time_out_c=0.5
        vul=False
        if '-v' in p:
            p=p.replace('-v')
            vul= input("Please enter path of file taht content vulnerabilities list")
        if '-t' in p:
            p=p.split('-t')
            time_out_c=float(p[-1])
            p=p[0].strip()

        chek='1 2 3 4'.split()   
        if p=='1':
            scan= input('Please enter <ip>, <port> (Ex: 10.0.0.1, 80)')
        elif p=='2':
            scan = input("please enter <ip>,<start port-end port> (Ex:10.0.0.1, 0-500)")
        elif p=='3':
            scan = input('Please enter <start ip-end ip>, <port> (Ex: 10.0.0.0-10.0.0.120, 80)')
        elif p=='4':
            scan = input("Please enter <start ip-end ip>, <start port-end port> (Ex: 10.0.0.0-10.0.0.120, 0-500)")
        elif p=='help':
            print(out)
        if p in chek:   
            scan=scan.split(',')
            if vul:
                try:
                    Scanner_ports(scan[0].strip(),scan[-1].strip(),time_out_c=time_out_c).scan_for_vulnerabilities(vul)
                except :
                    print("Something went wrong please try again.")
            else:
                try:
                    print(scan[0],scan[-1])
                    Scanner_ports(scan[0].strip(),scan[-1].strip(),time_out_c=time_out_c).scaning_for_ports_open()
                except Exception as e:
                    print("Something went wrong please try again.")
        else:
            print('Something went wrong please try again.')
        time.sleep(0.8)

if __name__=='__main__':
    main()
