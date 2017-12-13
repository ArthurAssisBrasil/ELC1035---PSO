#!/usr/bin/env python3

import json
import sys
import requests


class T6abrasil(object):
        def ipSRC(self, log):
                listaSRC = []
                print("Analisando IPs fonte...")
                for linha in log :
                        split = linha.split()
                        for x in split :
                                if "SRC=" in x :
                                        x = x.replace('SRC=','')
                                        sep = x.split(".")
                                        listaSRC.append(sep[0] + "." + sep[1] + "." + sep[2] + ".10")

                srcUnico = {}
                for ocorrencia in listaSRC:
                        if ((ocorrencia in srcUnico) == False):
                                srcUnico[ocorrencia] = listaSRC.count(ocorrencia)

                return srcUnico

        def ipDST(self, log):
                listaDST = []
                print("Analisando IPs destino...")
                for linha in log :
                        split = linha.split()
                        for x in split :
                                if "DST=" in x :
                                        x = x.replace('DST=','')
                                        sep = x.split(".")
                                        listaDST.append(sep[0] + "." + sep[1] + "." + sep[2] + ".10")

                dstUnico = {}
                for ocorrencia in listaDST:
                        if ((ocorrencia in dstUnico) == False):
                                dstUnico[ocorrencia] = listaDST.count(ocorrencia)

                return dstUnico


        def json1(self, ipUnico):             
                ipOrd = sorted(ipUnico,key = ipUnico.get, reverse = True)
                print("\nObtendo geolocalizacao...")
                jsonList = []
                if len(ipOrd) >= 10:
                        for x in range(10):
                                try:
                                        url = "https://ipvigilante.com/" + ipOrd[x]
                                        response = requests.get(url)
                                        response.raise_for_status()
                                        data = json.loads(response.text)
                                        jsonList.append(data)
                                except:                                 
                                        jsonList.append({"data": {"ipv4": ipOrd[x], "country_name":"None" }})
                else:
                        for x in ipOrd:
                                try:
                                        url = "https://ipvigilante.com/" + x
                                        response = requests.get(url)
                                        response.raise_for_status()
                                        data = json.loads(response.text)
                                        jsonList.append(data)
                                except:                                 
                                        jsonList.append({"data": {"ipv4": x, "country_name":"None" }})        

                return jsonList
        
        def json2(self, ipUnico):             
                ipOrd = sorted(ipUnico,key = ipUnico.get, reverse = True)
                print("\nObtendo geolocalizacao...")
                jsonList = []
                if len(ipOrd) >= 100:
                        for x in range(100):
                                try:
                                        url = "https://ipvigilante.com/" + ipOrd[x]
                                        response = requests.get(url)
                                        response.raise_for_status()
                                        data = json.loads(response.text)
                                        jsonList.append(data)
                                except:                                 
                                        jsonList.append({"data": {"ipv4": ipOrd[x], "country_name":"None" }})
                else:
                        for x in ipOrd:
                                try:
                                        url = "https://ipvigilante.com/" + x
                                        response = requests.get(url)
                                        response.raise_for_status()
                                        data = json.loads(response.text)
                                        jsonList.append(data)
                                except:                                 
                                        jsonList.append({"data": {"ipv4": x, "country_name":"None" }})        

                return jsonList
        
        def json3(self, ipUnico):             
                ipOrd = sorted(ipUnico,key = ipUnico.get, reverse = True)
                print("\nObtendo geolocalizacao...")
                jsonList = []
                if len(ipOrd) >= 500:
                        for x in range(500):
                                try:
                                        url = "https://ipvigilante.com/" + ipOrd[x]
                                        response = requests.get(url)
                                        response.raise_for_status()
                                        data = json.loads(response.text)
                                        jsonList.append(data)
                                except:                                 
                                        jsonList.append({"data": {"ipv4": ipOrd[x], "country_name":"None" }})
                else:
                        for x in ipOrd:
                                try:
                                        url = "https://ipvigilante.com/" + x
                                        response = requests.get(url)
                                        response.raise_for_status()
                                        data = json.loads(response.text)
                                        jsonList.append(data)
                                except:                                 
                                        jsonList.append({"data": {"ipv4": x, "country_name":"None" }})

                return jsonList

        def json4(self, ipUnico):             
                ipOrd = sorted(ipUnico,key = ipUnico.get, reverse = True)
                print("\nObtendo geolocalizacao...")
                jsonList = []
                if len(ipOrd) >= 1000:
                        for x in range(1000):
                                try:
                                        url = "https://ipvigilante.com/" + ipOrd[x]
                                        response = requests.get(url)
                                        response.raise_for_status()
                                        data = json.loads(response.text)
                                        jsonList.append(data)
                                except:                                 
                                        jsonList.append({"data": {"ipv4": ipOrd[x], "country_name":"None" }})
                else:
                        for x in ipOrd:
                                try:
                                        url = "https://ipvigilante.com/" + x
                                        response = requests.get(url)
                                        response.raise_for_status()
                                        data = json.loads(response.text)
                                        jsonList.append(data)
                                except:                                 
                                        jsonList.append({"data": {"ipv4": x, "country_name":"None" }})

                return jsonList
        

        def estatSRC(self, src, jsonSRC):                            
                dicPais = {}
                for ip in jsonSRC:
                        if str(ip["data"]["country_name"]) not in dicPais:
                                dicPais[str(ip["data"]["country_name"])] = src[str(ip["data"]["ipv4"])]
                        else:
                                dicPais[str(ip["data"]["country_name"])] = int(dicPais[str(ip["data"]["country_name"])]) + int(src[str(ip["data"]["ipv4"])])

                return dicPais


        def estatDST(self, dst, jsonDST):                            
                dicPais = {}
                for ip in jsonDST:
                        if str(ip["data"]["country_name"]) not in dicPais:
                                dicPais[str(ip["data"]["country_name"])] = dst[str(ip["data"]["ipv4"])]
                        else:
                                dicPais[str(ip["data"]["country_name"])] = int(dicPais[str(ip["data"]["country_name"])]) + int(dst[str(ip["data"]["ipv4"])])

                return dicPais


        def geraHtml(self, jsonSrc, jsonDst, srcPaises, dstPaises, src, dst, numIps):
                print("\nGerando html...")
                arq = open("Analisador_IP.html","r")
                site = arq.readlines()
                arq = open("Analisador_IP.html","w")
                linha =0

                srcOrd = sorted(srcPaises, key = srcPaises.get, reverse = True)
                dstOrd = sorted(dstPaises, key = dstPaises.get, reverse = True)

                while linha < len(site) :  
                        if "function getPointsFonte() {" in site[linha]:
                                arq.write(site[linha])
                                arq.write(site[linha+1])
                                linha = linha + 2
                                while("];" not in site[linha]):
                                        linha = linha + 1
                                linha = linha - 1
                                for ip in jsonSrc:
                                        for x in range(src[ip["data"]["ipv4"]]):
                                                try:
                                                        arq.write("          new google.maps.LatLng(" + str(ip["data"]["latitude"]) + ", " + str(ip["data"]["longitude"]) + "),\n")    
                                                except:
                                                        continue
                
                        elif "function getPointsDest() {" in site[linha]:
                                arq.write(site[linha])
                                arq.write(site[linha+1])
                                linha = linha + 2
                                while("];" not in site[linha]):
                                        linha = linha + 1
                                linha = linha - 1
                                for ip in jsonDst:
                                        for x in range(dst[ip["data"]["ipv4"]]):
                                                try:
                                                        arq.write("          new google.maps.LatLng(" + str(ip["data"]["latitude"]) + ", " + str(ip["data"]["longitude"]) + "),\n") 
                                                except:
                                                        continue 
                        
                        elif "texto-din1" in site[linha]:
                                texto = " "
                                percent = 0.0
                                if len(srcOrd) > 10:                                        
                                        for x in range(10):
                                                texto = texto + srcOrd[x] + " - " + str((float(srcPaises[srcOrd[x]]) * 100) / numIps) + "%<br> "
                                                percent = percent + ((float(srcPaises[srcOrd[x]]) * 100) / numIps)
                                else:
                                        for x in srcOrd:
                                                texto = texto + x + " - " + str((float(srcPaises[x]) * 100) / numIps) + "%<br> "  
                                                percent = percent + ((float(srcPaises[x]) * 100) / numIps)    
                                
                                linhaQueb = site[linha].split(">")
                                arq.write(linhaQueb[0] + ">" + texto + "Others/Unknown - " + str(100.0 - percent) + "%<br></p>\n")
                                
                        elif "texto-din2" in site[linha]:
                                texto = " "
                                percent = 0.0
                                if len(dstOrd) > 10:                                        
                                        for x in range(10):
                                                texto = texto + dstOrd[x] + " - " + str((float(dstPaises[dstOrd[x]]) * 100) / numIps) + "%<br> "
                                                percent = percent + ((float(dstPaises[dstOrd[x]]) * 100) / numIps)
                                else:
                                        for x in dstOrd:
                                                texto = texto + x + " - " + str((float(dstPaises[x]) * 100) / numIps) + "%<br> " 
                                                percent = percent + ((float(dstPaises[x]) * 100) / numIps)       
                                
                                linhaQueb = site[linha].split(">")
                                arq.write(linhaQueb[0] + ">" + texto + "Others/Unknown - " + str(100.0 - percent) + "%<br></p>\n")

                        else:
                                arq.write(site[linha])

                        linha = linha + 1
                
                arq.close()

                return


def main():
        arq = open(sys.argv[1],"r")
        log = arq.readlines()
        arq.close()
        t6 = T6abrasil()
        numIps = len(log)
        src = t6.ipSRC(log)
        dst = t6.ipDST(log)
        if len(sys.argv) == 3:
                if(sys.argv[2] == "1"):
                        jsonSrc = t6.json1(src)
                        jsonDst = t6.json1(dst)
                elif sys.argv[2] == "2":
                        jsonSrc = t6.json2(src)
                        jsonDst = t6.json2(dst)
                elif sys.argv[2] == "3":
                        jsonSrc = t6.json3(src)
                        jsonDst = t6.json3(dst)
                elif sys.argv[2] == "4":
                        jsonSrc = t6.json4(src)
                        jsonDst = t6.json4(dst)
                else:
                        print("Argumento 2 nao reconhecido")
                        jsonSrc = t6.json1(src)
                        jsonDst = t6.json1(dst)
        else:
                jsonSrc = t6.json1(src)
                jsonDst = t6.json1(dst)
        srcPaises = t6.estatSRC(src, jsonSrc)
        dstPaises = t6.estatDST(dst, jsonDst)
        t6.geraHtml(jsonSrc, jsonDst, srcPaises, dstPaises, src, dst, numIps)

        return 0

if __name__ == '__main__':
                main()
