from junitparser import JUnitXml
from junit2htmlreport.parser import Junit
import os

option = int(input("Pick an option: 1 -Enter name of files   2 -Enter folder path to pick files from :"))
if option == 1:
    input_files_count = int(input("Enter count of junit xml files:"))
    file_name = input("Enter name of file 1 :")
    merged_xml = JUnitXml.fromfile('reports/'+file_name)
    for i in range(2, input_files_count+1):
        file_name = input("Enter name of file "+str(i)+" :")
        merged_xml = merged_xml + JUnitXml.fromfile('reports/'+file_name)
    output_html_file_name = input("Enter output html file name :")
    merged_xml.write('reports/merged_junit.xml')
    with open('reports/'+output_html_file_name, 'w') as html_file:
        html_file.write(Junit('reports/merged_junit.xml').html())
elif option == 2:
    path = input("Enter junit xml files folder path:")
    file_list = os.listdir(path)
    merged_xml = JUnitXml.fromfile(path+"/"+file_list[0])
    for i in range(1, len(file_list)):
        merged_xml = merged_xml + JUnitXml.fromfile(path+"/"+file_list[i])
    output_html_file_name = input("Enter output html file name :")
    merged_xml.write(path+"/"+"merged_junit.xml")
    with open(path+"/"+output_html_file_name, 'w') as html_file:
        html_file.write(Junit(path+"/"+"merged_junit.xml").html())