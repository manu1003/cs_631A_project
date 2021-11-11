from django.http.response import HttpResponse
from django.shortcuts import render,HttpResponse
from django.http import HttpResponse
import requests
import cve
import json
# Create your views here.

des=[]
def index(request):
    return render(request,'test.html')


def invoke(request):
    return render(request,'api_test.html')

def test(request):
    assetname=request.POST.get('assetname')
    df=cve.search('','2021',assetname)
    vulnerability=df.sort_values(['baseScore','CVE_ID'],ascending=False)[:5].reset_index().to_json(orient ='records')
    
    data = []
    data = json.loads(vulnerability)
    # global des
    # des=list(data['Description'])
    
    context = {'d': data}
  
    return render(request, 'api_test.html', context)
    
def show_vul_list(request):
    return render(request,'show_vul_list.html',{'description':des})