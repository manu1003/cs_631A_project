from django.urls import path,include
from .import views
urlpatterns=[
    path('',views.index,name='index'),
    path('test',views.test,name='test'),
    path('show_vul_list',views.show_vul_list,name='show_vul_list'),
    
    
]