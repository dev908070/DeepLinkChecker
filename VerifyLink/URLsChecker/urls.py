from django.urls import path
from .views import *

urlpatterns = [
    path('content_urls_check/', url_checker),
]
