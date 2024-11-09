from rest_framework import status
from django.http import JsonResponse
from rest_framework.decorators import api_view
from .utils import *


@api_view(['POST'])
def url_checker(request):
    try:
        post_content = request.data.get('post_content')
        url_list = check_content_integrity(post_content)
        return JsonResponse({'malicious_url_list': url_list}, status=status.HTTP_200_OK)
    except Exception as e:
        return JsonResponse({'error':'something went wrong please contact developer','server_error':str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

