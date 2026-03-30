from django.urls import path

from . import views

urlpatterns = [path("index.html", views.index, name="index"),
	       path('UserLogin', views.UserLogin, name="UserLogin"),
	       path('UserLoginAction', views.UserLoginAction, name="UserLoginAction"),	   
	       path('Register', views.Register, name="Register"),
	       path('RegisterAction', views.RegisterAction, name="RegisterAction"),
	       path('HybridEncryption', views.HybridEncryption, name="HybridEncryption"),	
	       path('HybridEncryptionAction', views.HybridEncryptionAction, name="HybridEncryptionAction"),
	       path('AccessData', views.AccessData, name="AccessData"),	
	       path('Download', views.Download, name="Download"),
	       path('OTPAction', views.OTPAction, name="OTPAction"),
	       path('ImageSteg', views.ImageSteg, name="ImageSteg"),	
	       path('ImageStegAction', views.ImageStegAction, name="ImageStegAction"),	      
]