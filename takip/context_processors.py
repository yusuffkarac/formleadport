from django.shortcuts import render, redirect, get_object_or_404
from yonetim.models import Smtp, Firma, FooterYazi

def genel(request):
    smtp = Smtp.objects.first()
    firma = Firma.objects.first()
    footer = FooterYazi.objects.first()
    return { "smtp": smtp, "firma": firma, "footer": footer}
