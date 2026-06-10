from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Client

@login_required
def client_list(request):
    """
    Renders the list of clients for the active tenant.
    Supports creating a new client via POST.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found for your account.")
        return redirect('login')
        
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        
        if name:
            Client.objects.create(
                tenant=tenant,
                name=name,
                email=email or '',
                phone=phone or ''
            )
            messages.success(request, f"Client '{name}' was added successfully.")
        else:
            messages.error(request, "Client name is required.")
        return redirect('client_list')
        
    clients = Client.objects.filter(tenant=tenant)
    return render(request, 'tenants/client_list.html', {
        'clients': clients,
        'active_tenant': tenant,
    })
