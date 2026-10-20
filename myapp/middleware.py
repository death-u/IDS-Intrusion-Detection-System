import re
from django.http import HttpResponseForbidden
from .models import IntrusionLog, IDSSettings


class IntrusionDetectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

        self.sqli_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"union(\s+)select",
            r"select.+from",
            r"insert(\s+)into",
            r"drop(\s+)table",
            r"or(\s+)1(\s*)=(\s*)1",
        ]

        self.xss_patterns = [
            r"<script.*?>.*?</script.*?>",
            r"<.*?javascript:.*?>",
            r"on\w+\s*=\s*[\"\'].*?[\"\']",  
            r"<iframe.*?>",
            r"<img.*?onerror.*?>",
            r"<svg.*?onload.*?>",
        ]

        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"etc/passwd",
            r"boot\.ini",
        ]

        self.sqli_regex = [re.compile(p, re.IGNORECASE) for p in self.sqli_patterns]
        self.xss_regex = [re.compile(p, re.IGNORECASE) for p in self.xss_patterns]
        self.path_regex = [re.compile(p, re.IGNORECASE) for p in self.path_traversal_patterns]

    def __call__(self, request):
        settings_obj = IDSSettings.get_settings()

        if not settings_obj.is_active:
            # IDS is OFF 
            return self.get_response(request)

        attack_detected = self.inspect_request(request)

        if attack_detected:
            attack_type, payload = attack_detected
            self.log_intrusion(request, attack_type, payload)
            return HttpResponseForbidden(
                "Request blocked: suspicious activity detected."
            )

        response = self.get_response(request)
        return response

    def inspect_request(self, request):
        """Checks GET params, POST params, and path for attack signatures.
        Returns (attack_type, payload) if something's caught, else None.
        """
        
        data_to_check = {}
        data_to_check.update(request.GET.dict())
        data_to_check.update(request.POST.dict())

        
        for regex in self.path_regex:
            if regex.search(request.path):
                return ('path_traversal', request.path)

        # for sqli and xss, check GET and POST parameters
        for key, value in data_to_check.items():
            if not isinstance(value, str):
                continue

            for regex in self.sqli_regex:
                if regex.search(value):
                    return ('sqli', f"{key}={value}")

            for regex in self.xss_regex:
                if regex.search(value):
                    return ('xss', f"{key}={value}")

        return None

    def log_intrusion(self, request, attack_type, payload):
        ip = self.get_client_ip(request)
        IntrusionLog.objects.create(
            ip_address=ip,
            attack_type=attack_type,
            path=request.path,
            payload=payload[:500], 
            blocked=True,
        )

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')