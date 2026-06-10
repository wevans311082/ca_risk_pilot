import urllib.request
import json
import logging
from .models import AISettings

logger = logging.getLogger(__name__)

class BaseAIProvider:
    """
    Base abstraction class for AI LLM providers.
    """
    def __init__(self, model_name=None, api_key=None, api_url=None):
        self.model_name = model_name
        self.api_key = api_key
        self.api_url = api_url

    def generate_text(self, prompt, system_instruction=None, feature=None):
        raise NotImplementedError("Subclasses must implement generate_text")


class GeminiProvider(BaseAIProvider):
    """
    Google Gemini API REST provider wrapper.
    """
    def generate_text(self, prompt, system_instruction=None, feature=None):
        if not self.api_key:
            raise ValueError("Gemini API key is not configured.")
        
        model = self.model_name or "gemini-1.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
        headers = {'Content-Type': 'application/json'}
        
        data = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ]
        }
        
        if system_instruction:
            data["systemInstruction"] = {
                "parts": [
                    {"text": system_instruction}
                ]
            }

        try:
            req = urllib.request.Request(
                url, 
                data=json.dumps(data).encode('utf-8'), 
                headers=headers, 
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=20) as response:
                res = json.loads(response.read().decode('utf-8'))
                return res['candidates'][0]['content']['parts'][0]['text']
        except Exception as e:
            logger.error(f"Gemini API request failed: {e}")
            raise RuntimeError(f"Gemini API call failed: {e}")


class OpenAIProvider(BaseAIProvider):
    """
    OpenAI API REST provider wrapper.
    """
    def generate_text(self, prompt, system_instruction=None, feature=None):
        if not self.api_key:
            raise ValueError("OpenAI API key is not configured.")
        
        model = self.model_name or "gpt-4o-mini"
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        system_content = system_instruction or "You are a helpful cyber security risk assessor assistant."
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": prompt}
            ]
        }

        try:
            req = urllib.request.Request(
                url, 
                data=json.dumps(data).encode('utf-8'), 
                headers=headers, 
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=20) as response:
                res = json.loads(response.read().decode('utf-8'))
                return res['choices'][0]['message']['content']
        except Exception as e:
            logger.error(f"OpenAI API request failed: {e}")
            raise RuntimeError(f"OpenAI API call failed: {e}")


class OllamaProvider(BaseAIProvider):
    """
    Local Ollama API REST provider wrapper.
    """
    def generate_text(self, prompt, system_instruction=None, feature=None):
        base_url = (self.api_url or "http://localhost:11434").rstrip('/')
        url = f"{base_url}/api/chat"
        headers = {'Content-Type': 'application/json'}
        
        model = self.model_name or "llama3"
        system_content = system_instruction or "You are a helpful cyber security risk assessor assistant."
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": prompt}
            ],
            "stream": False
        }

        try:
            req = urllib.request.Request(
                url, 
                data=json.dumps(data).encode('utf-8'), 
                headers=headers, 
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=25) as response:
                res = json.loads(response.read().decode('utf-8'))
                return res['message']['content']
        except Exception as e:
            logger.error(f"Ollama API request failed: {e}")
            raise RuntimeError(f"Ollama API call failed: {e}")


class MockProvider(BaseAIProvider):
    """
    Mock LLM provider used for automated testing and local developer sandboxes.
    """
    def generate_text(self, prompt, system_instruction=None, feature=None):
        if feature == 'rationale_generation':
            return (
                "Based on the threat and vulnerability context, the risk score is justified. "
                "The unpatched vulnerability represents an active exposure path, and the threat frequency "
                "indicates a high likelihood of exploit attempts, leading to an elevated inherent risk rating."
            )
        elif feature == 'finding_suggestions':
            return (
                "Title: Critical Security Patches Missing on Database Server\n"
                "Description: The database host is running an outdated operating system with unpatched remote code "
                "execution vulnerabilities, exposing customer data to theft.\n"
                "Severity: Critical"
            )
        elif feature == 'recommendation_suggestions':
            return (
                "Recommendation: Deploy automated OS patching schedule weekly.\n"
                "Priority: High\n"
                "Effort: Medium\n"
                "Cost Estimate: 500.0"
            )
        elif feature == 'control_recommendations':
            return (
                "1. Mandate Multi-Factor Authentication (MFA) on all network boundaries.\n"
                "2. Restrict database access using host firewalls and network segmentation."
            )
        elif feature == 'evidence_summarisation':
            return (
                "This document outlines the backup retention schedule. Backups are executed daily, "
                "stored in AWS S3 with KMS encryption enabled, and tested monthly for integrity, "
                "supporting the disaster recovery control requirement."
            )
        elif feature == 'missing_control_identification':
            return (
                "1. Secondary backup power supply (UPS) is missing.\n"
                "2. Intrusion Detection System (IDS) alerts on network boundaries are missing."
            )
        elif feature == 'completeness_review':
            return (
                "The assessment is mostly complete, but the following areas require attention:\n"
                "- 'Vulnerability Rationale' is currently brief and lacks context.\n"
                "- Link clean evidence documents to support existing controls."
            )
        elif feature == 'contradiction_detection':
            return (
                "1. Contradiction: Existing Controls claim WAF is enabled, but Vulnerability states that no firewall is active."
            )
        
        return f"Mock AI completion result for prompt: {prompt[:30]}..."


def get_provider(tenant):
    """
    Resolves the configured AI provider for the given tenant.
    Returns MockProvider if no configuration is set or if settings are incomplete.
    """
    settings = AISettings.objects.filter(tenant=tenant).first()
    if not settings:
        return MockProvider()

    prov = settings.provider
    if prov == 'Gemini':
        if not settings.api_key:
            return MockProvider()
        return GeminiProvider(model_name=settings.model_name, api_key=settings.api_key)
    elif prov == 'OpenAI':
        if not settings.api_key:
            return MockProvider()
        return OpenAIProvider(model_name=settings.model_name, api_key=settings.api_key)
    elif prov == 'Ollama':
        return OllamaProvider(model_name=settings.model_name, api_url=settings.api_url)
    
    return MockProvider()
